//! The HTTP surface: the router, the two health probes, the response envelope and the error
//! type every handler returns (§3).
//!
//! Every JSON answer is `{"data": …}` and every failure is `{"error": "<plain sentence>"}` with
//! the status the UI branches on. The envelope exists so that adding a field to a response can
//! never turn an object into an array at the top level, which is the shape of change that
//! silently breaks a deployed browser tab.

use crate::api;
use crate::state::ServerState;
use axum::Json;
use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, OptionalFromRequest, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use cogwheel_storage::StorageError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tower_http::compression::CompressionLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

/// The success envelope: `{"data": …}`.
#[derive(Debug, Serialize)]
pub struct ApiEnvelope<T> {
    pub data: T,
}

impl<T: Serialize> IntoResponse for ApiEnvelope<T> {
    fn into_response(self) -> Response {
        Json(self).into_response()
    }
}

/// What a handler answers.
pub type ApiResult<T> = Result<ApiEnvelope<T>, ApiError>;

/// Wrap a payload in the envelope.
pub fn ok<T>(data: T) -> ApiResult<T> {
    Ok(ApiEnvelope { data })
}

/// A failure with the status code §3 assigns it and a sentence for the operator.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    /// 400: the request itself is wrong — an address that is not an address, a domain that is
    /// not a domain.
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    /// 404: no such device, list or rule.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// 409: the request conflicts with what is already stored — a duplicate IP or list name, or
    /// a 65th enabled list.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    /// 429: a manual refresh inside the 30-second gap, or one already running.
    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, message)
    }

    /// 503: the subsystem the request needs is not up (or is full, for the event stream).
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }

    /// 500: something inside failed. The detail goes to the log, not to the browser.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }

    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// The status this error answers with. Test-only: in the server itself an `ApiError` is
    /// always returned straight to axum, which reads the status through `IntoResponse`.
    #[cfg(test)]
    pub const fn status(&self) -> StatusCode {
        self.status
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({ "error": self.message }));
        (self.status, body).into_response()
    }
}

impl From<StorageError> for ApiError {
    /// Storage failures the handler did not classify are 500s.
    ///
    /// The two that mean something to a user — a unique violation and a foreign-key violation —
    /// are checked at the call site, where there is enough context to say *which* thing was
    /// duplicated. Anything reaching here is a database problem, so it is logged in full and
    /// reported as one sentence.
    fn from(error: StorageError) -> Self {
        tracing::error!(%error, "storage call failed");
        Self::internal("The database could not complete that request.")
    }
}

/// A query string, rejected in §3's envelope rather than axum's.
///
/// Axum's own `Query` and `Json` rejections answer `text/plain` — and, for a body, statuses (415,
/// 422) that §3 does not list — with serde's internal wording: `limit: invalid digit found in
/// string`. A browser that parses `{"error"}` on every other failure gets an unparseable body on
/// exactly the failures a typo produces. These two wrappers keep the contract total: every
/// failure that leaves this process is one of §3's statuses with a sentence in it.
pub struct ApiQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(QueryRejection::FailedToDeserializeQueryString(error)) => {
                // The serde message names the field but in its own vocabulary; it goes to the
                // log, where an operator can read it, and never to the browser.
                tracing::debug!(%error, "rejected a query string");
                Err(ApiError::bad_request(
                    "A query parameter has the wrong kind of value: counts are whole numbers and \
                     switches are true or false.",
                ))
            }
            // `QueryRejection` is non-exhaustive; a variant a later axum adds must still leave
            // here as one of §3's statuses with a sentence in it.
            Err(other) => {
                tracing::debug!(%other, "rejected a query string");
                Err(ApiError::bad_request(
                    "Those query parameters could not be read.",
                ))
            }
        }
    }
}

/// A JSON body, rejected in §3's envelope rather than axum's. See [`ApiQuery`].
pub struct ApiJson<T>(pub T);

impl<T, S> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        <Json<T> as FromRequest<S>>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(unreadable_body)
    }
}

impl<T, S> OptionalFromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    /// `POST /api/v1/lists/refresh` takes `{id}` or nothing at all, so a body-less request is not
    /// an error here — but a body that *is* present and malformed still is.
    async fn from_request(request: Request, state: &S) -> Result<Option<Self>, Self::Rejection> {
        Option::<Json<T>>::from_request(request, state)
            .await
            .map(|value| value.map(|Json(value)| Self(value)))
            .map_err(unreadable_body)
    }
}

/// The sentence a malformed body answers with. The rejection itself goes to the log.
fn unreadable_body(rejection: JsonRejection) -> ApiError {
    tracing::debug!(%rejection, "rejected a request body");
    ApiError::bad_request(match rejection {
        JsonRejection::MissingJsonContentType(_) => {
            "Send the body as JSON, with Content-Type: application/json."
        }
        JsonRejection::JsonSyntaxError(_) => "That request body is not valid JSON.",
        JsonRejection::JsonDataError(_) => {
            "That request body is missing a field, or one of them is the wrong type."
        }
        _ => "That request body could not be read.",
    })
}

/// Tracks whether each subsystem required to answer real traffic has come up.
///
/// Liveness and readiness must not be the same signal. A readiness probe that returns 200 the
/// instant axum binds its listener is strictly weaker than useless: an orchestrator cannot tell
/// "the process exists" from "this node can resolve DNS", so a rolling upgrade shifts traffic to
/// a node whose lists have not compiled yet.
#[derive(Debug, Default)]
pub struct Readiness {
    storage: AtomicBool,
    policy: AtomicBool,
    dns_listeners: AtomicBool,
}

impl Readiness {
    /// Storage is open and at schema v1.
    pub fn mark_storage_ready(&self) {
        self.storage.store(true, Ordering::Release);
    }

    /// A policy — even the empty one compiled from an empty cache — is installed.
    pub fn mark_policy_ready(&self) {
        self.policy.store(true, Ordering::Release);
    }

    /// Both DNS listeners are bound.
    pub fn mark_dns_ready(&self) {
        self.dns_listeners.store(true, Ordering::Release);
    }

    /// Whether every subsystem is up.
    pub fn is_ready(&self) -> bool {
        self.storage.load(Ordering::Acquire)
            && self.policy.load(Ordering::Acquire)
            && self.dns_listeners.load(Ordering::Acquire)
    }

    /// Per-subsystem detail, so a failing probe says which part is not up.
    pub fn detail(&self) -> ReadinessDetail {
        ReadinessDetail {
            storage: self.storage.load(Ordering::Acquire),
            policy: self.policy.load(Ordering::Acquire),
            dns_listeners: self.dns_listeners.load(Ordering::Acquire),
        }
    }
}

/// Per-subsystem readiness breakdown.
#[derive(Debug, Serialize)]
pub struct ReadinessDetail {
    pub storage: bool,
    pub policy: bool,
    pub dns_listeners: bool,
}

/// Body of the readiness probe.
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    /// `ready` or `starting`.
    pub status: &'static str,
    pub subsystems: ReadinessDetail,
}

/// Body of the liveness probe.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

/// Route 1: the process is running. The container HEALTHCHECK and install.sh use this.
async fn live() -> ApiEnvelope<HealthResponse> {
    ApiEnvelope {
        data: HealthResponse { status: "ok" },
    }
}

/// Route 2: every subsystem is up. 503 until then.
async fn ready(State(state): State<ServerState>) -> Response {
    let ready = state.readiness.is_ready();
    let body = ApiEnvelope {
        data: ReadinessResponse {
            status: if ready { "ready" } else { "starting" },
            subsystems: state.readiness.detail(),
        },
    };
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, body).into_response()
}

/// The twenty JSON routes plus the two probes, in §3 order.
pub fn api_router() -> Router<ServerState> {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/api/v1/overview", get(api::overview::overview))
        .route("/api/v1/runtime/pause", post(api::runtime::pause))
        .route("/api/v1/runtime/resume", post(api::runtime::resume))
        .route(
            "/api/v1/queries",
            get(api::queries::list).delete(api::queries::clear),
        )
        .route("/api/v1/events/stream", get(api::queries::stream))
        .route(
            "/api/v1/devices",
            get(api::devices::list).post(api::devices::create),
        )
        .route(
            "/api/v1/devices/{id}",
            put(api::devices::update).delete(api::devices::remove),
        )
        .route(
            "/api/v1/rules",
            get(api::rules::list).post(api::rules::create),
        )
        .route("/api/v1/rules/{id}", delete(api::rules::remove))
        .route(
            "/api/v1/lists",
            get(api::lists::catalogue).post(api::lists::create),
        )
        .route("/api/v1/lists/refresh", post(api::lists::refresh))
        .route(
            "/api/v1/lists/{id}",
            put(api::lists::update).delete(api::lists::remove),
        )
        .route("/api/v1/check", get(api::check::check))
        .route("/api/v1/settings", get(api::settings::settings))
}

/// The whole application: the API, the bundled web assets, compression and tracing.
pub fn app(state: ServerState) -> Router {
    app_serving(state, web_dist_dir())
}

/// [`app`], serving the web assets from `dist` rather than from wherever [`web_dist_dir`]
/// finds them. Split out so a test can point it at a build it made itself.
pub(crate) fn app_serving(state: ServerState, dist: Option<PathBuf>) -> Router {
    let router = match dist {
        Some(dist) => {
            tracing::info!(path = %dist.display(), "serving bundled web assets");
            // Serve the built SPA, answering a client-side route with `index.html` and a 200.
            //
            // `not_found_service` alone serves the shell but keeps the 404, which makes every
            // deep link look broken to probes, proxies and `curl -f`. A missing asset keeps its
            // 404, and an unmatched API path never reaches the static service at all: §3
            // promises a JSON envelope for every failure, and a client that asked for JSON must
            // not be handed an HTML shell to parse.
            //
            // A client-side route is answered by the shell *as a file*, not through ServeDir's
            // not-found service. That service relabels whatever the shell answered as a 404, so
            // a conditional request — every load, now that the shell is `no-cache` — came back
            // as a 304 relabelled 404, then 200, with no body: a reload of /devices was a blank
            // page. Served directly, a revalidation gets the 304 it asked for.
            let index = dist.join("index.html");
            let shell = ServeFile::new(&index);
            let files = ServeDir::new(dist).not_found_service(ServeFile::new(index));
            api_router().fallback_service(tower::service_fn(
                move |request: axum::http::Request<axum::body::Body>| {
                    let shell = shell.clone();
                    let files = files.clone();
                    let path = request.uri().path().to_owned();
                    async move {
                        if is_api_path(&path) {
                            return Ok(unknown_endpoint().into_response());
                        }
                        let is_spa_route =
                            !path.rsplit('/').next().is_some_and(|s| s.contains('.'));
                        let mut response = if is_spa_route {
                            tower::ServiceExt::oneshot(shell, request)
                                .await
                                .map(IntoResponse::into_response)?
                        } else {
                            tower::ServiceExt::oneshot(files, request)
                                .await
                                .map(IntoResponse::into_response)?
                        };
                        let policy = cache_control(&path, response.status());
                        response
                            .headers_mut()
                            .insert(header::CACHE_CONTROL, HeaderValue::from_static(policy));
                        Ok::<_, std::convert::Infallible>(response)
                    }
                },
            ))
        }
        None => {
            tracing::warn!("web assets not found; serving api routes only");
            api_router().fallback(|| async { unknown_endpoint() })
        }
    };

    router
        .with_state(state)
        // The control plane is served to phones over a LAN, where the JS and CSS bundles
        // compress by roughly four times. Applied to the whole router rather than the static
        // files alone so that a long query page benefits too. Gzip alone: brotli is a few
        // percent better on the same bundle and costs four more crates in the tree, which is
        // not a trade worth making for a link that is already a local network.
        .layer(CompressionLayer::new().gzip(true))
        .layer(TraceLayer::new_for_http())
}

/// `Cache-Control` for a file whose name changes whenever its contents do.
pub(crate) const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";

/// `Cache-Control` for a file that keeps its name across releases: keep it, but ask first.
pub(crate) const CACHE_REVALIDATE: &str = "no-cache";

/// How long a browser may keep what the static service answered for `path`.
///
/// Everything under `/assets/` is Vite's build output, named after a hash of its contents: a
/// changed file is a new URL, so the old one can be kept for a year and never asked about
/// again. Without this every revisit revalidated the vendor split — four requests for bytes
/// that cannot have changed. Everything else — `index.html`, the shell a client-side route is
/// answered with — keeps its name across releases, so the browser must check it each time
/// (`no-cache` means "revalidate", not "do not store"). That is what makes a `docker pull`
/// show on the next load: the new shell names new asset URLs, and the old ones age out
/// untouched. A missing asset is answered with the shell and a 404, and pinning that for a
/// year would outlive the release that fixes it.
fn cache_control(path: &str, status: StatusCode) -> &'static str {
    let hashed =
        path.starts_with("/assets/") && (status.is_success() || status == StatusCode::NOT_MODIFIED);
    if hashed {
        CACHE_IMMUTABLE
    } else {
        CACHE_REVALIDATE
    }
}

/// Whether a path belongs to the API rather than to the web app.
fn is_api_path(path: &str) -> bool {
    path.starts_with("/api/") || path.starts_with("/health/")
}

/// The 404 an unmatched API path answers with.
fn unknown_endpoint() -> ApiError {
    ApiError::not_found("No such endpoint.")
}

/// Where the built web assets are, if they are anywhere.
fn web_dist_dir() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(path) = std::env::var("COGWHEEL_WEB_DIST_DIR") {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(current) = std::env::current_dir() {
        candidates.push(current.join("apps/cogwheel-web/dist"));
        candidates.push(current.join("dist"));
    }
    candidates.push(PathBuf::from("/app/web"));
    candidates
        .into_iter()
        .find(|candidate| candidate.join("index.html").is_file())
}
