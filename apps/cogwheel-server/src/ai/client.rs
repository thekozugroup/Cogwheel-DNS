//! Talking to OpenRouter (ADR 0002 D19, §6.12): the one client, its three calls, and how a
//! failure is classified.
//!
//! This is not `state.http`, the list fetcher, which follows redirects and allows two minutes.
//! The OpenRouter client follows no redirect at all, so a 3xx can never re-send household names
//! or the bearer key to another host; it is HTTPS-only unless the base is this machine (the
//! offline stub); and for a loopback base it ignores the proxy variables, so a CI or host
//! `HTTPS_PROXY` never sees the stub or the closed test port.
//!
//! Nothing here logs a domain, a body or the key. Failures carry the HTTP status, OpenRouter's
//! `error.code` and `error.metadata.limit_source`, which are all the reviewer's one WARN line on a
//! state change may say.

use super::key::SecretKey;
use crate::config::is_loopback;
use reqwest::header::{CONTENT_TYPE, RETRY_AFTER};
use reqwest::{Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::BuildHasher;
use std::time::Duration;
use url::Url;

/// The whole of one request, connect included.
pub const TIMEOUT: Duration = Duration::from_secs(20);
/// Establishing the connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest decisions or key-info body read. Anything larger counts as unreadable (§6.8).
pub const BODY_CAP: usize = 64 * 1024;
/// The largest model listing read. Today's are about 14 KB and 8 KB.
pub const LISTING_CAP: usize = 1024 * 1024;
/// A `Retry-After` longer than this is not honoured past it.
pub const RETRY_AFTER_CAP: Duration = Duration::from_secs(60);
/// The longest wait between attempts when no `Retry-After` says otherwise.
pub const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// The 402 that means "too much in flight at once" rather than "out of credit" (the cookbook's
/// retryable 402).
const IN_FLIGHT_BUDGET: &str = "openrouter_in_flight_budget";

/// Build the OpenRouter client for `base` (D19). `proxy` is for tests, which cannot set the
/// process environment safely: production passes `None`, and reqwest then reads the proxy
/// variables itself for a non-loopback base.
///
/// # Errors
///
/// reqwest could not initialise TLS. Startup stops: "build the OpenRouter client".
pub fn build(base: &Url, proxy: Option<reqwest::Proxy>) -> reqwest::Result<Client> {
    let loopback = is_loopback(base);
    let mut builder = Client::builder()
        .user_agent(concat!("cogwheel-dns/", env!("CARGO_PKG_VERSION")))
        .timeout(TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        // A 3xx never re-sends names or the key anywhere else.
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!loopback);
    if let Some(proxy) = proxy {
        builder = builder.proxy(proxy);
    }
    if loopback {
        // After any proxy above, which this clears: the stub is never reached through one.
        builder = builder.no_proxy();
    }
    builder.build()
}

/// `{base}{path}`, with an optional query. The base has no path of its own (config.rs refuses
/// one), so this cannot produce anything but an OpenRouter endpoint.
fn endpoint(base: &Url, path: &str, query: Option<&str>) -> Url {
    let mut url = base.clone();
    url.set_path(path);
    url.set_query(query);
    url
}

/// The one place the key is spelled out. `bearer_auth` marks the header value sensitive, so
/// reqwest's own debug output redacts it.
fn authorized(request: RequestBuilder, key: &SecretKey) -> RequestBuilder {
    request.bearer_auth(key.expose())
}

/// Read at most `cap` bytes of a body; `None` if it is longer, or breaks off part-way.
async fn read_capped(mut response: Response, cap: usize) -> Option<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > cap as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > cap {
                    return None;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Some(body),
            Err(_) => return None,
        }
    }
}

// --------------------------------------------------------------------- classification

/// What to do about a request that did not succeed (§6.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Try again later: 429, any 5xx (524 and 529 included), a timeout or connect error, or a
    /// 402 for the in-flight budget. `after` is a numeric `Retry-After`, capped.
    Retry {
        after: Option<Duration>,
        rate_limited: bool,
    },
    /// 400, 413 or another 4xx: this one request is wrong. Dropped and counted; three in a row
    /// stop the model.
    Drop,
    /// 401, 403: `key_refused`.
    KeyRefused,
    /// Any other 402: `out_of_credit`.
    OutOfCredit,
    /// 404: no provider meets deny/zdr/max_price, or the model or endpoint is gone.
    ModelRefused,
    /// Any 3xx. Never followed.
    Redirected,
}

/// A failed request, and the only facts about it that may be logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub class: Class,
    /// The HTTP status, when there was a response.
    pub status: Option<u16>,
    /// OpenRouter's `error.code`.
    pub code: Option<i64>,
    /// OpenRouter's `error.metadata.limit_source`, when it is a plain identifier.
    pub limit_source: Option<String>,
}

/// OpenRouter's error envelope, read only for the two fields classification and logging use.
#[derive(Deserialize)]
struct ErrorEnvelope {
    error: Option<ErrorBody>,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: Option<i64>,
    metadata: Option<ErrorMetadata>,
}

#[derive(Deserialize)]
struct ErrorMetadata {
    limit_source: Option<String>,
}

/// Classify a non-2xx response from its status, its body and its `Retry-After`.
pub fn classify(status: u16, body: &[u8], retry_after_header: Option<&str>) -> Failure {
    let error = serde_json::from_slice::<ErrorEnvelope>(body)
        .ok()
        .and_then(|envelope| envelope.error);
    let code = error.as_ref().and_then(|error| error.code);
    // Only an identifier is kept: it is logged, and a free-text field is a place for something
    // else to turn up.
    let limit_source = error
        .and_then(|error| error.metadata)
        .and_then(|metadata| metadata.limit_source)
        .filter(|source| {
            source.len() <= 64
                && source
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        });
    let after = retry_after_header.and_then(retry_after);
    let class = match status {
        300..=399 => Class::Redirected,
        401 | 403 => Class::KeyRefused,
        402 if limit_source.as_deref() == Some(IN_FLIGHT_BUDGET) => Class::Retry {
            after,
            rate_limited: true,
        },
        402 => Class::OutOfCredit,
        404 => Class::ModelRefused,
        429 => Class::Retry {
            after,
            rate_limited: true,
        },
        500..=599 => Class::Retry {
            after,
            rate_limited: false,
        },
        _ => Class::Drop,
    };
    Failure {
        class,
        status: Some(status),
        code,
        limit_source,
    }
}

/// A request that got no response: a timeout, a refused or reset connection, a TLS failure.
/// All of them are worth another attempt; none of them is the household's fault.
pub fn transport(_error: &reqwest::Error) -> Failure {
    Failure {
        class: Class::Retry {
            after: None,
            rate_limited: false,
        },
        status: None,
        code: None,
        limit_source: None,
    }
}

/// A numeric `Retry-After`, capped at [`RETRY_AFTER_CAP`]. The HTTP-date form is not honoured:
/// it needs a clock that agrees with OpenRouter's, and the backoff covers it.
pub fn retry_after(value: &str) -> Option<Duration> {
    let seconds = value.trim().parse::<u64>().ok()?;
    Some(Duration::from_secs(seconds).min(RETRY_AFTER_CAP))
}

/// The wait before attempt `attempt + 1`: 1, 2, 4, 8 s… with ±25% jitter, capped at
/// [`BACKOFF_CAP`]. `salt` varies the jitter between jobs; the hasher's random keys vary it
/// between processes, so two appliances never retry in step.
pub fn backoff(attempt: u32, salt: u64) -> Duration {
    let base_ms = 1_000u64.saturating_mul(1u64 << attempt.min(16));
    let spread = std::collections::hash_map::RandomState::new().hash_one((attempt, salt)) % 501;
    // 750‰ to 1250‰ of the base.
    let jittered = base_ms.saturating_mul(750 + spread) / 1_000;
    Duration::from_millis(jittered).min(BACKOFF_CAP)
}

// --------------------------------------------------------------------- decisions

/// A 200 from the decisions endpoint. Billed either way, so both are settled (§6.13).
#[derive(Debug)]
pub enum Reply {
    Body(Vec<u8>),
    /// Over [`BODY_CAP`], or broken off: charged, and counted as malformed.
    Unreadable,
}

/// `POST {base}/api/alpha/decisions` with `body`, the request `prompt.rs` built.
///
/// # Errors
///
/// A classified [`Failure`] for any non-2xx status or a request that got no response.
pub async fn decide(
    client: &Client,
    base: &Url,
    key: &SecretKey,
    body: Vec<u8>,
) -> Result<Reply, Failure> {
    let request = client
        .post(endpoint(base, "/api/alpha/decisions", None))
        .header(CONTENT_TYPE, "application/json")
        .body(body);
    let response = authorized(request, key)
        .send()
        .await
        .map_err(|error| transport(&error))?;
    let status = response.status();
    if status.is_success() {
        return Ok(match read_capped(response, BODY_CAP).await {
            Some(body) => Reply::Body(body),
            None => Reply::Unreadable,
        });
    }
    Err(failure(response).await)
}

/// Classify a response that was not a success, reading only a bounded slice of its body.
async fn failure(response: Response) -> Failure {
    let status = response.status().as_u16();
    let retry_after = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = read_capped(response, BODY_CAP).await.unwrap_or_default();
    classify(status, &body, retry_after.as_deref())
}

// --------------------------------------------------------------------- the key

/// What `GET /api/v1/key` says about a key: its credit limit and what is left of it, and
/// nothing else. OpenRouter's `label` is a masked copy of the key (D10); it is not a field here,
/// so it is never read, stored, logged or forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub struct KeyInfo {
    /// USD; `None` when the key has no limit of its own.
    pub limit: Option<f64>,
    /// USD; `None` when the key has no limit of its own.
    pub limit_remaining: Option<f64>,
}

#[derive(Deserialize)]
struct KeyEnvelope {
    data: KeyInfo,
}

/// Read a `GET /api/v1/key` body: `data.limit` and `data.limit_remaining` only.
pub fn parse_key_info(body: &[u8]) -> Option<KeyInfo> {
    let info = serde_json::from_slice::<KeyEnvelope>(body).ok()?.data;
    let finite = |value: Option<f64>| value.filter(|usd| usd.is_finite());
    Some(KeyInfo {
        limit: finite(info.limit),
        limit_remaining: finite(info.limit_remaining),
    })
}

/// Why a key could not be checked; route 24's key-check table maps each to a status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCheck {
    /// 401, 403.
    Refused,
    /// 402.
    NoCredit,
    /// 404, another 4xx, a 3xx, or a 200 that could not be read.
    Unchecked,
    /// 429.
    RateLimited,
    /// 5xx, a timeout, a connect error.
    Unreachable,
}

/// `GET {base}/api/v1/key` with `key`.
///
/// # Errors
///
/// [`KeyCheck`] for anything but a readable 200.
pub async fn key_info(client: &Client, base: &Url, key: &SecretKey) -> Result<KeyInfo, KeyCheck> {
    let request = client.get(endpoint(base, "/api/v1/key", None));
    let response = authorized(request, key)
        .send()
        .await
        .map_err(|_| KeyCheck::Unreachable)?;
    match response.status().as_u16() {
        200 => read_capped(response, BODY_CAP)
            .await
            .as_deref()
            .and_then(parse_key_info)
            .ok_or(KeyCheck::Unchecked),
        401 | 403 => Err(KeyCheck::Refused),
        402 => Err(KeyCheck::NoCredit),
        429 => Err(KeyCheck::RateLimited),
        500..=599 => Err(KeyCheck::Unreachable),
        _ => Err(KeyCheck::Unchecked),
    }
}

// --------------------------------------------------------------------- the model list

/// OpenRouter's decision models, merged from both listings (route 25).
#[derive(Debug, Clone, Serialize)]
pub struct ModelList {
    pub fetched_at: i64,
    /// Sorted by price, cheapest first; an unknown price last.
    pub models: Vec<Model>,
}

impl ModelList {
    /// The model with this id.
    pub fn get(&self, id: &str) -> Option<&Model> {
        self.models.iter().find(|model| model.id == id)
    }
}

/// One decision model.
#[derive(Debug, Clone, Serialize)]
pub struct Model {
    pub id: String,
    pub name: String,
    pub description: String,
    pub context_length: u64,
    /// USD per million prompt tokens; `None` when the listing gives no usable price.
    pub prompt_usd_per_million: Option<f64>,
    /// Whether the `&zdr=true` listing has it; `None` when that listing could not be fetched.
    pub zero_retention: Option<bool>,
}

#[derive(Deserialize)]
struct Listing {
    data: Vec<ListedModel>,
}

#[derive(Deserialize)]
struct ListedModel {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    context_length: Option<u64>,
    #[serde(default)]
    pricing: Option<Pricing>,
}

#[derive(Deserialize)]
struct Pricing {
    prompt: Option<String>,
}

/// Fetch both listings, without the key. `None` if the main one cannot be read; if only the
/// `&zdr=true` one fails, every model's `zero_retention` is `None`.
pub async fn models(client: &Client, base: &Url, now: i64) -> Option<ModelList> {
    let all = listing(client, base, "output_modalities=decisions").await?;
    let zero_retention: Option<HashSet<String>> =
        listing(client, base, "output_modalities=decisions&zdr=true")
            .await
            .map(|listed| listed.into_iter().map(|model| model.id).collect());
    Some(merge(all, zero_retention.as_ref(), now))
}

async fn listing(client: &Client, base: &Url, query: &str) -> Option<Vec<ListedModel>> {
    let response = client
        .get(endpoint(base, "/api/v1/models", Some(query)))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = read_capped(response, LISTING_CAP).await?;
    serde_json::from_slice::<Listing>(&body)
        .ok()
        .map(|listing| listing.data)
}

/// The two listings as one sorted list.
fn merge(all: Vec<ListedModel>, zero_retention: Option<&HashSet<String>>, now: i64) -> ModelList {
    let mut models: Vec<Model> = all
        .into_iter()
        .map(|listed| {
            let price = listed
                .pricing
                .and_then(|pricing| pricing.prompt)
                .and_then(|per_token| per_token.trim().parse::<f64>().ok())
                // "-1" is how OpenRouter spells "varies"; it is not a price to budget against.
                .filter(|per_token| per_token.is_finite() && *per_token >= 0.0)
                .map(|per_token| round_price(per_token * 1e6));
            Model {
                zero_retention: zero_retention.map(|ids| ids.contains(&listed.id)),
                name: listed.name.unwrap_or_else(|| listed.id.clone()),
                description: listed.description.unwrap_or_default(),
                context_length: listed.context_length.unwrap_or(0),
                prompt_usd_per_million: price,
                id: listed.id,
            }
        })
        .collect();
    models.sort_by(|left, right| {
        let price = |model: &Model| model.prompt_usd_per_million.unwrap_or(f64::INFINITY);
        price(left).total_cmp(&price(right))
    });
    ModelList {
        fetched_at: now,
        models,
    }
}

/// A per-million price without the float noise of `per_token * 1e6` (`0.042000000000000003`).
pub fn round_price(per_million: f64) -> f64 {
    (per_million * 1e9).round() / 1e9
}
