//! Tests for the server crate: the harness the handler tests run against, plus the few checks
//! that are about the shape of the workspace rather than about a route.

mod handlers;
mod reads;

use crate::api::{check, devices, lists, rules};
use crate::config::{AppConfig, Profile};
use crate::http::{ApiJson, ApiQuery, Readiness};
use crate::querylog::EventBus;
use crate::state::{Cached, RefreshGate, ScopeAllocator, ServerState, TOP_DOMAIN_TTL};
use crate::{CliAction, parse_cli};

use axum::extract::State;
use axum::http::StatusCode;
use cogwheel_dns_core::{DnsRuntime, LogEntry, build_resolver};
use cogwheel_policy::{BlockMode, Policy};
use cogwheel_storage::Storage;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::{mpsc, watch};

/// A directory under the system temp dir, removed when the test that made it ends.
///
/// A hand-rolled one rather than a dev-dependency: the whole need is three lines, and this crate
/// is the one place in the workspace where an extra package shows up in the release lockfile.
pub struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "cogwheel-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create the temporary list cache");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A server state wired to an in-memory database and a temporary list cache.
///
/// The receiver and the shutdown sender are held rather than dropped: the runtime's log channel
/// and every task's shutdown signal are live for as long as a test holds this.
pub struct Harness {
    pub state: ServerState,
    pub lists: TempDir,
    _log_rx: mpsc::Receiver<LogEntry>,
    _shutdown: watch::Sender<bool>,
}

impl Harness {
    /// A harness with no lists, no devices and no rules.
    ///
    /// The first-boot seed is removed on the way out so that list counting starts from zero:
    /// what `seed_if_empty` inserts is storage's business and is tested there.
    pub async fn new() -> Self {
        Self::with_block_mode(BlockMode::NullIp).await
    }

    pub async fn with_block_mode(mode: BlockMode) -> Self {
        let lists = TempDir::new("lists");
        let mut config = AppConfig::for_profile(Profile::Home);
        config.database_url = ":memory:".to_owned();
        config.block_mode = mode;
        // Fixed so no test shells out to `hostname -I` on a machine this does not control.
        config.advertised_dns_targets = vec!["192.168.1.2".to_owned()];

        let storage = Storage::open(&config.database_url)
            .await
            .expect("open an in-memory database");
        for source in storage
            .list_sources()
            .await
            .expect("list the seeded sources")
        {
            storage
                .delete_source(&source.id)
                .await
                .expect("remove the seeded source");
        }

        let resolver = build_resolver(&config.upstream_servers).expect("build a resolver");
        let (runtime, log_rx) = DnsRuntime::new(resolver, Arc::new(Policy::empty(mode)));
        let (shutdown, shutdown_rx) = watch::channel(false);
        let state = ServerState {
            lists_dir: Arc::new(lists.path().to_path_buf()),
            config: Arc::new(config),
            storage,
            runtime,
            readiness: Arc::new(Readiness::default()),
            events: EventBus::new(),
            device_names: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
            indexed_lists: Arc::new(RwLock::new(Vec::new())),
            scopes: Arc::new(Mutex::new(ScopeAllocator::new())),
            rebuild_lock: Arc::new(tokio::sync::Mutex::new(())),
            refresh_gate: Arc::new(RefreshGate::default()),
            top_domains: Arc::new(Cached::new(TOP_DOMAIN_TTL)),
            connect_targets: Arc::new(Cached::new(TOP_DOMAIN_TTL)),
            http: reqwest::Client::new(),
            shutdown: shutdown_rx,
        };
        Self {
            state,
            lists,
            _log_rx: log_rx,
            _shutdown: shutdown,
        }
    }

    /// A second state over the same database and list cache, as a restart would produce.
    ///
    /// The caller holds the fresh runtime's log receiver: dropping it would make the runtime's
    /// `try_send` report a closed channel, which is not what a restarted process looks like.
    pub fn restarted(&self) -> (ServerState, mpsc::Receiver<LogEntry>) {
        let resolver =
            build_resolver(&self.state.config.upstream_servers).expect("build a resolver");
        let (runtime, log_rx) = DnsRuntime::new(
            resolver,
            Arc::new(Policy::empty(self.state.config.block_mode)),
        );
        let state = ServerState {
            runtime,
            scopes: Arc::new(Mutex::new(ScopeAllocator::new())),
            device_names: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
            indexed_lists: Arc::new(RwLock::new(Vec::new())),
            ..self.state.clone()
        };
        (state, log_rx)
    }
}

/// Write a list body into the cache exactly as a successful fetch would have.
///
/// `data:` URLs are the offline fetch path these tests otherwise use, but the URL parser
/// percent-encodes `|`, `^` and `@`, so an ABP body cannot survive one. Seeding the cache
/// directly is also the boot path of §2.7 — the policy is compiled from these files.
pub fn cache_body(harness: &Harness, source_id: &str, body: &str) {
    std::fs::write(harness.lists.path().join(format!("{source_id}.txt")), body)
        .expect("write a cached list body");
}

// --------------------------------------------------------------------- fixtures

/// A `data:` list body, which the fetcher decodes locally — these tests never touch the network.
const ADS_LIST: &str = "data:text/plain,ads.example.com%0Atracker.example.com";

fn device_input(name: &str, ip: &str) -> devices::DeviceInput {
    devices::DeviceInput {
        name: name.to_owned(),
        ip_address: ip.to_owned(),
        filtering: Some(true),
        all_lists: Some(true),
        lists: Some(Vec::new()),
    }
}

fn rule_input(domain: &str, action: &str, device_id: Option<&str>) -> rules::RuleInput {
    rules::RuleInput {
        domain: domain.to_owned(),
        action: action.to_owned(),
        device_id: device_id.map(ToOwned::to_owned),
    }
}

fn list_input(name: &str, url: &str, kind: &str) -> lists::ListInput {
    lists::ListInput {
        name: name.to_owned(),
        url: url.to_owned(),
        kind: kind.to_owned(),
        enabled: Some(true),
    }
}

async fn subscribe(harness: &Harness, name: &str, url: &str, kind: &str) -> lists::ListCreated {
    lists::create(
        State(harness.state.clone()),
        ApiJson(list_input(name, url, kind)),
    )
    .await
    .expect("subscribing to a list")
    .data
}

async fn verdict(harness: &Harness, domain: &str, client: Option<&str>) -> check::CheckResult {
    check::check(
        State(harness.state.clone()),
        ApiQuery(check::CheckQuery {
            domain: Some(domain.to_owned()),
            client: client.map(ToOwned::to_owned),
        }),
    )
    .await
    .expect("checking a domain")
    .data
}

// --------------------------------------------------------------------- workspace shape

/// The crate graph ADR 0001 fixes, checked against the manifests themselves.
///
/// Moved here from the deleted `cogwheel-api` crate. The boundary it protects is the one that
/// keeps the evaluator free of I/O: policy depends on nothing, lists and dns-core depend only on
/// policy, storage depends on nothing, and only the server is allowed to know about all of them.
#[test]
fn crate_path_dependencies_match_the_adr_boundaries() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps dir")
        .parent()
        .expect("workspace root");

    let expected = [
        ("crates/cogwheel-policy/Cargo.toml", &[][..]),
        ("crates/cogwheel-lists/Cargo.toml", &["cogwheel-policy"][..]),
        (
            "crates/cogwheel-dns-core/Cargo.toml",
            &["cogwheel-policy"][..],
        ),
        ("crates/cogwheel-storage/Cargo.toml", &[][..]),
        (
            "apps/cogwheel-server/Cargo.toml",
            &[
                "cogwheel-dns-core",
                "cogwheel-lists",
                "cogwheel-policy",
                "cogwheel-storage",
            ][..],
        ),
    ];

    for (relative_path, allowed) in expected {
        let manifest = std::fs::read_to_string(workspace_root.join(relative_path))
            .unwrap_or_else(|error| unreachable!("failed to read {relative_path}: {error}"));
        assert_eq!(
            path_dependencies(&manifest),
            allowed,
            "{relative_path} drifted from ADR 0001 crate boundaries; update the ADR first if \
             this coupling is intentional"
        );
    }
}

/// Collect the names of path dependencies declared in a manifest.
///
/// Only dependency tables are considered. Scanning every `path =` line would also match
/// `[[bin]]`, `[[example]]` and `[[bench]]` targets, which are not couplings between crates at
/// all — that false positive is what this section tracking exists to avoid.
fn path_dependencies(manifest: &str) -> Vec<&str> {
    let mut dependencies = Vec::new();
    let mut in_dependency_table = false;

    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let header = trimmed.trim_start_matches('[').trim_end_matches(']');
            in_dependency_table = header == "dependencies"
                || header == "dev-dependencies"
                || header == "build-dependencies"
                || header.ends_with(".dependencies")
                || header.ends_with(".dev-dependencies")
                || header.ends_with(".build-dependencies");
            continue;
        }
        if in_dependency_table
            && trimmed.contains("path =")
            && let Some(name) = trimmed.split('=').next()
        {
            dependencies.push(name.trim());
        }
    }

    dependencies.sort_unstable();
    dependencies
}

/// The longest a source file in this tree may be.
///
/// Not a style preference: a file this long is one nobody re-reads before changing, and the two
/// files that reached it did so by accumulating concerns rather than lines. The number is the
/// project's own, so the check belongs beside the ADR test rather than in a lint config.
const MAX_FILE_LINES: usize = 800;

/// The two structural rules §1.5 fixes that nothing else enforces: the file-length ceiling, and
/// the exact set of modules behind `api/`.
///
/// The crate graph already has the ADR test above. These two had only an external counting
/// script, which is to say nothing that fails a build.
#[test]
fn the_source_tree_keeps_the_shape_the_spec_fixes() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps dir")
        .parent()
        .expect("workspace root");

    let mut over_budget = Vec::new();
    let mut queue = vec![workspace_root.to_owned()];
    while let Some(directory) = queue.pop() {
        let entries = std::fs::read_dir(&directory).expect("read a source directory");
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Build output, vendored packages and the git object store are not ours to measure.
            if matches!(&*name, "target" | "node_modules" | "dist" | ".git") {
                continue;
            }
            if path.is_dir() {
                queue.push(path);
            } else if matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("rs" | "ts" | "tsx" | "css")
            ) {
                let lines = std::fs::read_to_string(&path).map_or(0, |text| text.lines().count());
                if lines > MAX_FILE_LINES {
                    over_budget.push(format!("{} ({lines} lines)", path.display()));
                }
            }
        }
    }
    over_budget.sort();
    assert!(
        over_budget.is_empty(),
        "these files are over the {MAX_FILE_LINES}-line ceiling; split them rather than raising \
         it: {over_budget:#?}"
    );

    let mut modules: Vec<String> =
        std::fs::read_dir(workspace_root.join("apps/cogwheel-server/src/api"))
            .expect("read the api directory")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
    modules.sort();
    assert_eq!(
        modules,
        [
            "check.rs",
            "devices.rs",
            "lists.rs",
            "mod.rs",
            "overview.rs",
            "queries.rs",
            "rules.rs",
            "runtime.rs",
            "settings.rs",
        ],
        "api/ drifted from the module list in spec section 1.5; amend the spec first if the new \
         shape is the right one"
    );
}

/// hickory builds its TLS client config as `RootCertStore::empty()` and only fills it in under a
/// trust-anchor feature. With `tls-ring` alone the store stays EMPTY, so every DoT/DoH
/// certificate fails to validate: the build succeeds, the TCP connection succeeds, the handshake
/// is rejected, and every encrypted query returns SERVFAIL forever. Measured — that is exactly
/// what happened before `webpki-roots` was added.
///
/// Nothing else fails if the feature is dropped, which is what makes it worth pinning here. A
/// guard on the manifest is crude, but it is the only place the mistake can be made and the only
/// place it can be caught cheaply; the alternative is a live TLS connection in the test suite.
#[test]
fn encrypted_upstreams_have_trust_anchors_compiled_in() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../Cargo.toml")
        .canonicalize()
        .expect("workspace manifest should exist");
    let text = std::fs::read_to_string(&manifest).expect("read workspace manifest");
    let hickory = text
        .split("hickory-resolver = ")
        .nth(1)
        .expect("workspace should pin hickory-resolver");
    let declaration = &hickory[..hickory.find('}').unwrap_or(hickory.len())];

    assert!(
        declaration.contains("webpki-roots") || declaration.contains("rustls-platform-verifier"),
        "hickory-resolver must enable a trust-anchor feature or DoT/DoH silently never \
         resolves; found: {declaration}"
    );
    assert!(
        declaration.contains("tls-ring") || declaration.contains("tls-aws-lc-rs"),
        "hickory-resolver must enable a TLS feature for DoT upstreams; found: {declaration}"
    );
}

// --------------------------------------------------------------------- routing

/// The router itself: that it builds at all, and that the routes §3 fixes are where the web
/// expects them.
///
/// Worth its own test because two of them overlap — `/api/v1/lists/refresh` sits inside
/// `/api/v1/lists/{id}` — and because an overlap is a panic at router-build time, which is to
/// say at the first request of a deployed appliance rather than here.
#[tokio::test]
async fn the_router_answers_every_route_in_the_contract() {
    let harness = Harness::new().await;
    let cases = [
        ("GET", "/health/live", "", StatusCode::OK),
        // Nothing marked this harness ready, which is the state a booting process is in.
        ("GET", "/health/ready", "", StatusCode::SERVICE_UNAVAILABLE),
        ("GET", "/api/v1/overview", "", StatusCode::OK),
        (
            "POST",
            "/api/v1/runtime/pause",
            "{\"minutes\":5}",
            StatusCode::OK,
        ),
        ("POST", "/api/v1/runtime/resume", "", StatusCode::OK),
        (
            "GET",
            "/api/v1/queries?limit=5&blocked=true",
            "",
            StatusCode::OK,
        ),
        ("DELETE", "/api/v1/queries", "", StatusCode::OK),
        ("GET", "/api/v1/devices", "", StatusCode::OK),
        (
            "POST",
            "/api/v1/devices",
            "{\"name\":\"Tablet\",\"ip_address\":\"192.168.1.20\"}",
            StatusCode::OK,
        ),
        ("GET", "/api/v1/rules", "", StatusCode::OK),
        (
            "POST",
            "/api/v1/rules",
            "{\"domain\":\"ads.example.com\",\"action\":\"block\"}",
            StatusCode::OK,
        ),
        ("GET", "/api/v1/lists", "", StatusCode::OK),
        // The static segment must win over `{id}`, or "refresh all" would 404 as a list id.
        ("POST", "/api/v1/lists/refresh", "{}", StatusCode::OK),
        (
            "GET",
            "/api/v1/check?domain=ads.example.com",
            "",
            StatusCode::OK,
        ),
        ("GET", "/api/v1/settings", "", StatusCode::OK),
        // An unmatched api path is a genuine 404, never the SPA shell.
        ("GET", "/api/v1/nonsense", "", StatusCode::NOT_FOUND),
    ];

    let app = crate::http::app(harness.state.clone());
    for (method, uri, body, expected) in cases {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .expect("build a request");
        let response = tower::ServiceExt::oneshot(app.clone(), request)
            .await
            .expect("the router answers");
        assert_eq!(response.status(), expected, "{method} {uri}");
    }
}

/// §3 promises `{"error": …}` for every failure, and a typo'd endpoint is a failure.
///
/// Worth asserting on the body and not just the status: the SPA fallback serves `index.html`
/// for anything it does not recognise, so the shape this checks is exactly the one that can
/// regress into HTML without changing a single status code.
#[tokio::test]
async fn an_unknown_endpoint_answers_json_not_the_web_shell() {
    let harness = Harness::new().await;
    let app = crate::http::app(harness.state.clone());
    for uri in ["/api/v1/definitely-not-real", "/health/nope"] {
        let request = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .expect("build a request");
        let response = tower::ServiceExt::oneshot(app.clone(), request)
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_error_envelope(response, uri).await;
    }
}

/// §3's error set is 400, 404, 409, 429, 503 and 500, always as `{"error": "<sentence>"}`.
///
/// Malformed input is where that is easiest to lose, and it is unreachable from a handler test:
/// axum's `Query` and `Json` rejections only run inside the router, and left alone they answer
/// `text/plain` with serde's internal wording — under 415 and 422, two statuses §3 does not have.
#[tokio::test]
async fn malformed_input_answers_one_of_the_contract_errors() {
    let harness = Harness::new().await;
    let app = crate::http::app(harness.state.clone());
    let cases = [
        ("GET", "/api/v1/queries?limit=abc", JSON, ""),
        ("GET", "/api/v1/queries?blocked=maybe", JSON, ""),
        ("GET", "/api/v1/queries?before=tomorrow", JSON, ""),
        (
            "POST",
            "/api/v1/runtime/pause",
            JSON,
            "{\"minutes\":\"ten\"}",
        ),
        ("POST", "/api/v1/runtime/pause", JSON, "{ not json"),
        // No Content-Type at all: axum answers this 415 unless it is caught.
        ("POST", "/api/v1/runtime/pause", None, "{\"minutes\":5}"),
        ("POST", "/api/v1/devices", JSON, "{\"name\":\"Tablet\"}"),
        // The optional body of "refresh all" is still a body when it is sent.
        ("POST", "/api/v1/lists/refresh", JSON, "{\"id\":7}"),
    ];

    for (method, uri, content_type, body) in cases {
        let mut request = axum::http::Request::builder().method(method).uri(uri);
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        let request = request
            .body(axum::body::Body::from(body))
            .expect("build a request");
        let response = tower::ServiceExt::oneshot(app.clone(), request)
            .await
            .expect("the router answers");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{method} {uri} {body}"
        );
        assert_error_envelope(response, uri).await;
    }
}

/// The `Content-Type` every JSON case above sends.
const JSON: Option<&str> = Some("application/json");

/// Assert a response is `application/json` carrying an `error` sentence.
async fn assert_error_envelope(response: axum::response::Response, label: &str) {
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        content_type.starts_with("application/json"),
        "{label} answered {content_type}"
    );
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read the body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("a json envelope");
    let message = json
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| unreachable!("{label} answered {json}"));
    assert!(
        message.ends_with('.') && !message.contains("Failed to deserialize"),
        "{label} answered a serde message rather than a sentence: {message}"
    );
}

// --------------------------------------------------------------------- command line

fn cli(args: &[&str]) -> CliAction {
    parse_cli(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
}

// The workspace bans `panic!`, so these render the wrong variant into the assertion message
// instead of unwrapping it.
fn printed(action: CliAction) -> String {
    match action {
        CliAction::Print(text) => text,
        other => format!("expected Print, got {other:?}"),
    }
}

fn failed(action: CliAction) -> String {
    match action {
        CliAction::Fail(message) => message,
        other => format!("expected Fail, got {other:?}"),
    }
}

#[test]
fn no_arguments_starts_the_server() {
    assert_eq!(cli(&[]), CliAction::Run);
}

#[test]
fn version_prints_the_crate_version_and_does_not_start_the_server() {
    for flag in ["--version", "-V"] {
        let text = printed(cli(&[flag]));
        assert!(
            text.starts_with("cogwheel-server ") && text.contains(env!("CARGO_PKG_VERSION")),
            "{flag} produced {text:?}"
        );
    }
}

#[test]
fn help_prints_usage_and_does_not_start_the_server() {
    for flag in ["--help", "-h"] {
        let text = printed(cli(&[flag]));
        assert!(text.contains("Usage:"), "{flag} produced {text:?}");
    }
}

/// The regression that motivated the parser: an argument the binary does not understand must NOT
/// fall through and start a DNS server. On an appliance that means a second resolver racing the
/// real one for port 53.
///
/// `healthcheck` is in this list deliberately — it used to be accepted and returned success
/// without checking anything.
#[test]
fn an_unrecognised_argument_refuses_to_start_the_server() {
    for arg in ["--verison", "-x", "serve", "healthcheck", "/etc/cogwheel"] {
        let message = failed(cli(&[arg]));
        assert!(
            message.contains(arg) && message.contains("unrecognised"),
            "{arg} produced {message:?}"
        );
    }
}

// --------------------------------------------------------------------- block mode

#[test]
fn the_default_block_response_is_an_all_zeros_address() {
    let config = AppConfig::from_source(|_| None).expect("defaults load");
    assert_eq!(config.block_mode, BlockMode::NullIp);
}

#[test]
fn each_block_mode_spelling_reaches_the_policy() {
    for (spelling, expected) in [
        ("null_ip", BlockMode::NullIp),
        (" NULL-IP ", BlockMode::NullIp),
        ("nxdomain", BlockMode::NxDomain),
        ("nodata", BlockMode::NoData),
        ("refused", BlockMode::Refused),
    ] {
        let config = AppConfig::from_source(|key| {
            (key == "COGWHEEL_BLOCKING__MODE").then(|| spelling.to_owned())
        })
        .unwrap_or_else(|error| unreachable!("{spelling:?} should parse: {error}"));
        assert_eq!(config.block_mode, expected, "{spelling:?}");
        // The mode reaches the hot path through the policy, not through a global.
        assert_eq!(Policy::empty(config.block_mode).block_mode, expected);
    }
}

#[test]
fn an_unknown_block_mode_fails_startup() {
    let error = AppConfig::from_source(|key| {
        (key == "COGWHEEL_BLOCKING__MODE").then(|| "sinkhole".to_owned())
    })
    .expect_err("an unknown mode must not boot");
    assert!(error.to_string().contains("COGWHEEL_BLOCKING__MODE"));
}

#[tokio::test]
async fn the_block_mode_survives_a_policy_rebuild() {
    let harness = Harness::with_block_mode(BlockMode::NxDomain).await;
    crate::policy_build::rebuild(&harness.state, crate::policy_build::Rebuild::Lists)
        .await
        .expect("rebuild");
    assert_eq!(
        harness.state.runtime.current_policy().block_mode,
        BlockMode::NxDomain
    );
}
