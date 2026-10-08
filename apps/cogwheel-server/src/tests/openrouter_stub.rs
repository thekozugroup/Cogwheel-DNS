//! A scripted OpenRouter on loopback for the AI route and end-to-end tests, and the harness helpers
//! that wire AI review to it.
//!
//! A `std::net::TcpListener` thread on `127.0.0.1:0`, like `cogwheel_lists::serve_once`, but
//! serving a script: each request takes the first unused reply whose path prefix matches its
//! target, every request is recorded raw (method, target, headers, body), and a reply can be
//! *held* until the test releases it, which is how a request is caught in flight. Each connection
//! is answered on its own thread, so a held reply never hides a request that arrives behind it.
//! `AiState`'s client skips proxies for a loopback base (D19), so nothing here can leave the host.

use super::Harness;
use crate::ai::{AiState, Seen};
use crate::config::AppConfig;
use crate::state::ServerState;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;

/// The decisions endpoint.
pub const DECISIONS: &str = "/api/alpha/decisions";
/// The key-info endpoint.
pub const KEY_INFO: &str = "/api/v1/key";
/// Both model listings; the zero-retention one is the longer prefix.
pub const LISTING: &str = "/api/v1/models";
pub const ZDR_LISTING: &str = "/api/v1/models?output_modalities=decisions&zdr=true";

/// The longest a held reply waits for its release, so a test that forgets cannot hang the suite.
const HOLD_LIMIT: Duration = Duration::from_secs(10);

/// One canned answer.
#[derive(Debug, Clone)]
pub struct Canned {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    hold: bool,
}

impl Canned {
    /// A JSON reply.
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.into(),
            hold: false,
        }
    }

    /// The same, with one more header.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Recorded on arrival, answered only once the test calls [`Stub::release`].
    pub fn held(mut self) -> Self {
        self.hold = true;
        self
    }
}

/// What one request carried.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    /// Path and query.
    pub target: String,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    /// The first header of this (lowercase) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The body as JSON.
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("the request body is JSON")
    }
}

#[derive(Default)]
struct Shared {
    script: Mutex<Vec<(&'static str, Canned)>>,
    requests: Mutex<Vec<Recorded>>,
    released: Mutex<bool>,
    wake: Condvar,
    closed: AtomicBool,
}

/// A scripted listener. Dropping it stops the thread and lets any held reply go.
pub struct Stub {
    pub base: Url,
    address: SocketAddr,
    shared: Arc<Shared>,
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Stub {
    /// Serve `script`: `(path prefix, reply)` pairs, each used once, the first match winning. A
    /// request nothing matches is answered 500.
    pub fn serve(script: Vec<(&'static str, Canned)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback stub");
        let address = listener.local_addr().expect("the stub's address");
        let shared = Arc::new(Shared {
            script: Mutex::new(script),
            ..Shared::default()
        });
        let serving = Arc::clone(&shared);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if serving.closed.load(Ordering::Acquire) {
                    return;
                }
                let Ok(stream) = stream else { continue };
                let serving = Arc::clone(&serving);
                std::thread::spawn(move || answer(stream, &serving));
            }
        });
        Self {
            base: format!("http://{address}").parse().expect("a loopback url"),
            address,
            shared,
        }
    }

    /// Everything received so far, in order of arrival.
    pub fn requests(&self) -> Vec<Recorded> {
        guard(&self.shared.requests).clone()
    }

    /// How many requests have gone to targets starting with `path`.
    pub fn sent(&self, path: &str) -> usize {
        guard(&self.shared.requests)
            .iter()
            .filter(|request| request.target.starts_with(path))
            .count()
    }

    /// Wait (a few seconds at most) until `count` requests have arrived; whether they did.
    pub async fn wait_for(&self, count: usize) -> bool {
        for _ in 0..1_000 {
            if guard(&self.shared.requests).len() >= count {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    /// Let every held reply go, and every later one through without holding.
    pub fn release(&self) {
        *guard(&self.shared.released) = true;
        self.shared.wake.notify_all();
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        self.release();
        // Wake the accept loop so it sees `closed` and ends.
        let _ = TcpStream::connect(self.address);
    }
}

fn answer(stream: TcpStream, shared: &Shared) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let reply = {
        let mut script = guard(&shared.script);
        let position = script
            .iter()
            .position(|(prefix, _)| target.starts_with(prefix));
        position.map(|index| script.remove(index).1)
    }
    .unwrap_or_else(|| Canned::json(500, r#"{"error":{"message":"unscripted"}}"#));
    guard(&shared.requests).push(Recorded {
        method,
        target,
        headers,
        body,
    });

    if reply.hold {
        let released = guard(&shared.released);
        let _ = shared
            .wake
            .wait_timeout_while(released, HOLD_LIMIT, |released| !*released);
    }
    let mut stream = reader.into_inner();
    let mut head = format!(
        "HTTP/1.1 {} Stub\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(reply.body.as_bytes());
    let _ = stream.flush();
}

// --------------------------------------------------------------------- canned bodies

/// A key of OpenRouter's real shape, `sk-or-v1-` and 64 hex digits, made at run time so that no
/// such string sits in the source for secret scanning to trip on. Every 8-character window of the
/// hex part holds letters, so none can turn up by accident in a timestamp or a byte count.
pub fn realistic_key() -> String {
    let hex: String = (0u32..64)
        .map(|index| char::from_digit((index * 5 + 11) % 16, 16).unwrap_or('0'))
        .collect();
    format!("sk-or-v1-{hex}")
}

/// OpenRouter's `label` for `key`: a masked copy of it (D10), `sk-or-v1-abc...123`.
pub fn masked_label(key: &str) -> String {
    let hex = key.trim_start_matches("sk-or-v1-");
    format!(
        "sk-or-v1-{}...{}",
        &hex[..3.min(hex.len())],
        &hex[hex.len().saturating_sub(3)..]
    )
}

/// `GET /api/v1/key`'s answer, with the masked label and more than Cogwheel reads.
pub fn key_info(key: &str) -> String {
    json!({"data": {
        "label": masked_label(key),
        "limit": 5.0,
        "limit_remaining": 4.12,
        "usage": 0.88,
        "is_free_tier": false,
    }})
    .to_string()
}

/// A decisions answer: the role question at `confidence` (unrated when `None`), the effect
/// question when given, and `cost` (none when `None`).
pub fn decision(
    choice: &str,
    confidence: Option<f64>,
    effect: Option<(&str, f64)>,
    cost: Option<f64>,
) -> String {
    let mut role = json!({"type": "choice", "choice": choice});
    if let Some(confidence) = confidence {
        role["confidence"] = json!(confidence);
    }
    let mut answers = json!({"role": role});
    if let Some((outcome, confidence)) = effect {
        answers["effect"] = json!({"type": "choice", "choice": outcome, "confidence": confidence});
    }
    let mut usage = json!({"input_tokens": 480, "output_tokens": 70});
    if let Some(cost) = cost {
        usage["cost"] = json!(cost);
    }
    json!({
        "id": "gen-dec-1",
        "model": "typesafe/jev-1.13-20260917",
        "provider": "TypeSafe",
        "answers": answers,
        "usage": usage,
    })
    .to_string()
}

/// The answer the Test passes with.
pub fn passing() -> Canned {
    Canned::json(
        200,
        decision(
            "block",
            Some(0.91),
            Some(("works", 0.94)),
            Some(0.000_021_3),
        ),
    )
}

/// A model listing of `ids`, each priced at $0.042 per million prompt tokens.
pub fn listing(ids: &[&str]) -> String {
    let models: Vec<Value> = ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "name": format!("Vendor: {id}"),
                "description": "A decision model.",
                "context_length": 32_000,
                "pricing": {"prompt": "0.000000042"},
            })
        })
        .collect();
    json!({ "data": models }).to_string()
}

/// Both listings, in the order the script needs them: the longer prefix first.
pub fn listings(all: &[&str], zero_retention: &[&str]) -> Vec<(&'static str, Canned)> {
    vec![
        (ZDR_LISTING, Canned::json(200, listing(zero_retention))),
        (LISTING, Canned::json(200, listing(all))),
    ]
}

/// The model every test picks.
pub const JEV: &str = "typesafe/jev-1.13";

/// Stored consent and the model, as a household that turned review on leaves them.
pub const CONSENT: [(&str, &str); 2] = [("ai_enabled", "1"), ("ai_model", JEV)];

// --------------------------------------------------------------------- the harness

impl Harness {
    /// A harness whose AI review was loaded, the way a boot loads it, from the harness's
    /// configuration as `configure` leaves it, over `stored` settings written first.
    pub async fn with_ai(
        configure: impl FnOnce(&mut AppConfig),
        stored: &[(&'static str, &str)],
    ) -> Self {
        let mut harness = Self::new().await;
        for (key, value) in stored {
            harness
                .state
                .storage
                .set_setting(key, Some((*value).to_owned()))
                .await
                .expect("store a setting");
        }
        let mut config = (*harness.state.config).clone();
        configure(&mut config);
        let (ai, tap_rx) = AiState::load(&config, &harness.state.storage)
            .await
            .expect("AI review's state loads");
        harness.state = ServerState {
            config: Arc::new(config),
            ai,
            ..harness.state.clone()
        };
        harness._tap_rx = tap_rx;
        harness
    }

    /// A fresh `AiState` over the same database and configuration, as a restart would load it.
    /// Unlike [`Harness::restarted`], which shares the old one, nothing in memory carries over:
    /// what it reports was read back from storage (or, for the key, from the environment).
    pub async fn restarted_ai(&self) -> (ServerState, mpsc::Receiver<Seen>) {
        self.rebooted(|_| {}).await
    }

    /// [`Harness::restarted_ai`] with the environment changed first, as an operator would change
    /// it between two starts.
    pub async fn rebooted(
        &self,
        configure: impl FnOnce(&mut AppConfig),
    ) -> (ServerState, mpsc::Receiver<Seen>) {
        let mut config = (*self.state.config).clone();
        configure(&mut config);
        let (ai, tap_rx) = AiState::load(&config, &self.state.storage)
            .await
            .expect("AI review's state loads again");
        (
            ServerState {
                config: Arc::new(config),
                ai,
                ..self.state.clone()
            },
            tap_rx,
        )
    }

    /// The tap's receiving end, for a test that reads what the query-log writer offered.
    pub fn take_tap(&mut self) -> mpsc::Receiver<Seen> {
        std::mem::replace(&mut self._tap_rx, mpsc::channel(1).1)
    }
}

/// `COGWHEEL_AI__OPENROUTER_API_KEY=key`, with OpenRouter left at the harness's closed port.
pub fn keyed(key: &str) -> impl FnOnce(&mut AppConfig) {
    let key = key.to_owned();
    move |config| {
        config.ai_api_key = crate::ai::key::SecretKey::from_env(&key).expect("a header-safe key");
    }
}

/// Point AI review at `stub`, with `key` set in the environment.
pub fn wired(stub: &Stub, key: Option<&str>) -> impl FnOnce(&mut AppConfig) {
    let base = stub.base.clone();
    let key = key.map(ToOwned::to_owned);
    move |config| {
        config.ai_base_url = base;
        if let Some(key) = key {
            config.ai_api_key =
                crate::ai::key::SecretKey::from_env(&key).expect("a header-safe key");
        }
    }
}

// --------------------------------------------------------------------- calling the routes

/// Send one request through the router, the way a browser on the LAN would (no `Host`, so the
/// guard's name checks have nothing to refuse); the status and the body as text.
pub async fn call(
    state: &ServerState,
    method: &str,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, String) {
    call_with(state, method, uri, &[], body).await
}

/// [`call`] with headers.
pub async fn call_with(
    state: &ServerState,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (StatusCode, String) {
    let (status, _, text) = exchange(state, method, uri, headers, body).await;
    (status, text)
}

/// [`call_with`], keeping the response headers too.
pub async fn exchange(
    state: &ServerState,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> (StatusCode, HeaderMap, String) {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let request = request
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_owned())))
        .expect("build a request");
    let response =
        tower::ServiceExt::oneshot(crate::http::app_serving(state.clone(), None), request)
            .await
            .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read the body");
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// A body as JSON.
pub fn parsed(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|error| unreachable!("{error}: {text}"))
}

/// The sentence of an error body.
pub fn sentence(text: &str) -> String {
    parsed(text)["error"]
        .as_str()
        .unwrap_or_else(|| unreachable!("not an error: {text}"))
        .to_owned()
}

// --------------------------------------------------------------------- captured logs

/// Everything a TRACE subscriber wrote while its guard was held, on this thread.
#[derive(Clone, Default)]
pub struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        guard(&self.0).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&guard(&self.0)).into_owned()
    }
}

/// Capture every event at every level on this thread until the guard is dropped. A
/// `#[tokio::test]` runs on one thread, so that is everything the test drives.
pub fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    (captured, tracing::subscriber::set_default(subscriber))
}

/// Every 8-character window of `secret`. A text that contains none of them holds no useful part
/// of it; for an OpenRouter key that includes its shared `sk-or-v1` prefix.
pub fn windows(secret: &str) -> Vec<&str> {
    (0..=secret.len().saturating_sub(8))
        .filter_map(|start| secret.get(start..start + 8))
        .collect()
}
