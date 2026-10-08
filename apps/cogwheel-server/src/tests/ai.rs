//! AI review's routes (§10 routes 23–26): the key, the guard, the PUT, the Test and the model
//! picker, through the router, against a scripted OpenRouter on loopback. The AI list's own
//! routes, `/check`'s provenance and the installs behind them are in `verdicts`.
//!
//! Through the router rather than the handlers, because what is under test here is mostly what
//! leaves the process: the bodies, the statuses, and the headers the guard reads.

mod verdicts;

use super::openrouter_stub::{
    CONSENT, Canned, DECISIONS, JEV, KEY_INFO, Stub, call, call_with, capture, key_info, keyed,
    listings, masked_label, parsed, passing, realistic_key, sentence, windows, wired,
};
use super::{Harness, TempDir};
use crate::ai::Unavailable;
use crate::policy_build::{Rebuild, rebuild};
use crate::state::now_secs;
use axum::http::StatusCode;
use cogwheel_storage::AiVerdict;
use serde_json::json;

/// What every guarded route answers a request from outside.
const NOT_LOCAL: &str = "Change AI review from Cogwheel's own address or a local name. Behind a \
                         reverse proxy, add its name to COGWHEEL_SERVER__ALLOWED_HOSTS.";

const DAY: i64 = 86_400;

async fn put(harness: &Harness, body: &str) -> (StatusCode, String) {
    call(&harness.state, "PUT", "/api/v1/ai", Some(body)).await
}

async fn test_route(harness: &Harness, body: &str) -> (StatusCode, String) {
    call(&harness.state, "POST", "/api/v1/ai/test", Some(body)).await
}

/// Assert a refusal: its status and its sentence.
fn refused(answer: &(StatusCode, String), status: StatusCode, expected: &str) {
    assert_eq!(answer.0, status, "{}", answer.1);
    assert_eq!(sentence(&answer.1), expected);
}

/// A stored verdict, judged for `www.example.com` with the lists having no opinion.
pub fn row(domain: &str, verdict: &str, confidence: f64, judged_at: i64) -> AiVerdict {
    AiVerdict {
        domain: domain.to_owned(),
        verdict: verdict.to_owned(),
        why: (verdict == "ignore").then(|| "unsure".to_owned()),
        choice: verdict.to_owned(),
        confidence: Some(confidence),
        effect: None,
        effect_confidence: None,
        lists: "nothing".to_owned(),
        site: Some("www.example.com".to_owned()),
        conflict_site: None,
        rechecks: 0,
        model: "typesafe/jev-1.13-20260917".to_owned(),
        judged_at,
        review_after: judged_at + 30 * DAY,
    }
}

// --------------------------------------------------------------------- the key

/// Every answer a household (or anyone on the LAN) can get, with a key of OpenRouter's real
/// shape saved and then from the environment: none carries the key, OpenRouter's masked `label`,
/// or any 8 characters of the key in a row.
#[tokio::test]
async fn the_key_never_appears_in_any_response() {
    let key = realistic_key();
    let label = masked_label(&key);
    let put_key = json!({ "key": key }).to_string();
    for from_environment in [false, true] {
        let mut script = Vec::new();
        if !from_environment {
            for status in [401, 402, 404, 307, 429, 503, 200] {
                let body = if status == 200 {
                    key_info(&key)
                } else {
                    "{}".to_owned()
                };
                script.push((KEY_INFO, Canned::json(status, body)));
            }
        }
        script.extend(listings(&[JEV], &[JEV]));
        script.push((DECISIONS, passing()));
        let stub = Stub::serve(script);
        let environment = from_environment.then_some(key.as_str());
        let harness = Harness::with_ai(wired(&stub, environment), &[]).await;
        let state = &harness.state;

        let mut calls: Vec<(&str, String, Option<String>, StatusCode)> = Vec::new();
        let mut plan = |method: &'static str, uri: &str, body: Option<&str>, status| {
            calls.push((method, uri.to_owned(), body.map(str::to_owned), status));
        };
        if from_environment {
            plan("PUT", "/api/v1/ai", Some(&put_key), StatusCode::CONFLICT);
            plan(
                "PUT",
                "/api/v1/ai",
                Some(r#"{"key":null}"#),
                StatusCode::CONFLICT,
            );
        } else {
            plan(
                "PUT",
                "/api/v1/ai",
                Some(r#"{"key":"short"}"#),
                StatusCode::BAD_REQUEST,
            );
            // The key check's refusals, in the stub's order, then its 200.
            for status in [400, 409, 503, 503, 429, 503, 200] {
                let status = StatusCode::from_u16(status).expect("a status");
                plan("PUT", "/api/v1/ai", Some(&put_key), status);
            }
        }
        let malformed = [
            json!({ "enabled": key }).to_string(),
            json!({ "daily_limit_usd": key }).to_string(),
            format!(r#"{{"key":"{key}""#),
        ];
        for body in &malformed {
            plan("PUT", "/api/v1/ai", Some(body), StatusCode::BAD_REQUEST);
        }
        plan("GET", "/api/v1/ai/models", None, StatusCode::OK);
        plan(
            "PUT",
            "/api/v1/ai",
            Some(r#"{"model":"typesafe/jev-1.13"}"#),
            StatusCode::OK,
        );
        plan("POST", "/api/v1/ai/test", Some("{}"), StatusCode::OK);
        plan(
            "POST",
            "/api/v1/ai/test",
            Some(&put_key),
            StatusCode::TOO_MANY_REQUESTS,
        );
        // The pass just made is reused, so turning on asks nothing more.
        plan(
            "PUT",
            "/api/v1/ai",
            Some(r#"{"enabled":true}"#),
            StatusCode::OK,
        );
        for uri in [
            "/api/v1/ai",
            "/api/v1/settings",
            "/api/v1/overview",
            "/api/v1/check?domain=ads.example.com",
            "/api/v1/ai/verdicts?view=all",
        ] {
            plan("GET", uri, None, StatusCode::OK);
        }
        plan(
            "DELETE",
            "/api/v1/ai/verdicts/ads.example.com",
            None,
            StatusCode::NOT_FOUND,
        );
        plan(
            "POST",
            "/api/v1/ai/test",
            Some(r#"{"model":"Not A Model"}"#),
            StatusCode::BAD_REQUEST,
        );
        if !from_environment {
            plan("PUT", "/api/v1/ai", Some(r#"{"key":null}"#), StatusCode::OK);
        }

        let mut bodies = Vec::new();
        for (method, uri, body, status) in calls {
            let (answered, text) = call(state, method, &uri, body.as_deref()).await;
            assert_eq!(answered, status, "{method} {uri}: {text}");
            bodies.push(text);
        }
        let (refused, text) = call_with(
            state,
            "PUT",
            "/api/v1/ai",
            &[("host", "rebind.attacker.example")],
            Some(&put_key),
        )
        .await;
        assert_eq!(refused, StatusCode::BAD_REQUEST);
        bodies.push(text);

        for body in &bodies {
            assert!(
                !body.contains(&label),
                "a response carried the label: {body}"
            );
            for window in windows(&key) {
                assert!(
                    !body.contains(window),
                    "a response carried {window:?}: {body}"
                );
            }
        }
        // It was used, though: in the one header it belongs in.
        let bearer = format!("Bearer {key}");
        assert!(
            stub.requests()
                .iter()
                .any(|request| request.header("authorization") == Some(bearer.as_str())),
            "the key reached OpenRouter"
        );
    }
}

/// serde's error text quotes the value it choked on, and in this body that value can be the key.
/// The answer is a fixed sentence, and nothing at any level is logged with the key in it.
#[tokio::test]
async fn a_malformed_put_body_never_echoes_the_key() {
    let key = realistic_key();
    let harness = Harness::new().await;
    let (logs, _subscriber) = capture();
    let cases = [
        (
            "/api/v1/ai",
            json!({ "enabled": key }).to_string(),
            "That request body is missing a field, or one of them is the wrong type.",
        ),
        (
            "/api/v1/ai",
            json!({ "key": [key] }).to_string(),
            "That request body is missing a field, or one of them is the wrong type.",
        ),
        (
            "/api/v1/ai",
            format!(r#"{{"key":"{key}" "#),
            "That request body is not valid JSON.",
        ),
        (
            "/api/v1/ai/test",
            json!({ "model": 7, "key": key }).to_string(),
            "That request body is missing a field, or one of them is the wrong type.",
        ),
    ];
    for (uri, body, expected) in cases {
        let method = if uri.ends_with("test") { "POST" } else { "PUT" };
        let answer = call(&harness.state, method, uri, Some(&body)).await;
        refused(&answer, StatusCode::BAD_REQUEST, expected);
    }
    let logged = logs.text();
    assert!(
        logged.contains("/api/v1/ai"),
        "the capture saw the requests"
    );
    for window in windows(&key) {
        assert!(!logged.contains(window), "the log carried {window:?}");
    }
}

// --------------------------------------------------------------------- the guard

/// §9: every guarded route refuses a rebinding name (in `Host` or in the request line), a
/// foreign or `null` Origin, and a cross-site fetch; and serves this appliance's own addresses,
/// local names, the Vite dev server, a client that sends none of it, and an allowed proxy name.
#[tokio::test]
async fn the_guard_refuses_a_rebinding_host_and_a_foreign_origin() {
    let harness = Harness::with_ai(
        |config| config.allowed_hosts = vec!["dns.example.com".to_owned()],
        &[],
    )
    .await;
    let routes = [
        ("PUT", "/api/v1/ai", Some("{}")),
        ("POST", "/api/v1/ai/test", Some("{}")),
        ("GET", "/api/v1/ai/models", None),
        ("DELETE", "/api/v1/ai/verdicts", None),
        ("DELETE", "/api/v1/ai/verdicts/ads.example.com", None),
    ];
    let foreign: [&[(&str, &str)]; 5] = [
        &[("host", "rebind.attacker.example")],
        &[("host", "rebind.attacker.example:8080")],
        &[
            ("host", "192.168.1.2:8080"),
            ("origin", "https://evil.example"),
        ],
        &[("host", "cogwheel.lan"), ("origin", "null")],
        &[("host", "cogwheel.lan"), ("sec-fetch-site", "cross-site")],
    ];
    let local: [&[(&str, &str)]; 8] = [
        &[("host", "192.168.1.2:8080")],
        &[("host", "cogwheel.lan")],
        &[("host", "localhost:30080")],
        &[("host", "[fd00::2]:8080")],
        &[],
        &[
            ("host", "192.168.1.2:8080"),
            ("origin", "http://192.168.1.2:8080"),
            ("sec-fetch-site", "same-origin"),
        ],
        // The Vite dev server: a port away, on loopback both sides.
        &[
            ("host", "localhost:8080"),
            ("origin", "http://localhost:5173"),
            ("sec-fetch-site", "same-site"),
        ],
        &[
            ("host", "dns.example.com"),
            ("origin", "https://dns.example.com"),
        ],
    ];
    for (method, uri, body) in routes {
        for headers in foreign {
            let answer = call_with(&harness.state, method, uri, headers, body).await;
            refused(&answer, StatusCode::BAD_REQUEST, NOT_LOCAL);
        }
        // The Host header passes; the authority in the request line does not.
        let absolute = format!("http://rebind.attacker.example{uri}");
        let answer = call_with(
            &harness.state,
            method,
            &absolute,
            &[("host", "cogwheel.lan")],
            body,
        )
        .await;
        refused(&answer, StatusCode::BAD_REQUEST, NOT_LOCAL);

        for headers in local {
            let (status, text) = call_with(&harness.state, method, uri, headers, body).await;
            assert!(
                !text.contains("Change AI review from"),
                "{method} {uri} {headers:?} was refused: {status} {text}"
            );
        }
    }
    // The status itself is read-only, and stays readable from anywhere, like every other GET.
    let (status, _) = call_with(
        &harness.state,
        "GET",
        "/api/v1/ai",
        &[("host", "rebind.attacker.example")],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// --------------------------------------------------------------------- availability

#[tokio::test]
async fn enabling_needs_a_key_and_a_model() {
    let bare = Harness::new().await;
    let answer = put(&bare, r#"{"enabled":true}"#).await;
    refused(
        &answer,
        StatusCode::CONFLICT,
        "Add an OpenRouter key before turning AI review on.",
    );
    let with_key = Harness::with_ai(keyed(&realistic_key()), &[]).await;
    let answer = put(&with_key, r#"{"enabled":true}"#).await;
    refused(
        &answer,
        StatusCode::CONFLICT,
        "Pick a model before turning AI review on.",
    );
    for harness in [&bare, &with_key] {
        let stored = harness
            .state
            .storage
            .setting("ai_enabled")
            .await
            .expect("read");
        assert_eq!(stored, None, "nothing was turned on");
    }
    let (_, text) = call(&with_key.state, "GET", "/api/v1/ai", None).await;
    let status = parsed(&text);
    assert_eq!(status["data"]["state"], "off");
    assert_eq!(status["data"]["key"]["source"], "environment");
}

/// D13: `HISTORY_DAYS=0` promises no record of what is looked up, so the AI list is emptied at
/// startup, review is unavailable, and turning it on is refused.
#[tokio::test]
async fn history_days_zero_makes_ai_review_unavailable_and_empties_the_ai_list() {
    let harness = Harness::with_ai(keyed(&realistic_key()), &CONSENT).await;
    let now = now_secs();
    harness
        .state
        .ai
        .settle(
            &harness.state.storage,
            crate::ai::Cost::default(),
            vec![row("ads.example.net", "block", 0.95, now)],
        )
        .await
        .expect("committed");
    rebuild(&harness.state, Rebuild::Ai)
        .await
        .expect("installed");
    assert_eq!(harness.state.runtime.current_policy().ai.len(), 1);

    let (state, _tap) = harness.rebooted(|config| config.history_days = 0).await;
    rebuild(&state, Rebuild::Lists)
        .await
        .expect("the boot rebuild");
    assert!(state.runtime.current_policy().ai.is_empty());
    assert!(
        state
            .storage
            .list_ai_verdicts()
            .await
            .expect("read")
            .is_empty()
    );
    assert_eq!(
        state.storage.setting("ai_enabled").await.expect("read"),
        None
    );
    assert_eq!(
        state
            .storage
            .setting("ai_model")
            .await
            .expect("read")
            .as_deref(),
        Some(JEV),
        "the model is not history"
    );

    let (_, text) = call(&state, "GET", "/api/v1/ai", None).await;
    let status = parsed(&text);
    assert_eq!(status["data"]["available"], false);
    assert_eq!(status["data"]["unavailable_reason"], "history_off");
    assert_eq!(status["data"]["state"], "unavailable");
    assert_eq!(status["data"]["verdicts"]["block"], 0);
    let answer = call(&state, "PUT", "/api/v1/ai", Some(r#"{"enabled":true}"#)).await;
    refused(
        &answer,
        StatusCode::CONFLICT,
        Unavailable::HistoryOff.sentence(),
    );
    let _alive = state.ai.reviewer_alive();
    assert!(state.ai.tap().is_none(), "nothing is ever tapped");
}

/// Consent is not carried across an unavailable boot: with `AVAILABLE=false` once, review comes
/// back off, and needs the Turn on dialog again. The key and the model are kept.
#[tokio::test]
async fn review_needs_a_fresh_enable_after_being_unavailable() {
    let harness = Harness::with_ai(keyed(&realistic_key()), &CONSENT).await;
    let read = |text: String| parsed(&text)["data"].clone();
    let (_, text) = call(&harness.state, "GET", "/api/v1/ai", None).await;
    assert_eq!(read(text)["state"], "reviewing");

    let (off, _tap) = harness.rebooted(|config| config.ai_available = false).await;
    let (_, text) = call(&off, "GET", "/api/v1/ai", None).await;
    let status = read(text);
    assert_eq!(status["state"], "unavailable");
    assert_eq!(status["unavailable_reason"], "operator_off");

    let (back, _tap) = harness.rebooted(|_| {}).await;
    let (_, text) = call(&back, "GET", "/api/v1/ai", None).await;
    let status = read(text);
    assert_eq!(
        (status["state"].clone(), status["enabled"].clone()),
        (json!("off"), json!(false))
    );
    assert_eq!(status["model"]["id"], JEV);
    assert_eq!(status["key"]["source"], "environment");
}

/// D16: `AVAILABLE=false` refuses every change to AI review, the Test and the model list.
/// Removing a saved key is never refused, and neither is deleting what the AI list holds.
#[tokio::test]
async fn the_operator_switch_refuses_every_write() {
    let harness = Harness::with_ai(|config| config.ai_available = false, &[]).await;
    let sentence = Unavailable::OperatorOff.sentence();
    for body in [
        r#"{"enabled":true}"#,
        r#"{"enabled":false}"#,
        r#"{"model":"typesafe/jev-1.13"}"#,
        r#"{"daily_limit_usd":0.25}"#,
        r#"{"key":"sk-or-v1-a-different-key-entirely"}"#,
        r#"{"key":null,"enabled":false}"#,
    ] {
        refused(&put(&harness, body).await, StatusCode::CONFLICT, sentence);
    }
    refused(
        &test_route(&harness, "{}").await,
        StatusCode::CONFLICT,
        sentence,
    );
    let models = call(&harness.state, "GET", "/api/v1/ai/models", None).await;
    refused(&models, StatusCode::CONFLICT, sentence);

    assert_eq!(put(&harness, r#"{"key":null}"#).await.0, StatusCode::OK);
    let (status, _) = call(&harness.state, "DELETE", "/api/v1/ai/verdicts", None).await;
    assert_eq!(status, StatusCode::OK);
}

/// With the key in the environment the UI cannot replace or remove it, but everything else on the
/// card still changes, turning review on included.
#[tokio::test]
async fn an_environment_key_cannot_be_replaced_but_the_rest_can_change() {
    let mut script = listings(&[JEV], &[JEV]);
    script.push((DECISIONS, passing()));
    let stub = Stub::serve(script);
    let harness = Harness::with_ai(wired(&stub, Some(&realistic_key())), &[]).await;
    let sentence = "The OpenRouter key is set in the environment \
                    (COGWHEEL_AI__OPENROUTER_API_KEY); change it there.";
    for body in [
        r#"{"key":"sk-or-v1-a-different-key-entirely"}"#,
        r#"{"key":null}"#,
    ] {
        refused(&put(&harness, body).await, StatusCode::CONFLICT, sentence);
    }
    for body in [
        r#"{"model":"typesafe/jev-1.13"}"#,
        r#"{"daily_limit_usd":0.25}"#,
        r#"{"enabled":true}"#,
    ] {
        let (status, text) = put(&harness, body).await;
        assert_eq!(status, StatusCode::OK, "{body}: {text}");
    }
    let (_, text) = call(&harness.state, "GET", "/api/v1/ai", None).await;
    let status = parsed(&text)["data"].clone();
    assert_eq!(status["state"], "reviewing");
    assert_eq!(status["daily_limit_usd"], 0.25);
    assert_eq!(status["model"]["prompt_usd_per_million"], 0.042);
    assert_eq!(status["key"]["source"], "environment");
    assert_eq!(stub.sent(DECISIONS), 1, "turning on ran the Test once");
}

// --------------------------------------------------------------------- the Test and the key check

/// A failing Test's status and sentence reach the browser unchanged, through the Test and through
/// the PUT that turns review on.
#[tokio::test]
async fn a_test_failure_passes_through_unchanged() {
    let cases = [
        (401, StatusCode::BAD_REQUEST, "OpenRouter refused the key."),
        (
            429,
            StatusCode::TOO_MANY_REQUESTS,
            "OpenRouter is rate-limiting this key; try again in a minute.",
        ),
        (
            503,
            StatusCode::SERVICE_UNAVAILABLE,
            "OpenRouter did not answer; try again in a minute.",
        ),
    ];
    for (upstream, status, expected) in cases {
        for through_the_put in [false, true] {
            let stub = Stub::serve(vec![(DECISIONS, Canned::json(upstream, "{}"))]);
            let harness =
                Harness::with_ai(wired(&stub, Some(&realistic_key())), &[("ai_model", JEV)]).await;
            let answer = if through_the_put {
                put(&harness, r#"{"enabled":true}"#).await
            } else {
                test_route(&harness, "{}").await
            };
            refused(&answer, status, expected);
            assert_eq!(stub.sent(DECISIONS), 1);
            let stored = harness
                .state
                .storage
                .setting("ai_enabled")
                .await
                .expect("read");
            assert_eq!(stored, None, "a failed Test turns nothing on");
        }
    }
}

/// Route 24's key-check table, row by row, and a key file written only for the key OpenRouter
/// accepted.
#[tokio::test]
async fn the_key_check_maps_every_status() {
    let rows = [
        (
            401,
            StatusCode::BAD_REQUEST,
            "OpenRouter did not accept that key.",
        ),
        (
            402,
            StatusCode::CONFLICT,
            "The OpenRouter account behind that key is out of credit; nothing was saved.",
        ),
        (
            404,
            StatusCode::SERVICE_UNAVAILABLE,
            "OpenRouter could not check that key, so nothing was saved.",
        ),
        (
            307,
            StatusCode::SERVICE_UNAVAILABLE,
            "OpenRouter could not check that key, so nothing was saved.",
        ),
        (
            429,
            StatusCode::TOO_MANY_REQUESTS,
            "OpenRouter is rate-limiting this key; try again in a minute.",
        ),
        (
            503,
            StatusCode::SERVICE_UNAVAILABLE,
            "OpenRouter could not be reached, so nothing was saved.",
        ),
    ];
    let key = realistic_key();
    let mut script: Vec<_> = rows
        .iter()
        .map(|(status, ..)| (KEY_INFO, Canned::json(*status, "{}")))
        .collect();
    script.push((KEY_INFO, Canned::json(200, key_info(&key))));
    let stub = Stub::serve(script);
    let data = TempDir::new("ai-key");
    let database = data.path().join("cogwheel.db").display().to_string();
    let base = stub.base.clone();
    let harness = Harness::with_ai(
        move |config| {
            config.ai_base_url = base;
            config.database_url = database;
        },
        &[],
    )
    .await;
    let file = data.path().join("openrouter.key");
    let body = json!({ "key": key }).to_string();
    for (_, status, expected) in rows {
        refused(&put(&harness, &body).await, status, expected);
        assert!(!file.exists(), "nothing was saved: {expected}");
    }
    let (status, text) = put(&harness, &body).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let saved = parsed(&text)["data"]["key"].clone();
    assert_eq!(
        saved,
        json!({"source": "saved", "limit_usd": 5.0, "limit_remaining_usd": 4.12,
               "checked_at": saved["checked_at"]})
    );
    assert_eq!(std::fs::read_to_string(&file).expect("the key file"), key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&file).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

/// A model that never says how sure it is would pass, then spend the daily limit on rows that
/// can never clear a bar (D6). It fails the Test, and the Test is still charged.
#[tokio::test]
async fn a_model_that_does_not_say_how_sure_it_is_fails_the_test() {
    let unrated = super::openrouter_stub::decision("block", None, None, Some(0.00002));
    let stub = Stub::serve(vec![(DECISIONS, Canned::json(200, unrated))]);
    let harness =
        Harness::with_ai(wired(&stub, Some(&realistic_key())), &[("ai_model", JEV)]).await;
    refused(
        &test_route(&harness, "{}").await,
        StatusCode::CONFLICT,
        "That model does not say how sure it is; pick another.",
    );
    let (_, text) = call(&harness.state, "GET", "/api/v1/ai", None).await;
    let today = parsed(&text)["data"]["today"].clone();
    assert_eq!(
        (today["requests"].clone(), today["spent_usd"].clone()),
        (json!(1), json!(0.00002))
    );
    let stored = harness
        .state
        .storage
        .setting("ai_spend")
        .await
        .expect("read");
    assert!(
        stored.is_some_and(|spend| spend.ends_with(" 20 1 0")),
        "the charge is stored"
    );
}

/// Route 25 merges both listings and the last Test of each model; the saved model of an enabled
/// configuration reads passed, because enabling needed a pass.
#[tokio::test]
async fn the_model_list_marks_zero_retention_and_tested_models() {
    let span = "respan/span-01";
    let mut script = listings(&[JEV, "cloudflare/clef", span], &[JEV, "cloudflare/clef"]);
    script.push((DECISIONS, Canned::json(400, "{}")));
    let stub = Stub::serve(script);
    let harness = Harness::with_ai(wired(&stub, Some(&realistic_key())), &CONSENT).await;
    let staged = json!({ "model": span }).to_string();
    let (status, _) = call(&harness.state, "GET", "/api/v1/ai/models", None).await;
    assert_eq!(status, StatusCode::OK);
    refused(
        &test_route(&harness, &staged).await,
        StatusCode::CONFLICT,
        "That model cannot answer Cogwheel's questions; pick another.",
    );

    let (_, text) = call(&harness.state, "GET", "/api/v1/ai/models", None).await;
    let list = parsed(&text)["data"].clone();
    assert_eq!(list["zero_retention_required"], true);
    let marks: Vec<(String, bool, Option<String>)> = list["models"]
        .as_array()
        .expect("a model list")
        .iter()
        .map(|model| {
            (
                model["id"].as_str().unwrap_or_default().to_owned(),
                model["zero_retention"].as_bool().unwrap_or(false),
                model["tested"].as_str().map(str::to_owned),
            )
        })
        .collect();
    assert_eq!(
        marks,
        [
            (JEV.to_owned(), true, Some("passed".to_owned())),
            ("cloudflare/clef".to_owned(), true, None),
            (span.to_owned(), false, Some("failed".to_owned())),
        ]
    );
    let first = &list["models"][0];
    assert_eq!(first["usd_per_thousand_names"], 0.021);
    assert_eq!(first["name"], "Vendor: typesafe/jev-1.13");
    // Fetched once for the hour, and without the key.
    assert_eq!(stub.sent("/api/v1/models"), 2);
    assert!(
        stub.requests()
            .iter()
            .filter(|request| request.target.starts_with("/api/v1/models"))
            .all(|request| request.header("authorization").is_none())
    );
}

#[tokio::test]
async fn the_daily_limit_must_be_a_preset() {
    let harness = Harness::new().await;
    for limit in ["0.07", "2", "0", "-0.05", "0.1001", "\"0.10\""] {
        let answer = put(&harness, &format!(r#"{{"daily_limit_usd":{limit}}}"#)).await;
        if limit.starts_with('"') {
            assert_eq!(
                answer.0,
                StatusCode::BAD_REQUEST,
                "a string is not a number"
            );
            continue;
        }
        refused(
            &answer,
            StatusCode::BAD_REQUEST,
            "Choose a daily limit of 5¢, 10¢, 25¢ or $1.",
        );
    }
    for limit in [0.05, 0.1, 0.25, 1.0] {
        let (status, text) = put(&harness, &json!({ "daily_limit_usd": limit }).to_string()).await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert_eq!(parsed(&text)["data"]["daily_limit_usd"], limit);
    }
}

#[tokio::test]
async fn test_is_rate_limited() {
    let stub = Stub::serve(vec![(DECISIONS, passing())]);
    let harness =
        Harness::with_ai(wired(&stub, Some(&realistic_key())), &[("ai_model", JEV)]).await;
    let (status, text) = test_route(&harness, "{}").await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let result = parsed(&text)["data"].clone();
    assert_eq!(result["ok"], true);
    assert_eq!(result["answer"]["confidence"], 0.91);
    assert_eq!(result["answer"]["effect_confidence"], 0.94);

    let (status, text) = test_route(&harness, "{}").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let said = sentence(&text);
    let seconds: u64 = said
        .strip_prefix("Tested a moment ago; try again in ")
        .and_then(|rest| rest.strip_suffix(" seconds."))
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or_else(|| unreachable!("{said}"));
    assert!((1..=10).contains(&seconds), "{said}");
    assert_eq!(stub.sent(DECISIONS), 1, "the second was never sent");
}
