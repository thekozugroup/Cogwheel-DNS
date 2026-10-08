//! `client.rs`: classification, `Retry-After`, backoff, and the client itself (D19).

use crate::ai::client::{
    self, BACKOFF_CAP, Class, KeyCheck, Reply as Answer, backoff, classify, parse_key_info,
    retry_after,
};
use crate::ai::key::SecretKey;
use crate::tests::openrouter_stub::{Canned, LISTING, Stub, ZDR_LISTING};
use std::collections::HashSet;
use std::time::Duration;

fn key() -> SecretKey {
    SecretKey::from_ui("sk-or-v1-fake-client-test-key-zxqw").expect("a key-shaped value")
}

#[tokio::test]
async fn retry_classification_covers_every_documented_status() {
    let retry = |rate_limited| Class::Retry {
        after: None,
        rate_limited,
    };
    let in_flight = br#"{"error":{"code":402,"message":"busy",
        "metadata":{"limit_source":"openrouter_in_flight_budget"}}}"#;
    let credit = br#"{"error":{"code":402,"message":"Insufficient credits",
        "metadata":{"limit_source":"key"}}}"#;
    let cases: [(u16, &[u8], Class); 17] = [
        (301, b"", Class::Redirected),
        (307, b"", Class::Redirected),
        (308, b"", Class::Redirected),
        (400, b"", Class::Drop),
        (401, b"", Class::KeyRefused),
        (402, in_flight, retry(true)),
        (402, credit, Class::OutOfCredit),
        (403, b"", Class::KeyRefused),
        (404, b"", Class::ModelRefused),
        (413, b"", Class::Drop),
        (429, b"", retry(true)),
        (500, b"", retry(false)),
        (502, b"", retry(false)),
        (503, b"", retry(false)),
        (524, b"", retry(false)),
        (529, b"", retry(false)),
        (418, b"not json at all", Class::Drop),
    ];
    for (status, body, expected) in cases {
        let failure = classify(status, body, None);
        assert_eq!(failure.class, expected, "status {status}");
        assert_eq!(failure.status, Some(status));
    }

    // Only what the WARN line may carry is kept: the status, `error.code` and an identifier-like
    // `limit_source`. Free text in that field is not an identifier and is dropped.
    let failure = classify(402, credit, None);
    assert_eq!(failure.code, Some(402));
    assert_eq!(failure.limit_source.as_deref(), Some("key"));
    let chatty = br#"{"error":{"metadata":{"limit_source":"see https://x.example for help"}}}"#;
    assert_eq!(classify(402, chatty, None).limit_source, None);

    // A timeout: a listener that accepts and never answers, and a client that gives up first.
    let hung = Stub::serve(vec![("", Canned::json(200, "{}").held())]);
    let impatient = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .no_proxy()
        .build()
        .expect("a test client");
    let failure = client::decide(&impatient, &hung.base, &key(), b"{}".to_vec())
        .await
        .expect_err("the request times out");
    assert_eq!(failure.class, retry(false));
    assert_eq!(failure.status, None, "no response, so no status");

    // A connect error, to a closed port.
    let closed: url::Url = "http://127.0.0.1:1".parse().expect("a loopback url");
    let ours = client::build(&closed, None).expect("the client builds");
    let failure = client::decide(&ours, &closed, &key(), b"{}".to_vec())
        .await
        .expect_err("nothing listens there");
    assert_eq!(failure.class, retry(false));
}

#[test]
fn retry_after_is_honoured_and_capped() {
    assert_eq!(retry_after("7"), Some(Duration::from_secs(7)));
    assert_eq!(retry_after(" 3 "), Some(Duration::from_secs(3)));
    assert_eq!(retry_after("0"), Some(Duration::ZERO));
    assert_eq!(retry_after("600"), Some(Duration::from_secs(60)), "capped");
    assert_eq!(retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
    assert_eq!(retry_after("-1"), None);
    assert_eq!(retry_after("1.5"), None);

    let failure = classify(429, b"", Some("12"));
    assert_eq!(
        failure.class,
        Class::Retry {
            after: Some(Duration::from_secs(12)),
            rate_limited: true,
        }
    );
    let failure = classify(503, b"", Some("3600"));
    assert_eq!(
        failure.class,
        Class::Retry {
            after: Some(Duration::from_secs(60)),
            rate_limited: false,
        }
    );
}

#[test]
fn backoff_is_capped_with_jitter() {
    // 1, 2, 4 and 8 s, each within ±25%.
    for (attempt, base_ms) in [(0, 1_000u64), (1, 2_000), (2, 4_000), (3, 8_000)] {
        for salt in 0..200 {
            let wait = backoff(attempt, salt).as_millis();
            let (low, high) = (u128::from(base_ms * 3 / 4), u128::from(base_ms * 5 / 4));
            assert!(
                (low..=high).contains(&wait),
                "attempt {attempt}: {wait} ms outside {low}..={high}"
            );
        }
    }
    // Past 30 s the cap holds, however large the attempt.
    for attempt in [5, 6, 16, 40, u32::MAX] {
        assert!(backoff(attempt, 1) <= BACKOFF_CAP, "attempt {attempt}");
    }
    // Jittered: two jobs failing together do not retry together.
    let spread: HashSet<u128> = (0..64).map(|salt| backoff(2, salt).as_millis()).collect();
    assert!(spread.len() > 8, "no jitter: {spread:?}");
}

#[tokio::test]
async fn the_client_follows_no_redirect() {
    let elsewhere = Stub::serve(vec![("", Canned::json(200, "{}"))]);
    let location = format!("{}api/alpha/decisions", elsewhere.base);
    let openrouter = Stub::serve(vec![
        ("", Canned::json(307, "").header("Location", &location)),
        ("", Canned::json(308, "").header("Location", &location)),
    ]);
    let ours = client::build(&openrouter.base, None).expect("the client builds");

    let failure = client::decide(&ours, &openrouter.base, &key(), b"{\"x\":1}".to_vec())
        .await
        .expect_err("a redirect is a failure, not something to follow");
    assert_eq!(failure.class, Class::Redirected);
    assert_eq!(failure.status, Some(307));
    // The key check refuses one the same way.
    assert_eq!(
        client::key_info(&ours, &openrouter.base, &key()).await,
        Err(KeyCheck::Unchecked)
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(openrouter.requests().len(), 2);
    assert!(
        elsewhere.requests().is_empty(),
        "the names and the key went to the redirect's target"
    );
}

#[tokio::test]
async fn a_loopback_base_bypasses_the_proxy_variables() {
    // What HTTPS_PROXY would do, without touching the process environment: a proxy on a port
    // nothing listens on.
    let proxy = || reqwest::Proxy::all("http://127.0.0.1:1").expect("a proxy url");

    // A client that does use it cannot reach the stub at all, so the test is not vacuous.
    let stub = Stub::serve(vec![("", Canned::json(200, r#"{"answers":{}}"#))]);
    let proxied = reqwest::Client::builder()
        .proxy(proxy())
        .build()
        .expect("a proxied client");
    let failure = client::decide(&proxied, &stub.base, &key(), b"{}".to_vec())
        .await
        .expect_err("the closed proxy refuses the connection");
    assert_eq!(failure.status, None);

    // AI review's own client, for a loopback base, goes straight to it.
    let ours = client::build(&stub.base, Some(proxy())).expect("the client builds");
    let answer = client::decide(&ours, &stub.base, &key(), b"{}".to_vec())
        .await
        .expect("the stub answers directly");
    assert!(matches!(answer, Answer::Body(body) if body == br#"{"answers":{}}"#));

    // A non-loopback base is HTTPS-only: plain http to it is refused before anything is sent.
    let remote: url::Url = "http://openrouter.example".parse().expect("a url");
    let ours = client::build(&remote, None).expect("the client builds");
    let failure = client::decide(&ours, &remote, &key(), b"{}".to_vec())
        .await
        .expect_err("https only");
    assert_eq!(failure.status, None);
}

#[tokio::test]
async fn a_decision_request_carries_the_key_only_in_its_header() {
    let stub = Stub::serve(vec![("", Canned::json(200, r#"{"answers":{}}"#))]);
    let ours = client::build(&stub.base, None).expect("the client builds");
    client::decide(&ours, &stub.base, &key(), br#"{"model":"m"}"#.to_vec())
        .await
        .expect("answered");
    let sent = stub.requests();
    let [request] = sent.as_slice() else {
        unreachable!("one request, got {}", sent.len())
    };
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/api/alpha/decisions");
    assert_eq!(
        request.header("authorization"),
        Some("Bearer sk-or-v1-fake-client-test-key-zxqw")
    );
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert!(
        request
            .header("user-agent")
            .is_some_and(|agent| agent.starts_with("cogwheel-dns/"))
    );
    assert_eq!(request.body, br#"{"model":"m"}"#);
}

#[tokio::test]
async fn an_oversized_answer_is_unreadable() {
    let huge = format!(r#"{{"pad":"{}"}}"#, "x".repeat(client::BODY_CAP));
    let stub = Stub::serve(vec![("", Canned::json(200, huge))]);
    let ours = client::build(&stub.base, None).expect("the client builds");
    let answer = client::decide(&ours, &stub.base, &key(), b"{}".to_vec())
        .await
        .expect("a 200 is a reply, however large");
    assert!(matches!(answer, Answer::Unreadable));
}

/// The cap holds for a body with no `Content-Length` to refuse it by, counted as it streams in;
/// and a body that breaks off part-way is unreadable, not a short answer.
#[tokio::test]
async fn a_streamed_answer_is_capped_and_a_broken_one_is_unreadable() {
    let decide = |stub: Stub| async move {
        let ours = client::build(&stub.base, None).expect("the client builds");
        client::decide(&ours, &stub.base, &key(), b"{}".to_vec())
            .await
            .expect("a 200 is a reply, however it reads")
    };
    let huge = "x".repeat(client::BODY_CAP + 1);
    let answer = decide(Stub::serve(vec![("", Canned::json(200, huge).chunked())])).await;
    assert!(matches!(answer, Answer::Unreadable));

    let small = r#"{"answers":{}}"#;
    let answer = decide(Stub::serve(vec![("", Canned::json(200, small).chunked())])).await;
    assert!(
        matches!(answer, Answer::Body(body) if body == small.as_bytes()),
        "chunked is read whole"
    );
    let answer = decide(Stub::serve(vec![(
        "",
        Canned::json(200, small).truncated(),
    )]))
    .await;
    assert!(matches!(answer, Answer::Unreadable));
}

#[test]
fn key_info_reads_only_the_limits() {
    let body = br#"{"data":{"label":"sk-or-v1-abc...123","name":"Cogwheel","limit":5,
        "usage":0.88,"limit_remaining":4.12,"is_free_tier":false,"rate_limit":{"requests":10}}}"#;
    let info = parse_key_info(body).expect("a readable key body");
    assert_eq!(info.limit, Some(5.0));
    assert_eq!(info.limit_remaining, Some(4.12));
    let printed = format!("{info:?}");
    for absent in ["label", "sk-or", "abc", "usage", "Cogwheel", "free"] {
        assert!(!printed.contains(absent), "{absent:?} in {printed}");
    }

    // No per-key limit is `null`; a missing `data` is unreadable.
    let info = parse_key_info(br#"{"data":{"limit":null,"limit_remaining":null}}"#)
        .expect("nulls are readable");
    assert_eq!((info.limit, info.limit_remaining), (None, None));
    assert_eq!(parse_key_info(br#"{"label":"sk-or-v1-x"}"#), None);
    assert_eq!(parse_key_info(b"<html>"), None);
}

#[tokio::test]
async fn the_key_check_maps_every_status() {
    let cases = [
        (401, Err(KeyCheck::Refused)),
        (403, Err(KeyCheck::Refused)),
        (402, Err(KeyCheck::NoCredit)),
        (404, Err(KeyCheck::Unchecked)),
        (400, Err(KeyCheck::Unchecked)),
        (307, Err(KeyCheck::Unchecked)),
        (429, Err(KeyCheck::RateLimited)),
        (500, Err(KeyCheck::Unreachable)),
        (503, Err(KeyCheck::Unreachable)),
    ];
    for (status, expected) in cases {
        let stub = Stub::serve(vec![("", Canned::json(status, "{}"))]);
        let ours = client::build(&stub.base, None).expect("the client builds");
        assert_eq!(
            client::key_info(&ours, &stub.base, &key()).await,
            expected,
            "status {status}"
        );
        let sent = stub.requests();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].target, "/api/v1/key");
    }
    // An unreadable 200, and nothing listening.
    let stub = Stub::serve(vec![("", Canned::json(200, "not json"))]);
    let ours = client::build(&stub.base, None).expect("the client builds");
    assert_eq!(
        client::key_info(&ours, &stub.base, &key()).await,
        Err(KeyCheck::Unchecked)
    );
    let closed: url::Url = "http://127.0.0.1:1".parse().expect("a loopback url");
    let ours = client::build(&closed, None).expect("the client builds");
    assert_eq!(
        client::key_info(&ours, &closed, &key()).await,
        Err(KeyCheck::Unreachable)
    );
}

#[tokio::test]
async fn the_model_listings_merge_by_price_and_zero_retention() {
    let all = r#"{"data":[
        {"id":"cloudflare/clef","name":"Cloudflare: Clef","description":"27B","context_length":65000,
         "pricing":{"prompt":"0.00000024","completion":"0"}},
        {"id":"typesafe/jev-1.13","name":"TypeSafe: Jev 1.13","description":"Jev","context_length":32000,
         "pricing":{"prompt":"0.000000042"}},
        {"id":"respan/span-01","name":"Span","pricing":{"prompt":"-1"}}]}"#;
    let zero_retention = r#"{"data":[{"id":"typesafe/jev-1.13"},{"id":"cloudflare/clef"}]}"#;
    let stub = Stub::serve(vec![
        (ZDR_LISTING, Canned::json(200, zero_retention)),
        (LISTING, Canned::json(200, all)),
    ]);
    let ours = client::build(&stub.base, None).expect("the client builds");
    let list = client::models(&ours, &stub.base, 1_791_400_000)
        .await
        .expect("both listings read");

    let ids: Vec<&str> = list.models.iter().map(|model| model.id.as_str()).collect();
    assert_eq!(
        ids,
        ["typesafe/jev-1.13", "cloudflare/clef", "respan/span-01"],
        "cheapest first, an unknown price last"
    );
    let jev = list.get("typesafe/jev-1.13").expect("listed");
    assert_eq!(jev.prompt_usd_per_million, Some(0.042));
    assert_eq!(jev.zero_retention, Some(true));
    assert_eq!(jev.name, "TypeSafe: Jev 1.13");
    let span = list.get("respan/span-01").expect("listed");
    assert_eq!(span.prompt_usd_per_million, None, "-1 is not a price");
    assert_eq!(span.zero_retention, Some(false));
    assert_eq!(span.name, "Span");

    let sent = stub.requests();
    assert_eq!(
        sent.iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        [
            "/api/v1/models?output_modalities=decisions",
            "/api/v1/models?output_modalities=decisions&zdr=true"
        ]
    );
    assert!(
        sent.iter()
            .all(|request| request.header("authorization").is_none()),
        "the listings are public: no key goes with them"
    );

    // Only the zero-retention listing fails: every model's mark is unknown, not false.
    let stub = Stub::serve(vec![
        (ZDR_LISTING, Canned::json(500, "")),
        (LISTING, Canned::json(200, all)),
    ]);
    let ours = client::build(&stub.base, None).expect("the client builds");
    let list = client::models(&ours, &stub.base, 0)
        .await
        .expect("the main listing read");
    assert!(
        list.models
            .iter()
            .all(|model| model.zero_retention.is_none())
    );

    // The main one fails: no list.
    let stub = Stub::serve(vec![("", Canned::json(503, ""))]);
    let ours = client::build(&stub.base, None).expect("the client builds");
    assert!(client::models(&ours, &stub.base, 0).await.is_none());
}
