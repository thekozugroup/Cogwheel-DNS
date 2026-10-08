//! What AI review never touches (§14): DNS answers and readiness while OpenRouter hangs, the
//! logs, and the query-log writer, which offers to the tap without ever waiting on it.

use super::{WEBSITE, answer, device, names, noon, rig};
use crate::ai::{Cost, State, TAP_DEPTH};
use crate::policy_build::{Rebuild, rebuild};
use crate::state::{ServerState, now_secs};
use crate::tests::Harness;
use crate::tests::openrouter_stub::{
    CONSENT, Canned, DECISIONS, JEV, call, capture, keyed, parsed, realistic_key, windows,
};
use axum::http::StatusCode;
use cogwheel_dns_core::{DnsRuntimeConfig, LogEntry};
use cogwheel_policy::{Reason, Verdict};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

// --------------------------------------------------------------------- DNS never waits

/// A DNS query for a hand-built A question.
fn query(id: u16, name: &str) -> Vec<u8> {
    let mut packet = id.to_be_bytes().to_vec();
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        packet.push(u8::try_from(label.len()).expect("a short label"));
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

/// A loopback port free for both UDP and TCP, a moment ago.
fn free_port() -> SocketAddr {
    for _ in 0..20 {
        let Ok(udp) = std::net::UdpSocket::bind("127.0.0.1:0") else {
            continue;
        };
        let Ok(address) = udp.local_addr() else {
            continue;
        };
        if std::net::TcpListener::bind(address).is_ok() {
            return address;
        }
    }
    unreachable!("no free loopback port")
}

/// With a request to OpenRouter hanging, DNS still answers from the policy (the AI list
/// included) and the appliance reports ready: the model is never on the DNS path.
#[tokio::test]
async fn dns_and_readiness_ignore_an_unreachable_openrouter() {
    let hanging = answer("block", 0.95, 0.00002).held();
    let mut rig = rig(vec![(DECISIONS, hanging)], &CONSENT).await;
    let state = rig.state().clone();
    state
        .ai
        .settle(
            &state.storage,
            Cost::default(),
            vec![crate::tests::ai::row(
                "ads.example.net",
                "block",
                0.95,
                now_secs(),
            )],
        )
        .await
        .expect("committed");
    rebuild(&state, Rebuild::Ai).await.expect("installed");

    let address = free_port();
    let (stop, shutdown) = watch::channel(false);
    state.readiness.mark_storage_ready();
    state.readiness.mark_policy_ready();
    let readiness = Arc::clone(&state.readiness);
    let dns = tokio::spawn(Arc::clone(&state.runtime).serve_with_ready_signal(
        DnsRuntimeConfig {
            udp_bind_addr: address,
            tcp_bind_addr: address,
        },
        move || readiness.mark_dns_ready(),
        shutdown,
    ));
    for _ in 0..400 {
        if state.readiness.is_ready() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let t = noon();
    rig.visit(t, &names(0..2));
    assert!(rig.start(t + 10));
    assert!(
        rig.stub.wait_for(1).await,
        "a request is hanging at OpenRouter"
    );

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a client socket");
    socket
        .send_to(&query(0x2b2b, "ads.example.net"), address)
        .await
        .expect("send");
    let mut buffer = [0u8; 512];
    let (size, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .expect("answered while OpenRouter hangs")
        .expect("received");
    let reply = &buffer[..size];
    assert_eq!(reply[..2], [0x2b, 0x2b]);
    assert_eq!(reply[3] & 0x0f, 0, "NOERROR");
    assert!(
        reply.ends_with(&[0, 0, 0, 0]),
        "the AI list's block, as 0.0.0.0: {reply:?}"
    );

    let (status, _) = call(&state, "GET", "/health/ready", None).await;
    assert_eq!(status, StatusCode::OK);
    let (_, text) = call(&state, "GET", "/api/v1/overview", None).await;
    let overview = parsed(&text)["data"]["ai"].clone();
    assert_eq!(
        overview,
        json!({"state": "reviewing", "applying": true, "applied_block": 1, "applied_allow": 0})
    );

    rig.stub.release();
    rig.settle(t + 11).await;
    let _ = stop.send(true);
    if tokio::time::timeout(Duration::from_secs(5), dns)
        .await
        .is_err()
    {
        unreachable!("the DNS listeners did not stop");
    }
}

// --------------------------------------------------------------------- logs

/// §6.16: the reviewer, its client, its installs and its prune log counts, states and statuses;
/// never a name it judged, a website, a name sent with one, or any part of the key.
#[tokio::test]
async fn the_reviewer_never_logs_a_domain_or_the_key() {
    let (logs, _subscriber) = capture();
    let script = vec![
        (DECISIONS, answer("block", 0.95, 0.00002)),
        (
            DECISIONS,
            Canned::json(429, "{}").header("Retry-After", "1"),
        ),
        (DECISIONS, answer("ignore", 0.6, 0.00002)),
        (
            DECISIONS,
            Canned::json(400, r#"{"error":{"code":400,"message":"t2.site2.com"}}"#),
        ),
        (DECISIONS, Canned::json(200, "not json")),
        (DECISIONS, Canned::json(401, "{}")),
    ];
    let mut rig = rig(script, &CONSENT).await;
    let t = noon();
    rig.visit(t, &names(0..8));
    rig.run(t + 10, t + 40).await;
    assert_eq!(
        rig.state().ai.state(),
        State::KeyRefused,
        "the script ran to its end"
    );
    rebuild(rig.state(), Rebuild::Ai).await.expect("an install");
    crate::prune::prune_ai_list(rig.state(), 1).await;

    let logged = logs.text();
    assert!(
        logged.contains("AI review stopped sending"),
        "the capture saw the reviewer"
    );
    for private in std::iter::once(WEBSITE.to_owned()).chain(names(0..8)) {
        assert!(!logged.contains(&private), "the log named {private}");
    }
    let key = rig
        .state()
        .ai
        .key()
        .map(|slot| slot.key.expose().to_owned())
        .unwrap_or_default();
    assert!(!key.is_empty());
    for window in windows(&key) {
        assert!(!logged.contains(window), "the log carried {window:?}");
    }
}

// --------------------------------------------------------------------- the tap

fn entry(domain: &str) -> LogEntry {
    LogEntry {
        ts: u32::try_from(now_secs()).expect("a timestamp that fits"),
        client: device(),
        domain: Arc::from(domain),
        qtype: 1,
        verdict: Verdict::allow(Reason::NoMatch),
        list: None,
    }
}

/// Run the query-log writer over `count` answered lookups and wait until it has written them all.
async fn write_log(state: &ServerState, count: usize) {
    let (log_tx, log_rx) = mpsc::channel(count + 1);
    let (stop, shutdown) = watch::channel(false);
    let writer = tokio::spawn(crate::querylog::writer(
        ServerState {
            shutdown,
            ..state.clone()
        },
        log_rx,
    ));
    for n in 0..count {
        log_tx
            .try_send(entry(&format!("n{n}.example.com")))
            .expect("room in the log channel");
    }
    // Everything received (and so offered to the tap) before the stop, which flushes the rest.
    for _ in 0..10_000 {
        if log_tx.capacity() == log_tx.max_capacity() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), writer)
        .await
        .expect("the writer never waits on the tap")
        .expect("the writer finished");
}

async fn logged(state: &ServerState) -> i64 {
    let buckets = state
        .storage
        .hourly_24h(now_secs())
        .await
        .expect("read the rollups");
    buckets.iter().map(|bucket| bucket.queries).sum()
}

#[tokio::test]
async fn a_full_tap_drops_and_counts_without_blocking_the_writer() {
    let mut harness = Harness::with_ai(keyed(&realistic_key()), &CONSENT).await;
    let tap = harness.take_tap();
    let state = harness.state.clone();
    let _alive = state.ai.reviewer_alive();
    assert!(state.ai.tap().is_some());

    // Nobody reads the tap: it fills, and the rest is dropped and counted.
    write_log(&state, TAP_DEPTH + 100).await;
    assert_eq!(tap.len(), TAP_DEPTH);
    assert_eq!(state.ai.counters.tap_dropped.load(Ordering::Relaxed), 100);
    assert_eq!(
        logged(&state).await,
        i64::try_from(TAP_DEPTH + 100).expect("fits"),
        "every lookup was still logged"
    );
}

#[tokio::test]
async fn nothing_is_tapped_while_ai_review_is_off() {
    let key = realistic_key();
    // Picked a model, never turned on.
    let mut harness = Harness::with_ai(keyed(&key), &[("ai_model", JEV)]).await;
    let mut tap = harness.take_tap();
    let state = harness.state.clone();
    let _alive = state.ai.reviewer_alive();
    assert!(state.ai.tap().is_none());
    write_log(&state, 50).await;
    assert!(tap.try_recv().is_err());

    // On, then off: the gate closes with the PUT, and nothing more is offered.
    let mut harness = Harness::with_ai(keyed(&key), &CONSENT).await;
    let mut tap = harness.take_tap();
    let state = harness.state.clone();
    let _alive = state.ai.reviewer_alive();
    assert!(state.ai.tap().is_some());
    let (status, _) = call(&state, "PUT", "/api/v1/ai", Some(r#"{"enabled":false}"#)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(state.ai.tap().is_none());
    write_log(&state, 50).await;
    assert!(tap.try_recv().is_err());
    assert_eq!(state.ai.counters.tap_dropped.load(Ordering::Relaxed), 0);
}
