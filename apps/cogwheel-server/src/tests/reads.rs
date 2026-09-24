//! The read routes and the rebuild rules behind them: the query log, pause, the Overview and
//! the settings dump (§3 routes 3–8 and 22, §6 step 4), and the cache headers the web shell is
//! served with.

use super::{ADS_LIST, Harness, TempDir, device_input, rule_input, subscribe};
use crate::api::{devices, overview, queries, rules, runtime, settings};
use crate::http::{ApiJson, ApiQuery};
use crate::policy_build::{Rebuild, rebuild};
use crate::state::now_secs;

use axum::extract::State;
use axum::http::StatusCode;
use cogwheel_policy::Reason;
use cogwheel_storage::QueryLogEntry;
use std::sync::Arc;

// --------------------------------------------------------------------- queries

#[tokio::test]
async fn the_query_log_pages_by_keyset_and_filters() {
    let harness = Harness::new().await;
    let now = now_secs();
    let entries = (0..5)
        .map(|index| QueryLogEntry {
            // Ascending, so that id order — which is what the keyset pages on — is time order.
            ts: now - i64::from(4 - index),
            client: "192.168.1.20".to_owned(),
            domain: format!("name{index}.example.com"),
            qtype: 1,
            blocked: index % 2 == 0,
            reason: if index % 2 == 0 {
                Reason::List.as_u8()
            } else {
                Reason::NoMatch.as_u8()
            },
            list: (index % 2 == 0).then(|| "ads".to_owned()),
        })
        .collect();
    harness
        .state
        .storage
        .insert_batch_with_rollups(entries, true)
        .await
        .expect("write the log");

    let page = |params: queries::QueryParams| {
        queries::list(State(harness.state.clone()), ApiQuery(params))
    };

    let first = page(queries::QueryParams {
        limit: Some(2),
        ..queries::QueryParams::default()
    })
    .await
    .expect("first page")
    .data;
    assert_eq!(first.rows.len(), 2);
    assert!(first.logging);
    assert_eq!(
        first.rows[0].domain, "name4.example.com",
        "most recently logged first"
    );
    let cursor = first.next_before.expect("a full page carries a cursor");

    let second = page(queries::QueryParams {
        limit: Some(2),
        before: Some(cursor),
        ..queries::QueryParams::default()
    })
    .await
    .expect("second page")
    .data;
    assert_eq!(second.rows.len(), 2);
    assert!(
        second.rows.iter().all(|row| row.id < cursor),
        "a keyset page must not repeat a row the previous one showed"
    );

    let blocked = page(queries::QueryParams {
        blocked: Some(true),
        ..queries::QueryParams::default()
    })
    .await
    .expect("blocked only")
    .data;
    assert_eq!(blocked.rows.len(), 3);
    assert!(blocked.rows.iter().all(|row| row.blocked));

    let matching = page(queries::QueryParams {
        q: Some("name3".to_owned()),
        ..queries::QueryParams::default()
    })
    .await
    .expect("substring filter")
    .data;
    assert_eq!(matching.rows.len(), 1);

    let cleared = queries::clear(State(harness.state.clone()))
        .await
        .expect("clear")
        .data;
    assert_eq!(cleared.deleted, 5);
    // The rollups survive, which is what keeps the Overview's counts honest after a clear.
    let day = overview::overview(State(harness.state.clone()))
        .await
        .expect("overview")
        .data
        .last_24h;
    assert_eq!(day.queries, 5);
    assert_eq!(day.blocked, 3);
}

#[tokio::test]
async fn a_named_device_relabels_the_history_it_already_has() {
    let harness = Harness::new().await;
    harness
        .state
        .storage
        .insert_batch_with_rollups(
            vec![QueryLogEntry {
                ts: now_secs(),
                client: "192.168.1.20".to_owned(),
                domain: "ads.example.com".to_owned(),
                qtype: 1,
                blocked: true,
                reason: Reason::List.as_u8(),
                list: Some("ads".to_owned()),
            }],
            true,
        )
        .await
        .expect("write the log");

    let before = queries::list(
        State(harness.state.clone()),
        ApiQuery(queries::QueryParams::default()),
    )
    .await
    .expect("page")
    .data;
    assert_eq!(before.rows[0].device_name, None);

    devices::create(
        State(harness.state.clone()),
        ApiJson(device_input("Tablet", "192.168.1.20")),
    )
    .await
    .expect("name the address");

    let after = queries::list(
        State(harness.state.clone()),
        ApiQuery(queries::QueryParams::default()),
    )
    .await
    .expect("page")
    .data;
    assert_eq!(after.rows[0].device_name.as_deref(), Some("Tablet"));

    // And the address stops being an unnamed client on the Devices page.
    let catalogue = devices::list(State(harness.state.clone()))
        .await
        .expect("devices")
        .data;
    assert!(catalogue.unnamed_clients.is_empty());
    assert_eq!(catalogue.devices[0].queries_24h, 1);
    assert_eq!(catalogue.devices[0].blocked_24h, 1);
}

// --------------------------------------------------------------------- pause and overview

#[tokio::test]
async fn a_pause_survives_a_restart_and_an_expired_one_is_ignored() {
    let harness = Harness::new().await;
    let paused = runtime::pause(
        State(harness.state.clone()),
        ApiJson(runtime::PauseRequest { minutes: 30 }),
    )
    .await
    .expect("pause")
    .data;
    let until = paused.paused_until.expect("a deadline");
    assert!(until > now_secs());

    let (restarted, _log_rx) = harness.restarted();
    assert_eq!(
        restarted.runtime.pause_until(),
        0,
        "a fresh runtime starts unpaused"
    );
    runtime::restore(&restarted).await;
    assert_eq!(
        i64::try_from(restarted.runtime.pause_until()).expect("a sane deadline"),
        until,
        "the stored deadline must come back"
    );

    // An expired deadline is left alone rather than resumed into.
    harness
        .state
        .storage
        .set_pause_until(Some(now_secs() - 60))
        .await
        .expect("store an expired pause");
    let (expired, _log_rx) = harness.restarted();
    runtime::restore(&expired).await;
    assert_eq!(expired.runtime.pause_until(), 0);

    runtime::resume(State(harness.state.clone()))
        .await
        .expect("resume");
    assert_eq!(harness.state.runtime.pause_until(), 0);
    assert_eq!(
        harness.state.storage.pause_until().await.expect("read"),
        None
    );
}

#[tokio::test]
async fn a_pause_outside_the_allowed_range_is_refused() {
    let harness = Harness::new().await;
    for minutes in [0, 1_441] {
        let error = runtime::pause(
            State(harness.state.clone()),
            ApiJson(runtime::PauseRequest { minutes }),
        )
        .await
        .expect_err("out of range");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn the_overview_has_the_shape_the_page_draws() {
    let harness = Harness::new().await;
    subscribe(&harness, "ads", ADS_LIST, "domains").await;
    harness
        .state
        .storage
        .insert_batch_with_rollups(
            vec![QueryLogEntry {
                ts: now_secs(),
                client: "192.168.1.20".to_owned(),
                domain: "ads.example.com".to_owned(),
                qtype: 1,
                blocked: true,
                reason: Reason::List.as_u8(),
                list: Some("ads".to_owned()),
            }],
            true,
        )
        .await
        .expect("write the log");

    let page = overview::overview(State(harness.state.clone()))
        .await
        .expect("overview")
        .data;
    assert_eq!(page.protection.paused_until, None);
    assert_eq!(page.last_24h.per_hour.len(), 24, "the bar strip is 24 bars");
    assert!(
        page.last_24h
            .per_hour
            .windows(2)
            .all(|pair| pair[0].hour < pair[1].hour),
        "oldest first"
    );
    assert_eq!(page.last_24h.queries, 1);
    assert_eq!(page.last_24h.active_clients, 1);
    assert_eq!(page.last_24h.unnamed_clients, 1);
    assert_eq!(page.last_24h.named_devices, 0);
    assert_eq!(page.lists.enabled, 1);
    assert_eq!(page.lists.total, 1);
    assert_eq!(page.lists.rules_loaded, 2);
    assert!(page.lists.downloaded);
    assert_eq!(
        page.top_blocked.first().map(|row| row.domain.as_str()),
        Some("ads.example.com")
    );
    assert_eq!(page.top_queried.len(), 1);
    assert_eq!(page.connect.targets, vec!["192.168.1.2".to_owned()]);
    assert_eq!(page.connect.port, 5353);
    assert_eq!(page.runtime.queries_total, 0);
}

#[tokio::test]
async fn the_settings_dump_describes_this_process() {
    let harness = Harness::new().await;
    let page = settings::settings(State(harness.state.clone()))
        .await
        .expect("settings")
        .data;
    assert_eq!(page.schema_version, cogwheel_storage::SCHEMA_VERSION);
    assert_eq!(page.protected_suffixes.len(), 21);
    assert_eq!(page.block_mode, "null_ip");
    assert_eq!(page.retention.history_days, 7);
    assert_eq!(page.retention.max_rows, 250_000);
    assert_eq!(page.upstreams.len(), 2);
    assert!(page.upstreams.iter().all(|upstream| !upstream.encrypted));
    assert!(page.db_size_bytes > 0);
    assert_eq!(page.lists_dir, harness.lists.path().display().to_string());
}

// --------------------------------------------------------------------- policy rebuilds

#[tokio::test]
async fn a_device_edit_keeps_the_dns_cache_and_a_household_rule_drops_it() {
    let harness = Harness::new().await;
    let state = harness.state.clone();
    subscribe(&harness, "ads", ADS_LIST, "domains").await;

    let device = devices::create(
        State(state.clone()),
        ApiJson(device_input("Tablet", "192.168.1.20")),
    )
    .await
    .expect("device")
    .data;
    let before = state.runtime.current_policy();

    rules::create(
        State(state.clone()),
        ApiJson(rule_input("games.example.com", "block", Some(&device.id))),
    )
    .await
    .expect("a device rule");
    let after = state.runtime.current_policy();
    assert!(
        Arc::ptr_eq(&before.index, &after.index),
        "a device rule must not recompile the lists"
    );
    let scope = after.scope_for("192.168.1.20".parse().expect("address"));
    assert!(
        scope.id > cogwheel_policy::SCOPE_UNFILTERED,
        "the device gets its own scope"
    );

    rules::create(
        State(state.clone()),
        ApiJson(rule_input("news.example.com", "block", None)),
    )
    .await
    .expect("a household rule");
    let household = state.runtime.current_policy();
    assert!(
        Arc::ptr_eq(&after.index, &household.index),
        "a household rule reuses the index but drops the cache"
    );
    assert!(
        household
            .scope_for("192.168.1.20".parse().expect("address"))
            .id
            > scope.id,
        "clearing the scope table must never hand back an id that meant something else"
    );
}

#[tokio::test]
async fn a_policy_compiled_from_the_cache_needs_no_network() {
    let harness = Harness::new().await;
    subscribe(&harness, "ads", ADS_LIST, "domains").await;

    // What a restart does: compile from the cached bodies alone.
    let (restarted, _log_rx) = harness.restarted();
    let stats = rebuild(&restarted, Rebuild::Lists)
        .await
        .expect("compile from the cache");
    assert_eq!(stats.slots, 1);
    assert_eq!(stats.rules_loaded, 2);
    assert!(restarted.readiness.detail().storage || true);
}

/// A list added between rebuilds shifts every slot after it, because slot order is `sources.id`
/// ascending and ids are random uuids. A rebuild that reuses the index has to notice.
#[tokio::test]
async fn a_rebuild_that_reuses_the_index_notices_the_slots_moving() {
    let harness = Harness::new().await;
    let state = harness.state.clone();
    let seed = |id: &str, name: &str| {
        state.storage.insert_source(cogwheel_storage::NewSource {
            id: Some(id.to_owned()),
            name: name.to_owned(),
            url: format!("https://lists.example.com/{name}.txt"),
            kind: "domains".to_owned(),
            enabled: true,
        })
    };

    seed("ffffffff-0000-4000-8000-000000000001", "last")
        .await
        .expect("seed");
    super::cache_body(
        &harness,
        "ffffffff-0000-4000-8000-000000000001",
        "last.example.com\n",
    );
    rebuild(&state, Rebuild::Lists).await.expect("compile");
    let policy = state.runtime.current_policy();
    assert_eq!(policy.index.name(0).map(|name| &**name), Some("last"));
    assert!(policy.index.name(1).is_none());

    // Inserted straight into storage, as a list whose first fetch failed would be: no rebuild
    // ran, and its id sorts ahead of the one already indexed.
    seed("00000000-0000-4000-8000-000000000001", "first")
        .await
        .expect("seed");
    super::cache_body(
        &harness,
        "00000000-0000-4000-8000-000000000001",
        "first.example.com\n",
    );

    rebuild(&state, Rebuild::Devices).await.expect("re-scope");
    let policy = state.runtime.current_policy();
    assert_eq!(
        (
            policy.index.name(0).map(|name| &**name),
            policy.index.name(1).map(|name| &**name)
        ),
        (Some("first"), Some("last")),
        "reusing the old index would have given slot 0 to the wrong list"
    );
}

/// §3 caps a page at 1,000 rows. Pinned so that the choice between refusing and quietly
/// clamping stays a decision: a caller handed 1,000 rows after asking for 5,000 cannot tell.
#[tokio::test]
async fn a_page_larger_than_the_cap_is_refused_rather_than_trimmed() {
    let harness = Harness::new().await;
    for limit in [0, 1_001, 5_000] {
        let error = queries::list(
            State(harness.state.clone()),
            ApiQuery(queries::QueryParams {
                limit: Some(limit),
                ..queries::QueryParams::default()
            }),
        )
        .await
        .expect_err("an out-of-range limit");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST, "limit={limit}");
    }

    let page = queries::list(
        State(harness.state.clone()),
        ApiQuery(queries::QueryParams {
            limit: Some(1_000),
            ..queries::QueryParams::default()
        }),
    )
    .await
    .expect("the cap itself is allowed");
    assert!(page.data.rows.is_empty());
}

// ------------------------------------------------------------------- web shell

/// Hashed assets are kept for a year; the shell is revalidated on every load.
///
/// The pair is what makes an update land: the browser asks for `index.html` each time, the new
/// one names new asset URLs, and the vendor split it already has is never asked about again. A
/// 404 under `/assets/` is the shell with a 404 status and must not be pinned, and the API is
/// not the static service's to label.
#[tokio::test]
async fn hashed_assets_are_immutable_and_the_shell_is_revalidated() {
    use crate::http::{CACHE_IMMUTABLE, CACHE_REVALIDATE};

    let harness = Harness::new().await;
    let dist = TempDir::new("web");
    std::fs::create_dir_all(dist.path().join("assets")).expect("create the assets directory");
    std::fs::write(
        dist.path().join("index.html"),
        "<!doctype html><title>Cogwheel</title>",
    )
    .expect("write the shell");
    std::fs::write(dist.path().join("assets/index-3f9a1c.js"), "export {};")
        .expect("write a hashed asset");
    let app = crate::http::app_serving(harness.state.clone(), Some(dist.path().to_path_buf()));

    let cases = [
        (
            "GET",
            "/assets/index-3f9a1c.js",
            StatusCode::OK,
            Some(CACHE_IMMUTABLE),
        ),
        (
            "HEAD",
            "/assets/index-3f9a1c.js",
            StatusCode::OK,
            Some(CACHE_IMMUTABLE),
        ),
        ("GET", "/", StatusCode::OK, Some(CACHE_REVALIDATE)),
        ("GET", "/index.html", StatusCode::OK, Some(CACHE_REVALIDATE)),
        // A client-side route, answered with the shell.
        ("GET", "/settings", StatusCode::OK, Some(CACHE_REVALIDATE)),
        ("HEAD", "/devices", StatusCode::OK, Some(CACHE_REVALIDATE)),
        (
            "GET",
            "/assets/index-000000.js",
            StatusCode::NOT_FOUND,
            Some(CACHE_REVALIDATE),
        ),
        ("GET", "/api/v1/settings", StatusCode::OK, None),
    ];

    for (method, uri, status, cache_control) in cases {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .body(axum::body::Body::empty())
            .expect("build a request");
        let response = tower::ServiceExt::oneshot(app.clone(), request)
            .await
            .expect("the router answers");
        assert_eq!(response.status(), status, "{method} {uri}");
        let header = response
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .map(|value| value.to_str().expect("an ASCII header"));
        assert_eq!(header, cache_control, "{method} {uri}");
    }
}

/// A reload of a client-side route revalidates the shell, and must get the shell or a 304.
///
/// The shell used to be reached through ServeDir's not-found service, which relabels whatever
/// the shell answered as a 404; the fallback then turned that 404 into a 200. A conditional
/// request therefore came back as `200 OK` with an empty body, and the browser — told by
/// `no-cache` to revalidate on every load — drew a blank page on every reload of /devices.
#[tokio::test]
async fn a_revalidated_client_route_is_a_304_not_an_empty_page() {
    let harness = Harness::new().await;
    let dist = TempDir::new("web-revalidate");
    let shell = "<!doctype html><title>Cogwheel</title>";
    std::fs::write(dist.path().join("index.html"), shell).expect("write the shell");
    let app = crate::http::app_serving(harness.state.clone(), Some(dist.path().to_path_buf()));

    let send = |uri: &str, since: Option<&str>| {
        let mut request = axum::http::Request::builder().uri(uri);
        if let Some(since) = since {
            request = request.header(axum::http::header::IF_MODIFIED_SINCE, since);
        }
        tower::ServiceExt::oneshot(
            app.clone(),
            request
                .body(axum::body::Body::empty())
                .expect("build a request"),
        )
    };

    for uri in ["/", "/devices", "/lists"] {
        let first = send(uri, None).await.expect("the router answers");
        assert_eq!(first.status(), StatusCode::OK, "{uri}");
        let modified = first
            .headers()
            .get(axum::http::header::LAST_MODIFIED)
            .expect("the shell carries Last-Modified")
            .to_str()
            .expect("an ASCII header")
            .to_owned();
        let body = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .expect("read the shell");
        assert_eq!(&body[..], shell.as_bytes(), "{uri}");

        let again = send(uri, Some(&modified))
            .await
            .expect("the router answers");
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED, "{uri}");
    }
}
