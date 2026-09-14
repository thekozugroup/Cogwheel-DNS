//! The write routes: devices, rules and lists, plus the "why?" answer they feed (§3 routes
//! 9–21).
//!
//! Called directly rather than through a socket: the extractors are the handler's real signature,
//! and a test that goes through axum ends up asserting on axum's routing rather than on the
//! behaviour §3 specifies.

use super::{ADS_LIST, Harness, device_input, list_input, rule_input, subscribe, verdict};
use crate::api::{check, devices, lists, rules, runtime};
use crate::http::{ApiJson, ApiQuery};
use crate::policy_build::{Rebuild, rebuild};
use crate::refresh::Outcome;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use cogwheel_policy::Reason;
use cogwheel_storage::NewSource;

// --------------------------------------------------------------------- devices

#[tokio::test]
async fn a_device_can_be_named_renamed_and_forgotten() {
    let harness = Harness::new().await;
    let state = harness.state.clone();

    let created = devices::create(
        State(state.clone()),
        ApiJson(device_input("Kitchen tablet", "192.168.1.20")),
    )
    .await
    .expect("create")
    .data;
    assert_eq!(created.name, "Kitchen tablet");
    assert_eq!(created.queries_24h, 0);
    assert_eq!(created.last_seen_at, None);

    // The policy learns the address immediately, which is what makes the live stream attribute
    // the device's very next query.
    assert!(
        state
            .runtime
            .current_policy()
            .by_ip
            .contains_key(&"192.168.1.20".parse().expect("address")),
        "a new device must be in the policy before the response is sent"
    );

    let renamed = devices::update(
        State(state.clone()),
        Path(created.id.clone()),
        ApiJson(device_input("Hallway tablet", "192.168.1.21")),
    )
    .await
    .expect("update")
    .data;
    assert_eq!(renamed.id, created.id, "an edit keeps the device's id");
    assert_eq!(renamed.ip_address, "192.168.1.21");

    let catalogue = devices::list(State(state.clone()))
        .await
        .expect("list")
        .data;
    assert_eq!(catalogue.devices.len(), 1);
    assert!(catalogue.unnamed_clients.is_empty());

    assert!(
        devices::remove(State(state.clone()), Path(created.id.clone()))
            .await
            .expect("delete")
            .data
            .deleted
    );
    let missing = devices::remove(State(state), Path(created.id))
        .await
        .expect_err("deleting twice");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn two_devices_cannot_share_an_address() {
    let harness = Harness::new().await;
    devices::create(
        State(harness.state.clone()),
        ApiJson(device_input("Tablet", "192.168.1.20")),
    )
    .await
    .expect("first device");

    let conflict = devices::create(
        State(harness.state.clone()),
        ApiJson(device_input("Phone", "192.168.1.20")),
    )
    .await
    .expect_err("the same address twice");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_device_needs_a_name_and_an_address_that_parses() {
    let harness = Harness::new().await;
    for input in [
        device_input("  ", "192.168.1.20"),
        device_input("Tablet", "192.168.1.256"),
        device_input("Tablet", "kitchen-tablet.local"),
    ] {
        let error = devices::create(State(harness.state.clone()), ApiJson(input))
            .await
            .expect_err("bad device input");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn editing_a_device_that_does_not_exist_is_a_404() {
    let harness = Harness::new().await;
    let error = devices::update(
        State(harness.state.clone()),
        Path("00000000-0000-4000-8000-00000000dead".to_owned()),
        ApiJson(device_input("Ghost", "192.168.1.99")),
    )
    .await
    .expect_err("a PUT must not create a device");
    assert_eq!(error.status(), StatusCode::NOT_FOUND);
    assert!(
        devices::list(State(harness.state.clone()))
            .await
            .expect("list")
            .data
            .devices
            .is_empty()
    );
}

#[tokio::test]
async fn a_device_can_be_limited_to_chosen_lists() {
    let harness = Harness::new().await;
    let list = subscribe(&harness, "ads", ADS_LIST, "domains").await.list;
    let device = devices::create(
        State(harness.state.clone()),
        ApiJson(devices::DeviceInput {
            all_lists: Some(false),
            lists: Some(vec![list.id.clone()]),
            ..device_input("Tablet", "192.168.1.20")
        }),
    )
    .await
    .expect("device with a selection")
    .data;
    assert_eq!(device.lists, vec![list.id]);

    let unknown = devices::create(
        State(harness.state.clone()),
        ApiJson(devices::DeviceInput {
            all_lists: Some(false),
            lists: Some(vec!["00000000-0000-4000-8000-00000000beef".to_owned()]),
            ..device_input("Phone", "192.168.1.21")
        }),
    )
    .await
    .expect_err("a selection naming no list");
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
}

// --------------------------------------------------------------------- rules

#[tokio::test]
async fn a_rule_is_normalised_and_upserted_rather_than_duplicated() {
    let harness = Harness::new().await;
    let state = harness.state.clone();

    let created = rules::create(
        State(state.clone()),
        ApiJson(rule_input(" *.Ads.Example.COM. ", "block", None)),
    )
    .await
    .expect("create a rule")
    .data;
    assert_eq!(created.domain, "ads.example.com");
    assert_eq!(created.action, "block");
    assert_eq!(created.device_id, None);

    let flipped = rules::create(
        State(state.clone()),
        ApiJson(rule_input("ads.example.com", "allow", None)),
    )
    .await
    .expect("flip the rule")
    .data;
    assert_eq!(
        flipped.id, created.id,
        "the row the UI is showing must survive"
    );
    assert_eq!(flipped.action, "allow");

    let all = rules::list(State(state.clone()), ApiQuery(rules::RuleQuery::default()))
        .await
        .expect("list rules")
        .data;
    assert_eq!(all.len(), 1);

    assert!(
        rules::remove(State(state.clone()), Path(created.id.to_string()))
            .await
            .expect("delete")
            .data
            .deleted
    );
    let missing = rules::remove(State(state), Path(created.id.to_string()))
        .await
        .expect_err("deleting twice");
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_rule_that_is_not_a_domain_is_refused() {
    let harness = Harness::new().await;
    for (domain, action) in [
        ("localhost", "block"),
        ("http://example.com", "block"),
        ("exa mple.com", "block"),
        ("not a domain", "block"),
        ("", "block"),
        ("example.com", "sinkhole"),
    ] {
        let error = rules::create(
            State(harness.state.clone()),
            ApiJson(rule_input(domain, action, None)),
        )
        .await
        .expect_err("bad rule input");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{domain} {action}");
    }
}

#[tokio::test]
async fn a_rule_for_a_device_that_does_not_exist_is_a_404() {
    let harness = Harness::new().await;
    let error = rules::create(
        State(harness.state.clone()),
        ApiJson(rule_input(
            "example.com",
            "block",
            Some("00000000-0000-4000-8000-00000000dead"),
        )),
    )
    .await
    .expect_err("an orphan rule");
    assert_eq!(error.status(), StatusCode::NOT_FOUND);
}

// --------------------------------------------------------------------- lists

#[tokio::test]
async fn a_new_list_is_fetched_parsed_and_installed_before_the_response() {
    let harness = Harness::new().await;
    let created = subscribe(&harness, "ads", ADS_LIST, "domains").await;
    assert_eq!(created.outcome, Outcome::Updated);
    assert_eq!(created.list.rule_count, 2);
    assert_eq!(created.list.last_error, None);
    assert!(
        harness
            .lists
            .path()
            .join(format!("{}.txt", created.list.id))
            .is_file(),
        "the body must be cached on disk so the next boot needs no network"
    );

    let decided = verdict(&harness, "ads.example.com", None).await;
    assert_eq!(decided.verdict, "block");
    assert_eq!(decided.reason, Reason::List);
    assert_eq!(decided.list.as_deref(), Some("ads"));
}

#[tokio::test]
async fn a_list_that_cannot_be_parsed_is_rejected_without_touching_the_policy() {
    let harness = Harness::new().await;
    let created = subscribe(
        &harness,
        "broken",
        "data:text/plain,%3Chtml%3Enot a list%3C/html%3E",
        "domains",
    )
    .await;
    assert_eq!(created.outcome, Outcome::Rejected);
    assert_eq!(created.list.rule_count, 0);
    assert!(created.list.last_error.is_some());
    assert_eq!(harness.state.runtime.current_policy().index.len(), 0);
}

#[tokio::test]
async fn the_sixty_fifth_enabled_list_is_refused() {
    let harness = Harness::new().await;
    for slot in 0..64 {
        harness
            .state
            .storage
            .insert_source(NewSource {
                id: None,
                name: format!("list {slot}"),
                url: format!("data:text/plain,slot{slot}.example.com"),
                kind: "domains".to_owned(),
                enabled: true,
            })
            .await
            .expect("seed an enabled list");
    }

    let refused = lists::create(
        State(harness.state.clone()),
        ApiJson(list_input("one too many", ADS_LIST, "domains")),
    )
    .await
    .expect_err("the 65th enabled list");
    assert_eq!(refused.status(), StatusCode::CONFLICT);

    // Disabled, it fits; enabling it afterwards is refused by the same rule.
    let parked = lists::create(
        State(harness.state.clone()),
        ApiJson(lists::ListInput {
            enabled: Some(false),
            ..list_input("parked", ADS_LIST, "domains")
        }),
    )
    .await
    .expect("a disabled list always fits")
    .data;
    let refused = lists::update(
        State(harness.state.clone()),
        Path(parked.list.id),
        ApiJson(lists::ListPatch {
            enabled: Some(true),
            ..lists::ListPatch::default()
        }),
    )
    .await
    .expect_err("enabling the 65th");
    assert_eq!(refused.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn two_lists_cannot_share_a_name_and_a_url_must_be_fetchable() {
    let harness = Harness::new().await;
    subscribe(&harness, "ads", ADS_LIST, "domains").await;

    let clash = lists::create(
        State(harness.state.clone()),
        ApiJson(list_input(
            "ads",
            "https://example.com/other.txt",
            "domains",
        )),
    )
    .await
    .expect_err("a duplicate name");
    assert_eq!(clash.status(), StatusCode::CONFLICT);

    for (url, kind) in [("ftp://example.com/list", "domains"), (ADS_LIST, "yaml")] {
        let error = lists::create(
            State(harness.state.clone()),
            ApiJson(list_input("another", url, kind)),
        )
        .await
        .expect_err("an unusable list");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn deleting_a_list_removes_its_cached_body_and_its_verdicts() {
    let harness = Harness::new().await;
    let created = subscribe(&harness, "ads", ADS_LIST, "domains").await;
    let body = harness
        .lists
        .path()
        .join(format!("{}.txt", created.list.id));

    lists::remove(State(harness.state.clone()), Path(created.list.id))
        .await
        .expect("delete the list");
    assert!(!body.exists(), "the cached body must go with the list");
    assert_eq!(
        verdict(&harness, "ads.example.com", None).await.verdict,
        "allow"
    );
}

#[tokio::test]
async fn a_second_manual_refresh_inside_the_gap_is_refused() {
    let harness = Harness::new().await;
    subscribe(&harness, "ads", ADS_LIST, "domains").await;

    let first = lists::refresh(State(harness.state.clone()), None)
        .await
        .expect("the first manual refresh")
        .data;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].outcome, Outcome::Updated);

    let refused = lists::refresh(State(harness.state.clone()), None)
        .await
        .expect_err("a second refresh straight away");
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_catalogue_carries_the_presets_and_the_due_flag() {
    let harness = Harness::new().await;
    let catalogue = lists::catalogue(State(harness.state.clone()))
        .await
        .expect("the catalogue")
        .data;
    assert!(catalogue.lists.is_empty());
    assert_eq!(catalogue.presets.len(), 11);
    assert!(
        catalogue
            .presets
            .iter()
            .any(|preset| preset.name == "oisd small")
    );

    subscribe(&harness, "ads", ADS_LIST, "domains").await;
    let catalogue = lists::catalogue(State(harness.state.clone()))
        .await
        .expect("the catalogue")
        .data;
    assert!(
        !catalogue.lists[0].due,
        "a list fetched a moment ago is not due again"
    );
}

// --------------------------------------------------------------------- check

/// The precedence table of §6, step by step, through the route that reports it.
#[tokio::test]
async fn check_reports_which_step_decided() {
    let harness = Harness::new().await;
    let state = harness.state.clone();
    // An ABP list, seeded into the cache and compiled the way a boot compiles it: a block, an
    // exception for a name the same list blocks, and a protected name the list is wrong about.
    let source = state
        .storage
        .insert_source(NewSource {
            id: None,
            name: "ads".to_owned(),
            url: "https://lists.example.com/ads.txt".to_owned(),
            kind: "adblock".to_owned(),
            enabled: true,
        })
        .await
        .expect("subscribe to a list");
    super::cache_body(
        &harness,
        &source.id,
        "[Adblock Plus 2.0]\n! a comment\n||ads.example.com^\n||shop.example.com^\n@@||shop.example.com^\n||promo.example.com^\n||time.apple.com^\n",
    );
    rebuild(&state, Rebuild::Lists)
        .await
        .expect("compile the cached body");

    let filtered = devices::create(
        State(state.clone()),
        ApiJson(device_input("Tablet", "192.168.1.20")),
    )
    .await
    .expect("a filtered device")
    .data;
    devices::create(
        State(state.clone()),
        ApiJson(devices::DeviceInput {
            filtering: Some(false),
            ..device_input("Guest TV", "192.168.1.30")
        }),
    )
    .await
    .expect("a device with filtering off");

    rules::create(
        State(state.clone()),
        ApiJson(rule_input("ads.example.com", "allow", Some(&filtered.id))),
    )
    .await
    .expect("a device rule");
    rules::create(
        State(state.clone()),
        ApiJson(rule_input("games.example.com", "block", Some(&filtered.id))),
    )
    .await
    .expect("a device block rule");
    rules::create(
        State(state.clone()),
        ApiJson(rule_input("news.example.com", "block", None)),
    )
    .await
    .expect("a household rule");
    rules::create(
        State(state.clone()),
        ApiJson(rule_input("promo.example.com", "allow", None)),
    )
    .await
    .expect("a household rule that overrides a list block");

    // 4. A device rule outranks the list that blocks the same name.
    let decided = verdict(&harness, "ads.example.com", Some("192.168.1.20")).await;
    assert_eq!(
        (decided.verdict, decided.reason),
        ("allow", Reason::DeviceRule)
    );
    assert_eq!(decided.scope, "device");
    assert_eq!(decided.device_name.as_deref(), Some("Tablet"));

    // 5. A device rule blocks a name nothing else has an opinion about.
    let decided = verdict(&harness, "games.example.com", Some("192.168.1.20")).await;
    assert_eq!(
        (decided.verdict, decided.reason),
        ("block", Reason::DeviceRule)
    );
    assert_eq!(decided.scope, "device");

    // 6. A household allow rule outranks the list that blocks the same name.
    let decided = verdict(&harness, "promo.example.com", Some("192.168.1.20")).await;
    assert_eq!(
        (decided.verdict, decided.reason),
        ("allow", Reason::HouseholdRule)
    );

    // 7. A household rule applies to a client with no device row.
    let decided = verdict(&harness, "news.example.com", Some("192.168.1.99")).await;
    assert_eq!(
        (decided.verdict, decided.reason),
        ("block", Reason::HouseholdRule)
    );
    assert_eq!(decided.scope, "household");

    // 8. Protected names outrank the subscribed list that blocks them.
    let decided = verdict(&harness, "time.apple.com", None).await;
    assert_eq!(
        (decided.verdict, decided.reason),
        ("allow", Reason::Protected)
    );

    // 9. A list exception outranks the block in the same list, and names the list that
    // carried it — "why is this allowed?" is only useful when it says which list decided.
    let decided = verdict(&harness, "shop.example.com", None).await;
    assert_eq!(
        (decided.verdict, decided.reason),
        ("allow", Reason::ListAllow)
    );
    assert_eq!(decided.list.as_deref(), Some("ads"));

    // 10. A list block, attributed to the list that carried it, and on a subdomain too.
    let decided = verdict(&harness, "tracker.ads.example.com", None).await;
    assert_eq!((decided.verdict, decided.reason), ("block", Reason::List));
    assert_eq!(decided.list.as_deref(), Some("ads"));

    // 3. Filtering off resolves everything.
    let decided = verdict(&harness, "ads.example.com", Some("192.168.1.30")).await;
    assert_eq!(
        (decided.verdict, decided.reason),
        ("allow", Reason::Unfiltered)
    );
    assert_eq!(decided.scope, "unfiltered");

    // 12. Nothing matched.
    let decided = verdict(&harness, "example.org", None).await;
    assert_eq!(
        (decided.verdict, decided.reason),
        ("allow", Reason::NoMatch)
    );

    // 1. Pause beats everything, for everyone.
    runtime::pause(
        State(state.clone()),
        ApiJson(runtime::PauseRequest { minutes: 5 }),
    )
    .await
    .expect("pause");
    let decided = verdict(&harness, "ads.example.com", Some("192.168.1.20")).await;
    assert_eq!((decided.verdict, decided.reason), ("allow", Reason::Paused));
    assert_eq!(decided.scope, "paused");

    // …including the name this very device has its own block rule for, which is the only
    // comparison that pins step 1 above step 5 rather than merely agreeing with it.
    let decided = verdict(&harness, "games.example.com", Some("192.168.1.20")).await;
    assert_eq!((decided.verdict, decided.reason), ("allow", Reason::Paused));
    let decided = verdict(&harness, "news.example.com", None).await;
    assert_eq!((decided.verdict, decided.reason), ("allow", Reason::Paused));
}

#[tokio::test]
async fn check_refuses_input_that_is_not_a_domain_or_an_address() {
    let harness = Harness::new().await;
    for (domain, client) in [
        (None, None),
        (Some("   "), None),
        (Some("example.com"), Some("not-an-ip")),
        // A string that is not a domain: `POST /rules` refuses these, so the page that asks
        // "why?" about one must not be handed a confident "allowed" instead.
        (Some("not a domain"), None),
        (Some("google"), None),
        (Some("http://example.com"), None),
    ] {
        let error = check::check(
            State(harness.state.clone()),
            ApiQuery(check::CheckQuery {
                domain: domain.map(ToOwned::to_owned),
                client: client.map(ToOwned::to_owned),
            }),
        )
        .await
        .expect_err("bad check input");
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
    }
}
