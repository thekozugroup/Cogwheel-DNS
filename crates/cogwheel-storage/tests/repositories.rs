//! The three user concepts on disk -- sources, devices and rules -- plus settings and the shapes
//! the API serialises (spec sections 1.4 and 2.1).

mod common;

use common::*;

// ---------------------------------------------------------------- sources

#[tokio::test]
async fn sources_round_trip_and_names_are_unique() {
    let (_dir, storage) = fresh("sources").await;

    let created = storage
        .insert_source(NewSource {
            id: None,
            name: "HaGeZi Pro".to_owned(),
            url: "https://example.invalid/pro.txt".to_owned(),
            kind: "adblock".to_owned(),
            enabled: true,
        })
        .await
        .expect("insert");
    assert!(created.enabled);
    assert_eq!(created.rule_count, 0);
    assert!(created.last_error.is_none());

    let fetched = storage
        .get_source(&created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(fetched.name, "HaGeZi Pro");

    let updated = storage
        .update_source(
            &created.id,
            SourcePatch {
                enabled: Some(false),
                ..SourcePatch::default()
            },
        )
        .await
        .expect("update")
        .expect("present");
    assert!(!updated.enabled);
    assert_eq!(updated.name, "HaGeZi Pro", "an absent field is left alone");
    assert_eq!(updated.url, created.url);

    let duplicate = storage
        .insert_source(NewSource {
            id: None,
            name: "HaGeZi Pro".to_owned(),
            url: "https://example.invalid/other.txt".to_owned(),
            kind: "hosts".to_owned(),
            enabled: true,
        })
        .await
        .expect_err("a duplicate name must be rejected");
    assert!(duplicate.is_unique_violation(), "{duplicate}");
    assert!(!duplicate.is_foreign_key_violation());

    assert!(storage.delete_source(&created.id).await.expect("delete"));
    assert!(!storage.delete_source(&created.id).await.expect("delete"));
    assert!(
        storage
            .get_source(&created.id)
            .await
            .expect("get")
            .is_none()
    );
}

#[tokio::test]
async fn fetch_status_transitions_keep_what_still_describes_the_cached_body() {
    let (_dir, storage) = fresh("fetch-status").await;
    let source = storage.list_sources().await.expect("list").remove(0);

    storage
        .update_fetch_status(
            &source.id,
            FetchStatus::Ok {
                at: NOW,
                etag: Some("\"abc\"".to_owned()),
                last_modified: Some("Tue, 14 Nov 2023 22:00:00 GMT".to_owned()),
                rule_count: 1234,
                note: Some("covers pool.ntp.org".to_owned()),
            },
        )
        .await
        .expect("ok status");
    let after_ok = storage
        .get_source(&source.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(after_ok.last_ok_at, Some(NOW));
    assert_eq!(after_ok.last_fetched_at, Some(NOW));
    assert_eq!(after_ok.rule_count, 1234);
    assert_eq!(after_ok.etag.as_deref(), Some("\"abc\""));
    assert!(after_ok.last_error.is_none());

    storage
        .update_fetch_status(
            &source.id,
            FetchStatus::Failed {
                at: NOW + 60,
                error: "connection refused".to_owned(),
            },
        )
        .await
        .expect("failed status");
    let after_failure = storage
        .get_source(&source.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        after_failure.last_error.as_deref(),
        Some("connection refused")
    );
    assert_eq!(after_failure.last_fetched_at, Some(NOW + 60));
    assert_eq!(
        after_failure.last_ok_at,
        Some(NOW),
        "a failure is not an update"
    );
    assert_eq!(
        after_failure.rule_count, 1234,
        "the cached body still serves"
    );
    assert_eq!(after_failure.etag.as_deref(), Some("\"abc\""));

    storage
        .update_fetch_status(&source.id, FetchStatus::Unchanged { at: NOW + 120 })
        .await
        .expect("unchanged status");
    let after_304 = storage
        .get_source(&source.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(after_304.last_ok_at, Some(NOW + 120));
    assert_eq!(after_304.rule_count, 1234);
    assert!(
        after_304.last_error.is_none(),
        "a 304 clears the previous error"
    );

    assert!(
        !storage
            .update_fetch_status("no-such-list", FetchStatus::Unchanged { at: NOW })
            .await
            .expect("missing list")
    );
}

// ---------------------------------------------------------------- devices

#[tokio::test]
async fn devices_upsert_in_place_and_addresses_are_unique() {
    let (_dir, storage) = fresh("devices").await;

    let created = storage
        .upsert_device(
            DeviceUpsert {
                id: None,
                name: "Kids Tablet".to_owned(),
                ip_address: "192.168.1.50".to_owned(),
                filtering: true,
                all_lists: true,
            },
            Vec::new(),
        )
        .await
        .expect("create");

    let renamed = storage
        .upsert_device(
            DeviceUpsert {
                id: Some(created.id.clone()),
                name: "Tablet".to_owned(),
                ip_address: "192.168.1.60".to_owned(),
                filtering: false,
                all_lists: false,
            },
            Vec::new(),
        )
        .await
        .expect("update");
    assert_eq!(renamed.id, created.id, "an update keeps the row");
    assert_eq!(renamed.name, "Tablet");
    assert_eq!(renamed.ip_address, "192.168.1.60");
    assert!(!renamed.filtering);
    assert!(!renamed.all_lists);
    assert_eq!(renamed.created_at, created.created_at);
    assert_eq!(storage.list_devices().await.expect("list").len(), 1);

    let duplicate = storage
        .upsert_device(
            DeviceUpsert {
                id: None,
                name: "Someone else".to_owned(),
                ip_address: "192.168.1.60".to_owned(),
                filtering: true,
                all_lists: true,
            },
            Vec::new(),
        )
        .await
        .expect_err("two devices cannot share an address");
    assert!(duplicate.is_unique_violation(), "{duplicate}");

    assert!(storage.delete_device(&created.id).await.expect("delete"));
    assert!(!storage.delete_device(&created.id).await.expect("delete"));
}

#[tokio::test]
async fn device_lists_are_replaced_deduped_and_cascade() {
    let (_dir, storage) = fresh("device-lists").await;
    let seeded = storage.list_sources().await.expect("list").remove(0);
    let second = storage
        .insert_source(NewSource {
            id: None,
            name: "StevenBlack".to_owned(),
            url: "https://example.invalid/hosts".to_owned(),
            kind: "hosts".to_owned(),
            enabled: true,
        })
        .await
        .expect("insert");
    // The same device, re-sent with a different selection each time — which is what the one
    // write it now takes looks like from the API above it.
    let console = |lists: Vec<String>| {
        (
            DeviceUpsert {
                id: None,
                name: "Console".to_owned(),
                ip_address: "192.168.1.70".to_owned(),
                filtering: true,
                all_lists: false,
            },
            lists,
        )
    };

    let (upsert, lists) = console(vec![
        seeded.id.clone(),
        seeded.id.clone(),
        second.id.clone(),
    ]);
    let device = storage.upsert_device(upsert, lists).await.expect("device");
    let selected = storage
        .list_device_lists(Some(&device.id))
        .await
        .expect("read lists");
    assert_eq!(selected.len(), 2, "a repeated id is stored once");

    let (mut upsert, lists) = console(vec![second.id.clone()]);
    upsert.id = Some(device.id.clone());
    storage
        .upsert_device(upsert, lists)
        .await
        .expect("replace lists");
    let selected = storage.list_device_lists(None).await.expect("read lists");
    assert_eq!(selected.len(), 1, "the selection is replaced, not merged");
    assert_eq!(selected[0].source_id, second.id);

    let (mut upsert, lists) = console(vec!["no-such-list".to_owned()]);
    upsert.id = Some(device.id.clone());
    upsert.name = "Renamed".to_owned();
    let unknown = storage
        .upsert_device(upsert, lists)
        .await
        .expect_err("an unknown list id is a foreign key violation");
    assert!(unknown.is_foreign_key_violation(), "{unknown}");
    assert_eq!(
        storage.list_device_lists(None).await.expect("read").len(),
        1,
        "and the transaction left the previous selection alone"
    );
    assert_eq!(
        storage
            .get_device(&device.id)
            .await
            .expect("read")
            .expect("the device is still there")
            .name,
        "Console",
        "a refused selection rolls the row back with it"
    );

    let (mut upsert, lists) = console(vec![seeded.id.clone(), second.id.clone()]);
    upsert.id = Some(device.id.clone());
    storage.upsert_device(upsert, lists).await.expect("relist");
    assert!(
        storage
            .delete_source(&second.id)
            .await
            .expect("delete list")
    );
    assert_eq!(
        storage.list_device_lists(None).await.expect("read").len(),
        1,
        "deleting a list takes its device_lists rows with it"
    );

    storage
        .delete_device(&device.id)
        .await
        .expect("delete device");
    assert!(
        storage
            .list_device_lists(None)
            .await
            .expect("read")
            .is_empty(),
        "and so does deleting the device"
    );
}

/// A create whose selection is refused must leave nothing behind: a device row with
/// `all_lists = 0` and no `device_lists` rows subscribes to no list at all, which is a device
/// that resolves everything after a request the caller was told had failed.
#[tokio::test]
async fn a_refused_selection_leaves_no_device_behind() {
    let (_dir, storage) = fresh("device-atomic").await;
    let refused = storage
        .upsert_device(
            DeviceUpsert {
                id: None,
                name: "Console".to_owned(),
                ip_address: "192.168.1.70".to_owned(),
                filtering: true,
                all_lists: false,
            },
            vec!["no-such-list".to_owned()],
        )
        .await
        .expect_err("an unknown list id is a foreign key violation");
    assert!(refused.is_foreign_key_violation(), "{refused}");
    assert!(
        storage.list_devices().await.expect("read").is_empty(),
        "the device row went back with the selection"
    );
    assert!(
        storage
            .list_device_lists(None)
            .await
            .expect("read")
            .is_empty()
    );
}

// ---------------------------------------------------------------- rules

#[tokio::test]
async fn rules_upsert_per_scope_and_cascade_with_their_device() {
    let (_dir, storage) = fresh("rules").await;
    let device = storage
        .upsert_device(
            DeviceUpsert {
                id: None,
                name: "Tablet".to_owned(),
                ip_address: "192.168.1.80".to_owned(),
                filtering: true,
                all_lists: true,
            },
            Vec::new(),
        )
        .await
        .expect("device");

    let household = storage
        .upsert_rule("ads.example.com", "block", None)
        .await
        .expect("household rule");
    assert!(household.device_id.is_none());
    assert!(household.device_name.is_none());

    let flipped = storage
        .upsert_rule("ads.example.com", "allow", None)
        .await
        .expect("flip");
    assert_eq!(flipped.id, household.id, "flipping keeps the row id");
    assert_eq!(flipped.action, "allow");
    assert_eq!(flipped.created_at, household.created_at);

    let per_device = storage
        .upsert_rule("ads.example.com", "block", Some(&device.id))
        .await
        .expect("device rule");
    assert_ne!(
        per_device.id, household.id,
        "the same domain in another scope is another rule"
    );
    assert_eq!(per_device.device_name.as_deref(), Some("Tablet"));

    assert_eq!(storage.list_rules(None).await.expect("all").len(), 2);
    assert_eq!(
        storage
            .list_rules(Some(&device.id))
            .await
            .expect("device")
            .len(),
        1
    );

    let orphan = storage
        .upsert_rule("ads.example.com", "block", Some("no-such-device"))
        .await
        .expect_err("a rule for a device that does not exist is a foreign key violation");
    assert!(orphan.is_foreign_key_violation(), "{orphan}");

    storage
        .delete_device(&device.id)
        .await
        .expect("delete device");
    let remaining = storage.list_rules(None).await.expect("all");
    assert_eq!(remaining.len(), 1, "device rules go with the device");
    assert!(remaining[0].device_id.is_none());

    let taken = storage
        .delete_rule(remaining[0].id)
        .await
        .expect("delete")
        .expect("the row that was removed comes back");
    assert_eq!(taken.id, remaining[0].id);
    assert!(taken.device_id.is_none(), "and says which scope it was in");
    assert!(
        storage
            .delete_rule(remaining[0].id)
            .await
            .expect("delete")
            .is_none()
    );
}

// ---------------------------------------------------------------- settings

#[tokio::test]
async fn pause_until_round_trips() {
    let (_dir, storage) = fresh("pause").await;
    assert!(storage.pause_until().await.expect("read").is_none());

    storage
        .set_pause_until(Some(NOW + 1800))
        .await
        .expect("pause");
    assert_eq!(storage.pause_until().await.expect("read"), Some(NOW + 1800));

    storage.set_pause_until(None).await.expect("resume");
    assert!(
        storage.pause_until().await.expect("read").is_none(),
        "resuming clears the row rather than storing a zero"
    );

    storage.set_pause_until(Some(0)).await.expect("zero");
    assert!(
        storage.pause_until().await.expect("read").is_none(),
        "a zero deadline is not a pause"
    );
}

// ---------------------------------------------------------------- API shapes

#[tokio::test]
async fn records_the_api_returns_serialize() {
    let (_dir, storage) = fresh("serde").await;
    let device = storage
        .upsert_device(
            DeviceUpsert {
                id: None,
                name: "Tablet".to_owned(),
                ip_address: "10.0.0.1".to_owned(),
                filtering: true,
                all_lists: true,
            },
            Vec::new(),
        )
        .await
        .expect("device");
    storage
        .upsert_rule("ads.example.com", "block", Some(&device.id))
        .await
        .expect("rule");
    storage
        .insert_batch_with_rollups(vec![entry(NOW, "10.0.0.1", "ads.example.com", true)], true)
        .await
        .expect("batch");

    let source = serde_json::to_value(&storage.list_sources().await.expect("sources")[0])
        .expect("serialize source");
    assert_eq!(source["name"], "oisd small");
    assert!(source.get("last_ok_at").is_some());

    let device = serde_json::to_value(&device).expect("serialize device");
    assert_eq!(device["ip_address"], "10.0.0.1");
    assert_eq!(device["filtering"], true);

    let rule = serde_json::to_value(&storage.list_rules(None).await.expect("rules")[0])
        .expect("serialize rule");
    assert_eq!(rule["device_name"], "Tablet");

    let page = storage
        .query_page(QueryFilter {
            limit: 10,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    let page = serde_json::to_value(&page).expect("serialize page");
    assert_eq!(page["rows"][0]["domain"], "ads.example.com");
    assert_eq!(page["rows"][0]["device_name"], "Tablet");

    let hours = serde_json::to_value(storage.hourly_24h(NOW).await.expect("hourly"))
        .expect("serialize hours");
    assert_eq!(hours.as_array().expect("array").len(), 24);
}
