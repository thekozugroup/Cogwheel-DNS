//! The query log, its hourly rollups and the retention passes over both (spec section 7).

mod common;

use common::*;

// ---------------------------------------------------------------- query log and rollups

#[tokio::test]
async fn rollups_accumulate_across_batches() {
    let (_dir, storage) = fresh("rollups").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "ads.example.com", true),
                entry(NOW, "10.0.0.1", "news.example.com", false),
                entry(NOW, "10.0.0.2", "cdn.example.com", false),
            ],
            true,
        )
        .await
        .expect("first batch");
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW + 10, "10.0.0.1", "ads.example.com", true),
                entry(NOW + 20, "10.0.0.2", "tracker.example.com", true),
            ],
            true,
        )
        .await
        .expect("second batch");

    let hours = storage.hourly_24h(NOW).await.expect("hourly");
    let current = hours.last().expect("24 buckets");
    assert_eq!(current.queries, 5, "both batches land in the same bucket");
    assert_eq!(current.blocked, 3);

    let clients = storage.per_client_24h(NOW).await.expect("per client");
    assert_eq!(clients.len(), 2, "the all-devices bucket is not a client");
    assert_eq!(clients[0].client, "10.0.0.1");
    assert_eq!(clients[0].queries, 3);
    assert_eq!(clients[0].blocked, 2);
    assert_eq!(clients[0].last_seen, NOW + 10, "last_seen is the maximum");
    assert_eq!(clients[1].client, "10.0.0.2");
    assert_eq!(clients[1].queries, 2);
    assert_eq!(clients[1].blocked, 1);
    assert_eq!(clients[1].last_seen, NOW + 20);
}

#[tokio::test]
async fn history_days_zero_writes_rollups_but_no_rows() {
    let (_dir, storage) = fresh("no-history").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "ads.example.com", true),
                entry(NOW, "10.0.0.1", "news.example.com", false),
            ],
            false,
        )
        .await
        .expect("batch");

    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert!(
        page.rows.is_empty(),
        "no browsing history is written at all"
    );

    let hours = storage.hourly_24h(NOW).await.expect("hourly");
    assert_eq!(
        hours.last().expect("bucket").queries,
        2,
        "but the counts are"
    );
    assert_eq!(hours.last().expect("bucket").blocked, 1);
}

#[tokio::test]
async fn the_hourly_chart_always_has_twenty_four_buckets() {
    let (_dir, storage) = fresh("hourly").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "a.example.com", true),
                entry(NOW - 5 * HOUR, "10.0.0.1", "b.example.com", false),
                // Older than the window: it must not appear, and must not shift the buckets.
                entry(NOW - 30 * HOUR, "10.0.0.1", "c.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    let hours = storage.hourly_24h(NOW).await.expect("hourly");
    assert_eq!(hours.len(), 24);
    assert!(
        hours
            .windows(2)
            .all(|pair| pair[1].hour - pair[0].hour == HOUR),
        "buckets are contiguous and in order"
    );
    assert_eq!(hours[23].queries, 1);
    assert_eq!(hours[23].blocked, 1);
    assert_eq!(hours[18].queries, 1, "five hours back");
    assert_eq!(hours[18].blocked, 0);
    assert_eq!(
        hours.iter().map(|bucket| bucket.queries).sum::<i64>(),
        2,
        "the out-of-window hour is not folded in anywhere"
    );
}

#[tokio::test]
async fn paging_walks_the_log_newest_first() {
    let (_dir, storage) = fresh("paging").await;
    let batch = (0..4)
        .map(|index| {
            entry(
                NOW + index,
                "10.0.0.1",
                &format!("d{index}.example.com"),
                false,
            )
        })
        .collect();
    storage
        .insert_batch_with_rollups(batch, true)
        .await
        .expect("batch");

    let empty = storage
        .query_page(QueryFilter {
            limit: 0,
            ..QueryFilter::default()
        })
        .await
        .expect("limit 0");
    assert!(empty.rows.is_empty());
    assert!(empty.next_before.is_none(), "limit 0 is not a cursor");

    let first = storage
        .query_page(QueryFilter {
            limit: 2,
            ..QueryFilter::default()
        })
        .await
        .expect("first page");
    assert_eq!(
        first
            .rows
            .iter()
            .map(|row| row.domain.as_str())
            .collect::<Vec<_>>(),
        ["d3.example.com", "d2.example.com"]
    );

    let second = storage
        .query_page(QueryFilter {
            limit: 2,
            before: first.next_before,
            ..QueryFilter::default()
        })
        .await
        .expect("second page");
    assert_eq!(
        second
            .rows
            .iter()
            .map(|row| row.domain.as_str())
            .collect::<Vec<_>>(),
        ["d1.example.com", "d0.example.com"]
    );

    // The log ended exactly on a page boundary, so the cursor is still set and the page after it
    // is what tells the caller there is nothing more.
    assert!(second.next_before.is_some());
    let third = storage
        .query_page(QueryFilter {
            limit: 2,
            before: second.next_before,
            ..QueryFilter::default()
        })
        .await
        .expect("third page");
    assert!(third.rows.is_empty());
    assert!(third.next_before.is_none());
}

#[tokio::test]
async fn page_filters_narrow_the_log() {
    let (_dir, storage) = fresh("filters").await;
    storage
        .upsert_device(
            DeviceUpsert {
                id: None,
                name: "Kids Tablet".to_owned(),
                ip_address: "10.0.0.1".to_owned(),
                filtering: true,
                all_lists: true,
            },
            Vec::new(),
        )
        .await
        .expect("device");
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "ads.example.com", true),
                entry(NOW + 1, "10.0.0.1", "news.example.com", false),
                entry(NOW + 2, "10.0.0.2", "ADS.example.org", true),
                entry(NOW + 3, "10.0.0.2", "cdn.example.org", false),
            ],
            true,
        )
        .await
        .expect("batch");

    let all = QueryFilter {
        limit: 100,
        ..QueryFilter::default()
    };

    let named = storage
        .query_page(QueryFilter {
            client: Some("10.0.0.1".to_owned()),
            ..all.clone()
        })
        .await
        .expect("client filter");
    assert_eq!(named.rows.len(), 2);
    assert!(
        named
            .rows
            .iter()
            .all(|row| row.device_name.as_deref() == Some("Kids Tablet")),
        "the join relabels history with the device's current name"
    );

    let unnamed = storage
        .query_page(QueryFilter {
            unnamed: true,
            ..all.clone()
        })
        .await
        .expect("unnamed filter");
    assert_eq!(unnamed.rows.len(), 2);
    assert!(
        unnamed
            .rows
            .iter()
            .all(|row| row.client == "10.0.0.2" && row.device_id.is_none())
    );

    let blocked = storage
        .query_page(QueryFilter {
            blocked: Some(true),
            ..all.clone()
        })
        .await
        .expect("blocked filter");
    assert_eq!(blocked.rows.len(), 2);
    assert!(blocked.rows.iter().all(|row| row.blocked));

    let allowed = storage
        .query_page(QueryFilter {
            blocked: Some(false),
            ..all.clone()
        })
        .await
        .expect("allowed filter");
    assert_eq!(allowed.rows.len(), 2);
    assert!(allowed.rows.iter().all(|row| !row.blocked));

    let searched = storage
        .query_page(QueryFilter {
            contains: Some("ADS.".to_owned()),
            ..all.clone()
        })
        .await
        .expect("substring filter");
    assert_eq!(
        searched.rows.len(),
        1,
        "the needle is case-insensitive; stored domains are already lower case"
    );
    assert_eq!(searched.rows[0].domain, "ads.example.com");

    let combined = storage
        .query_page(QueryFilter {
            blocked: Some(true),
            unnamed: true,
            ..all
        })
        .await
        .expect("combined filters");
    assert_eq!(combined.rows.len(), 1);
    assert_eq!(combined.rows[0].client, "10.0.0.2");
}

#[tokio::test]
async fn unnamed_clients_are_the_ones_without_a_device_row() {
    let (_dir, storage) = fresh("unnamed").await;
    storage
        .upsert_device(
            DeviceUpsert {
                id: None,
                name: "Kids Tablet".to_owned(),
                ip_address: "10.0.0.1".to_owned(),
                filtering: true,
                all_lists: true,
            },
            Vec::new(),
        )
        .await
        .expect("device");
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "a.example.com", false),
                entry(NOW, "10.0.0.2", "b.example.com", true),
                entry(NOW, "10.0.0.3", "c.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    assert_eq!(storage.per_client_24h(NOW).await.expect("all").len(), 3);
    let unnamed = storage.unnamed_clients_24h(NOW).await.expect("unnamed");
    assert_eq!(
        unnamed
            .iter()
            .map(|client| client.client.as_str())
            .collect::<Vec<_>>(),
        ["10.0.0.2", "10.0.0.3"]
    );
    assert_eq!(unnamed[0].blocked, 1);
    assert_eq!(unnamed[0].last_seen, NOW);
}

#[tokio::test]
async fn top_domains_ranks_blocked_and_queried_separately() {
    let (_dir, storage) = fresh("top").await;
    let mut batch = Vec::new();
    for _ in 0..5 {
        batch.push(entry(NOW, "10.0.0.1", "ads.example.com", true));
    }
    for _ in 0..9 {
        batch.push(entry(NOW, "10.0.0.1", "cdn.example.com", false));
    }
    batch.push(entry(NOW, "10.0.0.1", "tracker.example.com", true));
    // Before the window, and logged after the rows that are inside it: counted by neither table,
    // and it must not take the window's own rows out of the bounded scan with it.
    batch.push(entry(NOW - 2 * DAY, "10.0.0.1", "old.example.com", true));
    storage
        .insert_batch_with_rollups(batch, true)
        .await
        .expect("batch");

    let top = storage.top_domains(NOW - DAY, 10).await.expect("top ten");
    assert_eq!(
        top.blocked
            .iter()
            .map(|row| (row.domain.as_str(), row.count))
            .collect::<Vec<_>>(),
        [("ads.example.com", 5), ("tracker.example.com", 1)]
    );
    assert_eq!(top.queried[0].domain, "cdn.example.com");
    assert_eq!(top.queried[0].count, 9);
    assert_eq!(
        top.queried.len(),
        3,
        "allowed and blocked names both count as queried"
    );

    let capped = storage.top_domains(NOW - DAY, 1).await.expect("limit");
    assert_eq!(capped.blocked.len(), 1);
    assert_eq!(capped.queried.len(), 1);
}

/// The bound the scan takes is derived from the rollups and is an over-estimate, so a log far
/// longer than the window still answers for the whole window.
#[tokio::test]
async fn top_domains_counts_the_whole_window_of_a_long_log() {
    let (_dir, storage) = fresh("top-window").await;
    // Three days of log, one row per minute, with the window's names distinguishable from the
    // ones that came before it.
    let minutes = 3 * 24 * 60;
    let batch: Vec<QueryLogEntry> = (0..minutes)
        .map(|minute| {
            let ts = NOW - (minutes - minute) * 60;
            let inside = ts >= NOW - DAY;
            entry(
                ts,
                "10.0.0.1",
                if inside {
                    "new.example.com"
                } else {
                    "old.example.com"
                },
                true,
            )
        })
        .collect();
    storage
        .insert_batch_with_rollups(batch, true)
        .await
        .expect("batch");

    let top = storage.top_domains(NOW - DAY, 10).await.expect("top ten");
    assert_eq!(
        top.blocked
            .iter()
            .map(|row| (row.domain.as_str(), row.count))
            .collect::<Vec<_>>(),
        [("new.example.com", 24 * 60)],
        "every row of the window, and nothing older"
    );
}

#[tokio::test]
async fn clearing_the_log_keeps_the_counts() {
    let (_dir, storage) = fresh("clear").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW, "10.0.0.1", "ads.example.com", true),
                entry(NOW, "10.0.0.1", "news.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    assert_eq!(storage.clear_query_log().await.expect("clear"), 2);
    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert!(page.rows.is_empty());

    let hours = storage.hourly_24h(NOW).await.expect("hourly");
    assert_eq!(
        hours.last().expect("bucket").queries,
        2,
        "counts are not browsing history and survive a clear"
    );
    assert_eq!(storage.per_client_24h(NOW).await.expect("clients").len(), 1);
}

#[tokio::test]
async fn pruning_drops_rows_past_the_retention_window() {
    let (_dir, storage) = fresh("prune-days").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW - 10 * DAY, "10.0.0.1", "old.example.com", false),
                entry(NOW - 8 * DAY, "10.0.0.1", "older.example.com", false),
                entry(NOW - DAY, "10.0.0.1", "recent.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    let outcome = storage
        .prune_query_log(NOW, 7, u64::MAX, 90)
        .await
        .expect("prune");
    assert_eq!(outcome.by_age, 2);
    assert_eq!(outcome.by_cap, 0);

    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].domain, "recent.example.com");
}

#[tokio::test]
async fn pruning_with_history_off_keeps_what_is_already_there() {
    let (_dir, storage) = fresh("prune-off").await;
    storage
        .insert_batch_with_rollups(
            vec![entry(NOW - 10 * DAY, "10.0.0.1", "old.example.com", false)],
            true,
        )
        .await
        .expect("batch");

    let outcome = storage
        .prune_query_log(NOW, 0, u64::MAX, 90)
        .await
        .expect("prune");
    assert_eq!(
        outcome.by_age, 0,
        "turning logging off must not wipe the log"
    );
    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert_eq!(page.rows.len(), 1);
}

#[tokio::test]
async fn the_row_cap_keeps_exactly_max_rows() {
    let (_dir, storage) = fresh("prune-cap").await;
    let batch = (0..5)
        .map(|index| {
            entry(
                NOW + index,
                "10.0.0.1",
                &format!("d{index}.example.com"),
                false,
            )
        })
        .collect();
    storage
        .insert_batch_with_rollups(batch, true)
        .await
        .expect("batch");

    let outcome = storage
        .prune_query_log(NOW + 10, 7, 2, 90)
        .await
        .expect("prune");
    assert_eq!(outcome.by_cap, 3);

    let page = storage
        .query_page(QueryFilter {
            limit: 100,
            ..QueryFilter::default()
        })
        .await
        .expect("page");
    assert_eq!(
        page.rows
            .iter()
            .map(|row| row.domain.as_str())
            .collect::<Vec<_>>(),
        ["d4.example.com", "d3.example.com"],
        "the cap keeps the newest max_rows rows and no more"
    );

    let again = storage
        .prune_query_log(NOW + 10, 7, 2, 90)
        .await
        .expect("prune again");
    assert_eq!(again.by_cap, 0, "a log already at the cap is left alone");
}

#[tokio::test]
async fn old_rollup_buckets_are_pruned_on_their_own_schedule() {
    let (_dir, storage) = fresh("prune-rollups").await;
    storage
        .insert_batch_with_rollups(
            vec![
                entry(NOW - 100 * DAY, "10.0.0.1", "ancient.example.com", false),
                entry(NOW, "10.0.0.1", "today.example.com", false),
            ],
            true,
        )
        .await
        .expect("batch");

    let outcome = storage
        .prune_query_log(NOW, 0, u64::MAX, 90)
        .await
        .expect("prune");
    assert_eq!(
        outcome.rollups, 2,
        "the all-devices bucket and the client bucket for that hour"
    );
    assert_eq!(storage.per_client_24h(NOW).await.expect("clients").len(), 1);
}
