//! `burst.rs` (§6.5): per-device bursts, closing them on a synthetic clock, and picking the
//! website.

use crate::ai::Seen;
use crate::ai::burst::{Bursts, LATE, MAX_CLIENTS, MAX_CLOSED, MAX_NAMES, QUIET, SPAN, SiteLoad};
use crate::ai::site::sendable;
use cogwheel_policy::Reason;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// 2026-10-08 00:00 UTC.
const T: u32 = 1_791_417_600;

fn at(offset: i64) -> i64 {
    i64::from(T) + offset
}

fn device(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
}

fn seen(client: IpAddr, offset: u32, domain: &str) -> Seen {
    Seen {
        ts: T + offset,
        client,
        domain: Arc::from(domain),
        blocked: false,
        reason: Reason::NoMatch,
    }
}

fn blocked(client: IpAddr, offset: u32, domain: &str) -> Seen {
    Seen {
        blocked: true,
        reason: Reason::List,
        ..seen(client, offset, domain)
    }
}

/// Everything may be sent, as far as these tests care.
fn anything(_: &str) -> bool {
    true
}

fn members(load: &SiteLoad) -> Vec<&str> {
    load.members.iter().map(|looked| &*looked.domain).collect()
}

fn push_all(bursts: &mut Bursts, client: IpAddr, names: &[(u32, &str)]) {
    for (offset, name) in names {
        bursts.push(seen(client, *offset, name));
    }
}

#[test]
fn a_quiet_gap_or_the_span_closes_a_burst() {
    let a = device(2);
    let mut bursts = Bursts::default();
    push_all(
        &mut bursts,
        a,
        &[
            (0, "www.news-site.com"),
            (1, "static.news-site.com"),
            (2, "cdn.news-site.com"),
        ],
    );
    // Over once it has been quiet for QUIET, plus LATE for misses still to be logged.
    assert!(bursts.tick(at(2 + QUIET + LATE - 1), anything).is_empty());
    let loads = bursts.tick(at(2 + QUIET + LATE), anything);
    assert_eq!(loads.len(), 1);
    assert_eq!(&*loads[0].anchor, "www.news-site.com");
    assert_eq!(&*loads[0].anchor_key, "news-site.com");
    assert_eq!(loads[0].client, a);
    assert_eq!(
        members(&loads[0]),
        ["static.news-site.com", "cdn.news-site.com"]
    );
    assert!(bursts.is_empty());

    // A lookup after a quiet gap closes the open burst and starts the next one.
    push_all(
        &mut bursts,
        a,
        &[
            (100, "www.shop.com"),
            (101, "api.shop.com"),
            (105, "www.recipes.org"),
        ],
    );
    bursts.push(seen(a, 106, "static.recipes.org"));
    let loads = bursts.tick(at(106), anything);
    assert_eq!(loads.len(), 1, "only the closed burst is a load yet");
    assert_eq!(&*loads[0].anchor, "www.shop.com");
    assert_eq!(members(&loads[0]), ["api.shop.com"]);
    let loads = bursts.tick(at(106 + QUIET + LATE), anything);
    assert_eq!(&*loads[0].anchor, "www.recipes.org");

    // A device that never goes quiet: a lookup every 2 s. The burst takes what falls within
    // SPAN of its start, and the next lookup starts another.
    let stream: Vec<(u32, String)> = (0..=10)
        .map(|step| (200 + step * 2, format!("n{step}.feed.com")))
        .collect();
    for (offset, name) in &stream {
        bursts.push(seen(a, *offset, name));
    }
    let loads = bursts.tick(at(220), anything);
    assert_eq!(loads.len(), 1);
    assert_eq!(&*loads[0].anchor, "n0.feed.com");
    assert_eq!(loads[0].members.len(), 7, "n1 to n7, up to start + SPAN");
    assert!(
        loads[0]
            .members
            .iter()
            .all(|looked| i64::from(looked.first_ts) <= at(200 + SPAN))
    );

    // The span also closes a burst on the clock, however recent its last lookup.
    let mut bursts = Bursts::default();
    for step in 0..=7 {
        bursts.push(seen(a, 300 + step * 2, &format!("n{step}.feed.com")));
    }
    assert!(bursts.tick(at(300 + SPAN + LATE - 1), anything).is_empty());
    assert_eq!(bursts.tick(at(300 + SPAN + LATE), anything).len(), 1);
}

#[test]
fn late_logged_misses_join_their_burst() {
    let a = device(2);
    let mut bursts = Bursts::default();
    // The page's names were answered from the cache and logged at once; the website's own name
    // was a miss, logged when the upstream answered, stamped with when it was asked.
    bursts.push(seen(a, 10, "static.news-site.com"));
    bursts.push(seen(a, 11, "cdn.news-site.com"));
    bursts.push(seen(a, 10 - 4, "www.news-site.com"));
    // Too late to place: older than LATE before the burst began.
    bursts.push(seen(a, 10 - 5, "stale.example-cdn.net"));
    assert!(
        bursts.tick(at(11 + QUIET), anything).is_empty(),
        "waits LATE"
    );
    let loads = bursts.tick(at(11 + QUIET + LATE), anything);
    assert_eq!(loads.len(), 1);
    assert_eq!(
        &*loads[0].anchor, "www.news-site.com",
        "the earliest lookup, wherever it was logged"
    );
    assert_eq!(
        members(&loads[0]),
        ["static.news-site.com", "cdn.news-site.com"],
        "in first-seen order"
    );
}

#[test]
fn the_anchor_is_the_shared_site_not_a_tracker() {
    let a = device(2);
    let mut bursts = Bursts::default();
    // A tracker looked up first (a prefetch, say) is outscored by the site most names share.
    push_all(
        &mut bursts,
        a,
        &[
            (0, "ads.tracker-example.net"),
            (0, "www.news-site.com"),
            (1, "static.news-site.com"),
            (1, "cdn.news-site.com"),
            (1, "img.news-site.com"),
        ],
    );
    let loads = bursts.tick(at(100), anything);
    assert_eq!(&*loads[0].anchor, "www.news-site.com");
    assert!(members(&loads[0]).contains(&"ads.tracker-example.net"));

    // A site's own name gets the same bonus as a `www` name; a tie goes to the earliest.
    push_all(
        &mut bursts,
        a,
        &[
            (200, "cdn.example-cdn.net"),
            (201, "img.shop.com"),
            (201, "shop.com"),
            (201, "static.shop.com"),
        ],
    );
    assert_eq!(&*bursts.tick(at(300), anything)[0].anchor, "shop.com");
    push_all(
        &mut bursts,
        a,
        &[(400, "x.one.com"), (401, "www.two.com"), (401, "y.two.com")],
    );
    assert_eq!(&*bursts.tick(at(500), anything)[0].anchor, "x.one.com");
}

#[test]
fn the_anchor_is_never_a_member() {
    let a = device(2);
    let mut bursts = Bursts::default();
    push_all(
        &mut bursts,
        a,
        &[
            (0, "www.news-site.com"),
            (0, "static.news-site.com"),
            (1, "www.news-site.com"),
            (1, "static.news-site.com"),
        ],
    );
    let loads = bursts.tick(at(100), anything);
    assert_eq!(&*loads[0].anchor, "www.news-site.com");
    assert_eq!(members(&loads[0]), ["static.news-site.com"], "deduplicated");

    // A burst that is only its website has nothing to judge, and is discarded.
    push_all(
        &mut bursts,
        a,
        &[(200, "www.news-site.com"), (201, "www.news-site.com")],
    );
    assert!(bursts.tick(at(300), anything).is_empty());
    assert!(bursts.is_empty());
}

#[test]
fn a_blocked_name_is_never_the_anchor() {
    let a = device(2);
    let shareable = |name: &str| sendable(name, &[]);
    let mut bursts = Bursts::default();
    bursts.push(blocked(a, 0, "ads.adnet-example.com"));
    bursts.push(blocked(a, 0, "pixel.adnet-example.com"));
    bursts.push(blocked(a, 1, "js.adnet-example.com"));
    bursts.push(seen(a, 1, "nas.lan"));
    bursts.push(seen(a, 2, "cdn.recipes.org"));
    let loads = bursts.tick(at(100), shareable);
    assert_eq!(
        &*loads[0].anchor, "cdn.recipes.org",
        "the only name both shareable and not blocked"
    );
    let first = &loads[0].members[0];
    assert_eq!(
        (&*first.domain, first.blocked, first.reason),
        ("ads.adnet-example.com", true, Reason::List)
    );

    // Blocked once in the burst is blocked.
    bursts.push(seen(a, 200, "www.flip.com"));
    bursts.push(blocked(a, 200, "www.flip.com"));
    bursts.push(seen(a, 201, "cdn.other.com"));
    assert_eq!(&*bursts.tick(at(300), shareable)[0].anchor, "cdn.other.com");

    // Nothing that could be the website: discarded.
    bursts.push(blocked(a, 400, "ads.adnet-example.com"));
    bursts.push(blocked(a, 400, "pixel.adnet-example.com"));
    bursts.push(seen(a, 401, "printer.local"));
    assert!(bursts.tick(at(500), shareable).is_empty());
}

#[test]
fn clients_are_grouped_separately() {
    let (a, b) = (device(2), device(3));
    let mut bursts = Bursts::default();
    // Interleaved in time; each device's lookups stay its own.
    bursts.push(seen(a, 0, "www.news-site.com"));
    bursts.push(seen(b, 0, "www.shop.com"));
    bursts.push(seen(a, 1, "static.news-site.com"));
    bursts.push(seen(b, 1, "api.shop.com"));
    bursts.push(seen(b, 2, "js.payments-example.com"));
    let mut loads = bursts.tick(at(100), anything);
    loads.sort_by_key(|load| load.client);
    assert_eq!(loads.len(), 2);
    assert_eq!(
        (loads[0].client, &*loads[0].anchor, members(&loads[0])),
        (a, "www.news-site.com", vec!["static.news-site.com"])
    );
    assert_eq!(
        (loads[1].client, &*loads[1].anchor, members(&loads[1])),
        (
            b,
            "www.shop.com",
            vec!["api.shop.com", "js.payments-example.com"]
        )
    );
}

#[test]
fn the_client_table_is_bounded() {
    let mut bursts = Bursts::default();
    let clients: Vec<IpAddr> = (0..=MAX_CLIENTS)
        .map(|n| IpAddr::V4(Ipv4Addr::new(10, 0, (n / 256) as u8, (n % 256) as u8)))
        .collect();
    for (n, client) in clients.iter().enumerate() {
        // The first device's burst is the oldest.
        let offset = u32::from(n > 0);
        push_all(
            &mut bursts,
            *client,
            &[(offset, "www.news-site.com"), (offset, "cdn.news-site.com")],
        );
    }
    // One more device than the table holds: the oldest burst was closed early, and is a load at
    // the next tick, long before its own quiet gap.
    let loads = bursts.tick(at(2), anything);
    assert_eq!(loads.len(), 1);
    assert_eq!(loads[0].client, clients[0]);
    assert_eq!(bursts.len(), MAX_CLIENTS);

    // A burst keeps MAX_NAMES distinct names, the website included.
    let mut bursts = Bursts::default();
    let a = device(2);
    bursts.push(seen(a, 0, "www.news-site.com"));
    for n in 0..40 {
        bursts.push(seen(a, 1, &format!("n{n}.news-site.com")));
    }
    let loads = bursts.tick(at(100), anything);
    assert_eq!(loads[0].members.len(), MAX_NAMES - 1);

    // Closed bursts waiting for a tick are bounded too: the oldest go, and are counted.
    let mut bursts = Bursts::default();
    let gap = u32::try_from(QUIET + 1).expect("a small gap");
    for n in 0..300 {
        bursts.push(seen(a, n * gap, "www.news-site.com"));
    }
    assert_eq!(bursts.len(), MAX_CLOSED + 1);
    assert_eq!(
        bursts.dropped(),
        u64::try_from(299 - MAX_CLOSED).expect("fits")
    );
    bursts.clear();
    assert!(bursts.is_empty());
}
