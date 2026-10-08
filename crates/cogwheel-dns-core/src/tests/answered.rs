//! `LogEntry::answered_public` (ADR 0002, finding F01): the classifier over every range it
//! refuses and the ones it keeps on purpose, then the flag end to end — a miss computes it from
//! the upstream's answer, a hit and a stale fallback log the one their entry was cached with, and
//! a block, a failure or an empty answer is never public.
//!
//! A child of `tests` so it can drive the same private `Harness` and stub upstream.

use super::*;
use crate::alloc_guard::counted;
use crate::answer::{all_public, is_public};
use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{HTTPS, SVCB, TXT};

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// A response to an A question for `example.com` with `code` and `answers`.
fn response(code: ResponseCode, answers: Vec<Record>) -> Message {
    let mut request = Message::new(1, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(name("example.com"), RecordType::A));
    let mut response = build_base_response(&request, code);
    for record in answers {
        response.add_answer(record);
    }
    response
}

fn v6(owner: &str, address: &str) -> Record {
    aaaa(owner, address.parse().expect("an IPv6 address"))
}

/// An HTTPS record for `owner` whose `ipv4hint` is `hint`: an address, but not an A record.
fn https(owner: &str, hint: [u8; 4]) -> Record {
    let hint = SvcParamValue::Ipv4Hint(IpHint(vec![A(Ipv4Addr::from(hint))]));
    let svcb = SVCB::new(1, Name::root(), vec![(SvcParamKey::Ipv4Hint, hint)]);
    Record::from_rdata(name(owner), 300, RData::HTTPS(HTTPS(svcb)))
}

// --------------------------------------------------------------------- the classifier

/// Each refused range at its edges and somewhere inside, so a mask that is one bit off fails.
#[test]
fn every_private_local_and_reserved_ipv4_range_is_not_public() {
    for address in [
        // 0/8, "this network".
        "0.0.0.0",
        "0.255.255.255",
        // The private ranges.
        "10.0.0.0",
        "10.0.0.5",
        "10.255.255.255",
        "172.16.0.0",
        "172.20.1.1",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.1.30",
        "192.168.255.255",
        // Shared address space, which a provider's CGNAT hands out.
        "100.64.0.0",
        "100.100.100.100",
        "100.127.255.255",
        "127.0.0.1",
        "127.255.255.255",
        "169.254.0.0",
        "169.254.169.254",
        "169.254.255.255",
        // Multicast, then reserved, then broadcast.
        "224.0.0.251",
        "239.255.255.250",
        "240.0.0.1",
        "254.255.255.255",
        "255.255.255.255",
    ] {
        assert!(!is_public(ip(address)), "{address}");
    }
}

#[test]
fn the_addresses_beside_those_ranges_and_the_documentation_ranges_are_public() {
    for address in [
        "1.1.1.1",
        "8.8.8.8",
        "93.184.216.34",
        "9.255.255.255",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "223.255.255.255",
        // Documentation and benchmarking: public on purpose (`answer.rs` says why).
        "192.0.2.1",
        "198.51.100.7",
        "203.0.113.10",
        "198.18.0.1",
        "198.19.255.255",
        "2001:db8::1",
        // Global unicast, and the IPv4-mapped form of a public address.
        "2a00:1450:4001:80b::200e",
        "2606:4700::6810:84e5",
        "fbff:ffff::1",
        "::ffff:93.184.216.34",
        "::ffff:203.0.113.10",
    ] {
        assert!(is_public(ip(address)), "{address}");
    }
}

#[test]
fn every_local_ipv6_range_and_every_embedded_private_ipv4_is_not_public() {
    for address in [
        "::",
        "::1",
        // Unique-local fc00::/7: what a router hands out for the house's own addresses.
        "fc00::1",
        "fd12:3456:789a::5",
        "fdff:ffff:ffff:ffff::1",
        "fe80::1",
        "febf:ffff::1",
        // Site-local, deprecated but still answered by old gear.
        "fec0::1",
        "feff:ffff::1",
        "ff02::fb",
        "ff05::1:3",
        // IPv4-mapped and IPv4-compatible forms of non-public IPv4 addresses.
        "::ffff:10.0.0.5",
        "::ffff:192.168.1.30",
        "::ffff:127.0.0.1",
        "::ffff:100.64.0.1",
        "::ffff:169.254.1.1",
        "::10.0.0.5",
        "::192.168.1.30",
    ] {
        assert!(!is_public(ip(address)), "{address}");
    }
}

/// An answer is public only when it has an address and every address is.
#[test]
fn all_public_needs_at_least_one_address_and_no_private_one() {
    assert!(!all_public(std::iter::empty()));
    assert!(all_public([ip("203.0.113.1"), ip("2001:db8::1")]));
    assert!(!all_public([ip("203.0.113.1"), ip("10.0.0.5")]));
    assert!(!all_public([ip("fd00::5"), ip("2001:db8::1")]));
}

#[test]
fn an_answer_is_public_only_with_noerror_and_every_address_public() {
    let public = || a("example.com", [203, 0, 113, 10]);
    let cases = [
        (
            "one public A",
            response(ResponseCode::NoError, vec![public()]),
            true,
        ),
        (
            "public A and AAAA",
            response(
                ResponseCode::NoError,
                vec![public(), v6("example.com", "2001:db8::10")],
            ),
            true,
        ),
        (
            "an alias to a public address",
            response(
                ResponseCode::NoError,
                vec![
                    cname("example.com", "edge.cdn.net"),
                    a("edge.cdn.net", [198, 51, 100, 7]),
                ],
            ),
            true,
        ),
        (
            "public and private A",
            response(
                ResponseCode::NoError,
                vec![public(), a("example.com", [192, 168, 1, 30])],
            ),
            false,
        ),
        (
            "public and unique-local AAAA",
            response(
                ResponseCode::NoError,
                vec![
                    v6("example.com", "2001:db8::10"),
                    v6("example.com", "fd00::10"),
                ],
            ),
            false,
        ),
        ("NODATA", response(ResponseCode::NoError, vec![]), false),
        (
            "a bare alias",
            response(
                ResponseCode::NoError,
                vec![cname("example.com", "edge.cdn.net")],
            ),
            false,
        ),
        (
            "no address record at all",
            response(
                ResponseCode::NoError,
                vec![Record::from_rdata(
                    name("example.com"),
                    300,
                    RData::TXT(TXT::new(vec!["v=spf1 -all".to_owned()])),
                )],
            ),
            false,
        ),
        // A hint is the publisher's suggestion, not an answer to an address question.
        (
            "an HTTPS record with a public hint",
            response(
                ResponseCode::NoError,
                vec![https("example.com", [203, 0, 113, 10])],
            ),
            false,
        ),
        // Records under an error code are not an answer, whatever they say.
        (
            "NXDOMAIN",
            response(ResponseCode::NXDomain, vec![public()]),
            false,
        ),
        (
            "SERVFAIL",
            response(ResponseCode::ServFail, vec![public()]),
            false,
        ),
        (
            "REFUSED",
            response(ResponseCode::Refused, vec![public()]),
            false,
        ),
    ];
    for (case, message, expected) in cases {
        assert_eq!(answered_public(&message), expected, "{case}");
    }
}

/// It runs once per miss, never per hit, and still costs the allocator nothing.
#[test]
fn classifying_an_answer_allocates_nothing() {
    let message = response(
        ResponseCode::NoError,
        vec![
            cname("example.com", "edge.cdn.net"),
            a("edge.cdn.net", [198, 51, 100, 7]),
            a("edge.cdn.net", [203, 0, 113, 9]),
            v6("edge.cdn.net", "::ffff:203.0.113.9"),
        ],
    );
    assert_eq!(counted(|| answered_public(&message)), 0);
    assert_eq!(counted(|| is_public(ip("fd00::5"))), 0);
}

/// A block is the reviewer's to judge by its verdict, whatever address its block mode answers.
#[test]
fn a_cached_block_is_never_public() {
    let message = response(
        ResponseCode::NoError,
        vec![a("example.com", [203, 0, 113, 10])],
    );
    let allowed =
        CachedWire::from_message(&message, MAX_CACHE_TTL, Verdict::allow(Reason::NoMatch))
            .expect("encode");
    assert!(allowed.answered_public);
    let blocked =
        CachedWire::from_message(&message, MAX_CACHE_TTL, Verdict::Block(Reason::List, 0))
            .expect("encode");
    assert!(!blocked.answered_public);
}

// --------------------------------------------------------------------- end to end

/// What `harness` logs for one query of `owner`.
async fn logged(harness: &mut Harness, owner: &str, qtype: RecordType) -> LogEntry {
    harness.query(owner, qtype).await;
    let entry = harness.next_log().await;
    assert_eq!(&*entry.domain, owner);
    entry
}

/// A miss reads the flag off the upstream's answer: a name the household's own resolver answers
/// with a private address is false, however public its suffix looks.
#[tokio::test]
async fn a_miss_logs_whether_its_answer_was_public() {
    let zone = zone(&[
        (
            "www.shop.test",
            RecordType::A,
            vec![a("www.shop.test", [203, 0, 113, 10])],
        ),
        (
            "nas.home-family.test",
            RecordType::A,
            vec![a("nas.home-family.test", [10, 0, 0, 5])],
        ),
        (
            "mixed.test",
            RecordType::A,
            vec![
                a("mixed.test", [203, 0, 113, 1]),
                a("mixed.test", [192, 168, 1, 30]),
            ],
        ),
        (
            "alias.test",
            RecordType::A,
            vec![
                cname("alias.test", "edge.cdn.test"),
                a("edge.cdn.test", [198, 51, 100, 7]),
            ],
        ),
        (
            "v6.test",
            RecordType::AAAA,
            vec![v6("v6.test", "2001:db8::5")],
        ),
        (
            "ula.test",
            RecordType::AAAA,
            vec![v6("ula.test", "fd00::5")],
        ),
        (
            "www.shop.test",
            RecordType::HTTPS,
            vec![https("www.shop.test", [203, 0, 113, 10])],
        ),
    ]);
    let mut harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;

    for (owner, qtype, expected) in [
        ("www.shop.test", RecordType::A, true),
        ("nas.home-family.test", RecordType::A, false),
        ("mixed.test", RecordType::A, false),
        ("alias.test", RecordType::A, true),
        ("v6.test", RecordType::AAAA, true),
        ("ula.test", RecordType::AAAA, false),
        // NOERROR with nothing in it.
        ("nodata.test", RecordType::A, false),
        // Answered, and with an address in it, but not with an A or AAAA record: an HTTPS lookup
        // is never public, so a name reaches AI review through its address lookups.
        ("www.shop.test", RecordType::HTTPS, false),
    ] {
        let entry = logged(&mut harness, owner, qtype).await;
        assert_eq!(entry.answered_public, expected, "{owner} {qtype}");
        assert_eq!(entry.verdict, Verdict::allow(Reason::NoMatch), "{owner}");
    }
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 0);
}

/// A name that never resolved — a typo, a search-domain guess, a random probe — is never public.
#[tokio::test]
async fn nxdomain_and_servfail_are_never_public() {
    let zone = zone(&[(
        "typo.test",
        RecordType::A,
        vec![a("typo.test", [203, 0, 113, 10])],
    )]);
    let mut harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;

    harness.stub.set_mode(NXDOMAIN);
    let answer = harness.query("typo.test", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
    assert!(!harness.next_log().await.answered_public);

    harness.stub.set_mode(SERVFAIL);
    let answer = harness.query("down.test", RecordType::A).await;
    assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
    assert!(!harness.next_log().await.answered_public);
}

/// A hit logs the flag its entry was cached with, both ways, and a stale answer served through
/// an outage keeps it.
#[tokio::test]
async fn a_cache_hit_and_a_stale_answer_repeat_the_flag_of_their_entry() {
    let zone = zone(&[
        (
            "www.shop.test",
            RecordType::A,
            vec![a("www.shop.test", [203, 0, 113, 10])],
        ),
        (
            "nas.home-family.test",
            RecordType::A,
            vec![a("nas.home-family.test", [10, 0, 0, 5])],
        ),
    ]);
    let mut harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;

    for (owner, expected) in [("www.shop.test", true), ("nas.home-family.test", false)] {
        for _ in 0..2 {
            let entry = logged(&mut harness, owner, RecordType::A).await;
            assert_eq!(entry.answered_public, expected, "{owner}");
        }
        let key = Harness::key(owner, RecordType::A);
        let cached = harness.runtime.cache.get(&key).expect("cached");
        assert_eq!(cached.answered_public, expected, "{owner}");
    }
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 2);

    let key = Harness::key("www.shop.test", RecordType::A);
    harness.expire(&key);
    harness.stub.set_mode(SERVFAIL);
    let entry = logged(&mut harness, "www.shop.test", RecordType::A).await;
    assert_eq!(harness.runtime.snapshot().stale_served_total, 1);
    assert!(entry.answered_public, "the stale answer is the same answer");
}

/// A block is never public, as a miss or as a hit: the reviewer takes it on its verdict.
#[tokio::test]
async fn a_blocked_answer_is_never_public() {
    let zone = zone(&[(
        "alias.test",
        RecordType::A,
        vec![
            cname("alias.test", "tracker.test"),
            a("tracker.test", [203, 0, 113, 9]),
        ],
    )]);
    let mut harness = Harness::start(
        zone,
        policy(&["ads.test", "tracker.test"], &[], HashMap::new()),
    )
    .await;

    for owner in ["ads.test", "ads.test", "alias.test", "alias.test"] {
        let entry = logged(&mut harness, owner, RecordType::A).await;
        assert!(entry.verdict.is_blocked(), "{owner}");
        assert!(!entry.answered_public, "{owner}");
    }
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 2);
}

/// TCP logs the same flag, from a miss it runs inline and from a hit.
#[tokio::test]
async fn a_tcp_answer_logs_the_same_flag() {
    let zone = zone(&[
        (
            "www.shop.test",
            RecordType::A,
            vec![a("www.shop.test", [203, 0, 113, 10])],
        ),
        (
            "nas.home-family.test",
            RecordType::A,
            vec![a("nas.home-family.test", [10, 0, 0, 5])],
        ),
    ]);
    let mut harness = Harness::start(zone, policy(&[], &[], HashMap::new())).await;
    let client: IpAddr = "127.0.0.1".parse().expect("ip");

    for (owner, expected) in [
        ("www.shop.test", true),
        ("www.shop.test", true),
        ("nas.home-family.test", false),
        ("nas.home-family.test", false),
    ] {
        let payload = harness
            .request(owner, RecordType::A, None)
            .to_vec()
            .expect("encode");
        harness
            .runtime
            .answer_tcp(&payload, client)
            .await
            .expect("answered over TCP");
        let entry = harness.next_log().await;
        assert_eq!((&*entry.domain, entry.answered_public), (owner, expected));
    }
    assert_eq!(harness.runtime.snapshot().cache_hits_total, 2);
}
