//! The precedence table of the crate root, exercised end to end.

use crate::*;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

type Entries<'a> = Vec<(Action, Pattern, &'a str)>;

/// One list per slot; each list is `(action, pattern, domain)` entries.
fn index_of(lists: &[Entries<'_>]) -> Arc<ListIndex> {
    let mut builder = ListIndex::builder();
    for (slot, entries) in lists.iter().enumerate() {
        let slot = u8::try_from(slot).expect("test lists fit in 64 slots");
        builder.name(slot, format!("list {slot}"));
        for (action, pattern, domain) in entries {
            builder.insert(slot, *action, *pattern, domain);
        }
    }
    Arc::new(builder.build())
}

fn blocklist<'a>(domains: &[&'a str]) -> Entries<'a> {
    domains
        .iter()
        .map(|domain| (Action::Block, Pattern::Suffix, *domain))
        .collect()
}

fn rules(entries: &[(&str, Action)]) -> Arc<RuleSet> {
    Arc::new(entries.iter().map(|(d, a)| (*d, *a)).collect())
}

fn all_mask(lists: usize) -> u64 {
    (1u64 << lists) - 1
}

/// A policy with only lists: the household scope sees every slot.
fn list_policy(lists: &[Entries<'_>]) -> Policy {
    Policy::new(
        index_of(lists),
        Arc::new(RuleSet::new()),
        HashMap::new(),
        all_mask(lists.len()),
        BlockMode::NullIp,
    )
}

fn household_verdict(policy: &Policy, name: &str) -> Verdict {
    evaluate(policy, policy.scope(SCOPE_HOUSEHOLD), name)
}

/// The gap this closes: a blocklist covering an OCSP responder or an NTP
/// pool could take a device off the network.
#[test]
fn a_protected_domain_outranks_a_blocklist_entry() {
    let policy = list_policy(&[blocklist(&["letsencrypt.org"])]);
    assert_eq!(
        household_verdict(&policy, "letsencrypt.org"),
        Verdict::allow(Reason::Protected)
    );
}

/// Protection used to be an exact match, so the apex was covered and every
/// name actually looked up during certificate validation was not.
#[test]
fn protection_covers_subdomains_not_just_the_apex() {
    let policy = list_policy(&[blocklist(&["letsencrypt.org"])]);
    for host in ["r3.letsencrypt.org", "ocsp.int-x3.letsencrypt.org"] {
        assert_eq!(
            household_verdict(&policy, host),
            Verdict::allow(Reason::Protected),
            "{host} should be protected"
        );
    }
}

/// Suffix matching must stop at a label boundary, or protecting
/// `apple.com` would quietly protect `evil-apple.com` too.
#[test]
fn protection_stops_at_a_label_boundary() {
    let policy = list_policy(&[blocklist(&["notapple.com", "evil-apple.com"])]);
    for host in ["notapple.com", "evil-apple.com"] {
        assert!(
            household_verdict(&policy, host).is_blocked(),
            "{host} must NOT inherit protection from apple.com"
        );
    }
}

#[test]
fn an_unprotected_domain_is_still_blocked_normally() {
    let policy = list_policy(&[blocklist(&["doubleclick.net"])]);
    assert_eq!(
        household_verdict(&policy, "ads.doubleclick.net"),
        Verdict::Block(Reason::List, 0)
    );
}

/// Suffix matching must only match on a label boundary, and must not allocate to do it.
#[test]
fn suffix_entries_match_only_on_label_boundaries() {
    let policy = list_policy(&[blocklist(&["example.com"])]);
    for blocked in ["example.com", "ads.example.com", "a.b.example.com"] {
        assert!(
            household_verdict(&policy, blocked).is_blocked(),
            "{blocked} should match the suffix entry"
        );
    }
    for allowed in ["notexample.com", "example.com.evil.net", "myexample.com"] {
        assert_eq!(
            household_verdict(&policy, allowed),
            Verdict::allow(Reason::NoMatch),
            "{allowed} must NOT match the suffix entry"
        );
    }
}

/// A hosts-file line names one host; its subdomains are not implied.
#[test]
fn exact_entries_do_not_cover_subdomains() {
    let policy = list_policy(&[vec![(Action::Block, Pattern::Exact, "ads.example.com")]]);
    assert!(household_verdict(&policy, "ads.example.com").is_blocked());
    assert!(!household_verdict(&policy, "www.ads.example.com").is_blocked());
    assert!(!household_verdict(&policy, "example.com").is_blocked());
}

#[test]
fn allow_precedes_block() {
    let policy = list_policy(&[vec![
        (Action::Block, Pattern::Suffix, "ads.example.com"),
        (Action::Allow, Pattern::Exact, "ads.example.com"),
    ]]);
    assert_eq!(
        household_verdict(&policy, "ads.example.com"),
        Verdict::Allow(Reason::ListAllow, 0)
    );

    // The exception must name the list it came from, not slot 0 by default: "why is this
    // allowed?" is only a useful answer when it says which list let the name through.
    let policy = list_policy(&[
        blocklist(&["ads.example.com"]),
        vec![(Action::Allow, Pattern::Suffix, "ads.example.com")],
    ]);
    assert_eq!(
        household_verdict(&policy, "ads.example.com"),
        Verdict::Allow(Reason::ListAllow, 1)
    );

    let household = rules(&[
        ("example.com", Action::Allow),
        ("ads.example.com", Action::Block),
    ]);
    let policy = Policy::new(
        Arc::new(ListIndex::default()),
        household,
        HashMap::new(),
        0,
        BlockMode::NullIp,
    );
    assert_eq!(
        household_verdict(&policy, "ads.example.com"),
        Verdict::allow(Reason::HouseholdRule)
    );
}

/// The fixed precedence: pause → filtering off → device rules → household rules →
/// protected → list allow → list block → allow.
#[test]
fn precedence_table() {
    // Slot 0 blocks broadly (including a protected name); slot 1 carries the exceptions.
    let index = index_of(&[
        blocklist(&[
            "pool.ntp.org",
            "tracker.example",
            "example.com",
            "shared.example",
            "ads.example",
        ]),
        vec![
            (Action::Allow, Pattern::Suffix, "cdn.ads.example"),
            (Action::Block, Pattern::Suffix, "shared.example"),
        ],
    ]);
    let household = rules(&[
        ("pool.ntp.org", Action::Block),
        ("tracker.example", Action::Allow),
        ("home.example", Action::Block),
    ]);
    let device_rules = rules(&[
        ("home.example", Action::Allow),
        ("time.apple.com", Action::Block),
    ]);
    let device = Scope {
        id: 2,
        filtering: true,
        mask: 0b01,
        rules: Some(device_rules),
    };
    let mut by_ip = HashMap::new();
    by_ip.insert(CLIENT, device);
    let policy = Policy::new(index, household, by_ip, 0b11, BlockMode::NxDomain);
    let household_scope = policy.scope(SCOPE_HOUSEHOLD);
    let device_scope = policy.scope_for(CLIENT);
    let unfiltered = policy.scope(SCOPE_UNFILTERED);

    let table: &[(&Scope, &str, Verdict)] = &[
        // device block beats protected
        (
            device_scope,
            "ntp.time.apple.com",
            Verdict::Block(Reason::DeviceRule, 0),
        ),
        // device allow beats household block
        (
            device_scope,
            "home.example",
            Verdict::allow(Reason::DeviceRule),
        ),
        (
            household_scope,
            "home.example",
            Verdict::Block(Reason::HouseholdRule, 0),
        ),
        // household block beats protected
        (
            household_scope,
            "pool.ntp.org",
            Verdict::Block(Reason::HouseholdRule, 0),
        ),
        // household allow beats a list block
        (
            household_scope,
            "tracker.example",
            Verdict::allow(Reason::HouseholdRule),
        ),
        // protected beats a list block
        (
            household_scope,
            "time.google.com",
            Verdict::allow(Reason::Protected),
        ),
        (
            device_scope,
            "time.google.com",
            Verdict::allow(Reason::Protected),
        ),
        // list @@ beats a list block, and names the list that carried the exception
        (
            household_scope,
            "cdn.ads.example",
            Verdict::Allow(Reason::ListAllow, 1),
        ),
        (
            household_scope,
            "ads.example",
            Verdict::Block(Reason::List, 0),
        ),
        // ...unless the mask excludes the slot carrying the exception
        (
            device_scope,
            "cdn.ads.example",
            Verdict::Block(Reason::List, 0),
        ),
        // a block is attributed to the lowest slot inside the mask
        (
            household_scope,
            "shared.example",
            Verdict::Block(Reason::List, 0),
        ),
        // a suffix entry covers subdomains but not a longer-label lookalike
        (
            household_scope,
            "www.example.com",
            Verdict::Block(Reason::List, 0),
        ),
        (
            household_scope,
            "notexample.com",
            Verdict::allow(Reason::NoMatch),
        ),
        // the unfiltered scope allows everything without probing
        (
            unfiltered,
            "pool.ntp.org",
            Verdict::allow(Reason::Unfiltered),
        ),
        (
            unfiltered,
            "tracker.example",
            Verdict::allow(Reason::Unfiltered),
        ),
        (
            unfiltered,
            "home.example",
            Verdict::allow(Reason::Unfiltered),
        ),
    ];
    for (scope, name, expected) in table {
        assert_eq!(
            evaluate(&policy, scope, name),
            *expected,
            "{name} in scope {}",
            scope.id
        );
    }
}

#[test]
fn a_mask_excludes_a_slot_and_attribution_skips_it() {
    let policy = list_policy(&[blocklist(&["ads.example"]), blocklist(&["ads.example"])]);
    assert_eq!(
        evaluate_lists(&policy, 0b11, "ads.example"),
        Verdict::Block(Reason::List, 0)
    );
    assert_eq!(
        evaluate_lists(&policy, 0b10, "ads.example"),
        Verdict::Block(Reason::List, 1)
    );
    assert_eq!(
        evaluate_lists(&policy, 0, "ads.example"),
        Verdict::allow(Reason::NoMatch)
    );
    assert_eq!(policy.index.name(1).map(|n| &**n), Some("list 1"));
    assert_eq!(policy.index.name(2), None);
}

#[test]
fn reserved_and_unknown_scope_ids_resolve() {
    let policy = list_policy(&[blocklist(&["ads.example"])]);
    assert_eq!(policy.scope(SCOPE_HOUSEHOLD).mask, 0b1);
    assert!(policy.scope(SCOPE_HOUSEHOLD).filtering);
    assert!(!policy.scope(SCOPE_UNFILTERED).filtering);
    assert_eq!(policy.scope(99).id, SCOPE_HOUSEHOLD);
    assert_eq!(policy.scope_for(CLIENT).id, SCOPE_HOUSEHOLD);
    assert!(!evaluate(&policy, policy.scope(SCOPE_UNFILTERED), "ads.example").is_blocked());
}

#[test]
fn an_empty_policy_allows_everything() {
    let policy = Policy::empty(BlockMode::Refused);
    assert_eq!(
        household_verdict(&policy, "ads.example"),
        Verdict::allow(Reason::NoMatch)
    );
    assert!(policy.index.is_empty());
    assert_eq!(policy.block_mode, BlockMode::Refused);
}

#[test]
fn a_trailing_root_dot_is_tolerated_on_lookup() {
    let policy = list_policy(&[blocklist(&["ads.example"])]);
    assert!(household_verdict(&policy, "ads.example.").is_blocked());
    assert!(evaluate_lists(&policy, u64::MAX, "www.ads.example.").is_blocked());
}

#[test]
fn verdict_slot_is_only_reported_for_list_tiers() {
    assert_eq!(Verdict::Block(Reason::List, 3).slot(), Some(3));
    assert_eq!(Verdict::Block(Reason::Cname, 3).slot(), Some(3));
    assert_eq!(Verdict::Allow(Reason::ListAllow, 3).slot(), Some(3));
    assert_eq!(Verdict::Block(Reason::DeviceRule, 0).slot(), None);
    assert_eq!(Verdict::allow(Reason::NoMatch).slot(), None);
    assert_eq!(Verdict::Block(Reason::Cname, 3).reason(), Reason::Cname);
}

#[test]
fn reason_round_trips_through_its_stored_form() {
    for value in 0..=8u8 {
        let reason = Reason::from_u8(value).expect("every code below 9 is a reason");
        assert_eq!(reason.as_u8(), value);
        assert_eq!(
            serde_json::to_string(&reason).expect("serialises"),
            format!("\"{}\"", reason.as_str())
        );
    }
    assert_eq!(Reason::from_u8(9), None);
}

#[test]
fn rule_set_upserts_and_walks_boundaries() {
    let mut set = RuleSet::new();
    assert_eq!(set.insert("example.com", Action::Block), None);
    assert_eq!(
        set.insert("example.com", Action::Allow),
        Some(Action::Block)
    );
    assert_eq!(set.len(), 1);
    assert_eq!(set.get("example.com"), Some(Action::Allow));
    assert_eq!(set.get("www.example.com"), None);
    assert_eq!(
        set.get_at_boundaries("www.example.com"),
        Some(Action::Allow)
    );
    assert_eq!(set.get_at_boundaries("notexample.com"), None);
    assert_eq!(set.iter().count(), 1);
}

#[test]
fn deep_names_still_match_short_rules() {
    let deep = "a.".repeat(40) + "example.com";
    let policy = list_policy(&[blocklist(&["example.com"])]);
    assert!(household_verdict(&policy, &deep).is_blocked());
    assert!(is_protected(&("x.".repeat(30) + "pool.ntp.org")));
}

#[test]
fn slots_beyond_the_mask_width_are_ignored() {
    let mut builder = ListIndex::builder();
    builder.insert(64, Action::Block, Pattern::Suffix, "ads.example");
    builder.name(64, "overflow");
    let index = builder.build();
    assert!(index.is_empty());
    assert!(index.names().is_empty());
}

#[test]
fn normalisation() {
    assert_eq!(normalize_domain("  Example.COM. "), "example.com");
    assert_eq!(normalize_rule_domain("*.Example.com"), "example.com");
    assert_eq!(normalize_rule_domain("example.com"), "example.com");
    assert_eq!("nxdomain".parse::<BlockMode>(), Ok(BlockMode::NxDomain));
    assert_eq!(BlockMode::NullIp.as_str(), "null_ip");
    assert_eq!("block".parse::<Action>(), Ok(Action::Block));
    assert_eq!(
        serde_json::to_string(&BlockMode::NoData).expect("serialises"),
        "\"nodata\""
    );
    assert_eq!(
        serde_json::to_string(&Action::Allow).expect("serialises"),
        "\"allow\""
    );
}

/// The shape check §3 route 14 fixes, moved here with the predicate so `POST /rules` and
/// `GET /check` cannot drift apart over what counts as a domain.
#[test]
fn a_pasted_wildcard_rule_normalises_to_its_domain() {
    assert_eq!(
        normalize_rule_domain("*.ads.example.com"),
        "ads.example.com"
    );
    assert!(is_domain_shaped(&normalize_rule_domain(
        "*.ads.example.com"
    )));
}

#[test]
fn things_that_are_not_domains_are_refused() {
    for input in [
        "",
        "localhost",
        "example..com",
        "http://example.com",
        "192.168.1.1:53",
        "exa mple.com",
        ".example.com",
        "not a domain",
    ] {
        assert!(
            !is_domain_shaped(&normalize_rule_domain(input)),
            "{input:?} should not be accepted as a domain"
        );
    }
}

#[test]
fn punycode_digits_and_discovery_labels_pass() {
    assert!(is_domain_shaped("xn--bcher-kva.example"));
    assert!(is_domain_shaped("s3-1.eu-west-2.amazonaws.com"));
    // Names every current stub resolver asks for; they reach the query log, so a person has to
    // be able to ask "why?" about them and to write a rule for them.
    assert!(is_domain_shaped("_dns.resolver.arpa"));
    assert!(is_domain_shaped("_dmarc.example.com"));
}
