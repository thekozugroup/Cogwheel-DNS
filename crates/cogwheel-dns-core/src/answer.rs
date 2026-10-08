//! What a miss reads out of the upstream's answer besides its bytes: whether an alias in it is one
//! the lists block (the CNAME re-check, §6 step 12), and whether the addresses it gave are all
//! public ones ([`crate::LogEntry::answered_public`]).
//!
//! Both read the answer section the miss already holds, once, before the answer is cached; a hit
//! never looks at either again.

use cogwheel_policy::{Policy, Reason, Verdict, evaluate_lists, normalize_domain};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// CNAME targets checked per upstream answer.
const MAX_CNAME_TARGETS: usize = 8;

/// A list-tier block for any CNAME target in `answers`, attributed to [`Reason::Cname`].
///
/// Read from the answer the upstream already returned, so the check costs no round trip. Only
/// the list tier applies: a user's rule names the query, not the aliases behind it.
pub(crate) fn cname_block(policy: &Policy, mask: u64, answers: &[Record]) -> Option<Verdict> {
    answers
        .iter()
        .filter_map(cname_target)
        .take(MAX_CNAME_TARGETS)
        .find_map(|target| {
            let target = normalize_domain(&target.to_ascii());
            match evaluate_lists(policy, mask, &target) {
                Verdict::Block(_, slot) => Some(Verdict::Block(Reason::Cname, slot)),
                Verdict::Allow(..) => None,
            }
        })
}

pub(crate) fn cname_target(record: &Record) -> Option<&Name> {
    match &record.data {
        RData::CNAME(target) => Some(&target.0),
        _ => None,
    }
}

/// Whether `response` is a NOERROR answer whose answer section holds at least one A or AAAA
/// address, every one of them public by [`is_public`].
///
/// False for NXDOMAIN, SERVFAIL and every other error, for NODATA, and for an answer of another
/// type (HTTPS, TXT, a bare CNAME) — so a name that never resolved, or resolved to nothing a
/// browser connects to, is never taken for a public one. One private address among public ones
/// makes the whole answer false. Walks the records once and allocates nothing.
pub(crate) fn answered_public(response: &Message) -> bool {
    response.metadata.response_code == ResponseCode::NoError
        && all_public(response.answers.iter().filter_map(address))
}

/// Whether `addresses` holds at least one address and every one is public.
pub(crate) fn all_public(addresses: impl IntoIterator<Item = IpAddr>) -> bool {
    let mut any = false;
    for address in addresses {
        if !is_public(address) {
            return false;
        }
        any = true;
    }
    any
}

/// The address an A or AAAA record carries.
fn address(record: &Record) -> Option<IpAddr> {
    match record.data {
        RData::A(A(address)) => Some(IpAddr::V4(address)),
        RData::AAAA(AAAA(address)) => Some(IpAddr::V6(address)),
        _ => None,
    }
}

/// Whether `address` could be a host on the internet rather than one inside the house, the
/// provider's network or this machine.
///
/// Not public: for IPv4 `0.0.0.0/8`, the private `10/8`, `172.16/12` and `192.168/16`, the shared
/// (CGNAT) `100.64/10`, loopback `127/8`, link-local `169.254/16`, multicast `224/4` and the
/// reserved `240/4` with the broadcast address in it; for IPv6 `::`, `::1`, unique-local
/// `fc00::/7`, link-local `fe80::/10`, the deprecated site-local `fec0::/10`, multicast `ff00::/8`,
/// and an IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`) address whose IPv4 is
/// not public.
///
/// Public on purpose: the documentation and benchmarking ranges (`192.0.2/24`, `198.51.100/24`,
/// `203.0.113/24`, `198.18/15`, `2001:db8::/32`). No household names a device in them, and every
/// stub upstream in the test suites and the benchmarks answers with them.
pub(crate) fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => public_v4(address),
        IpAddr::V6(address) => public_v6(address),
    }
}

fn public_v4(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    let this_network = first == 0;
    let shared = first == 100 && second & 0xc0 == 0x40;
    // 224/4 is multicast and 240/4 reserved, 255.255.255.255 included: everything from 224 up.
    let multicast_or_reserved = first >= 224;
    !(this_network
        || address.is_private()
        || shared
        || address.is_loopback()
        || address.is_link_local()
        || multicast_or_reserved)
}

fn public_v6(address: Ipv6Addr) -> bool {
    if address.is_unspecified() || address.is_loopback() {
        return false;
    }
    // Mapped and compatible forms are the IPv4 address they carry.
    if let Some(embedded) = address.to_ipv4() {
        return public_v4(embedded);
    }
    let [first, ..] = address.segments();
    let unique_local = first & 0xfe00 == 0xfc00;
    let link_local = first & 0xffc0 == 0xfe80;
    let site_local = first & 0xffc0 == 0xfec0;
    !(unique_local || link_local || site_local || address.is_multicast())
}
