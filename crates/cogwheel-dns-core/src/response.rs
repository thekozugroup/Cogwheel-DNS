//! Wire-format answers: the builders every response goes through, and the TTL
//! clamp that decides how long an upstream answer stays fresh in the cache.

use cogwheel_policy::BlockMode;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Never cache for less than this, however small the record's TTL.
///
/// Some CDNs answer with a TTL of 0 or 1 second. Honouring that literally
/// turns every page load into a fresh upstream query per name, which on an
/// encrypted upstream means a TLS round trip on the critical path.
pub(crate) const MIN_CACHE_TTL: Duration = Duration::from_secs(5);

/// Never cache for longer than this, however large the record's TTL.
///
/// Some records advertise a day or more. Holding an address that long on an
/// appliance nobody restarts is how a household ends up pinned to a decommissioned
/// server, so this bounds the worst case regardless of what upstream claims.
pub(crate) const MAX_CACHE_TTL: Duration = Duration::from_secs(3_600);

/// Lifetime for a response carrying no answer records.
///
/// NXDOMAIN and NODATA get a shorter life than a positive answer: a name that
/// does not exist yet is far more likely to start existing than a live address
/// is to change, and caching "this does not exist" for an hour is how a
/// newly-provisioned host stays unreachable long after it came up.
pub(crate) const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Lifetime for a blocked answer.
///
/// A block never goes stale the way an address does: the verdict only changes
/// when the policy changes, and every policy change that can flip a verdict
/// empties the cache. Five minutes keeps the entry from occupying a slot for
/// ever on a name the household asked once.
pub(crate) const BLOCKED_CACHE_TTL: Duration = Duration::from_secs(300);

/// How long a response may be cached, from the records it actually contains.
///
/// The minimum TTL across the answer section, clamped. The minimum rather than
/// the maximum because a response is only wholly valid until its shortest-lived
/// record expires.
pub(crate) fn cacheable_for(response: &Message) -> Duration {
    response
        .answers
        .iter()
        .map(|record| record.ttl)
        .min()
        .map_or(NEGATIVE_CACHE_TTL, |ttl| {
            Duration::from_secs(u64::from(ttl)).clamp(MIN_CACHE_TTL, MAX_CACHE_TTL)
        })
}

/// SERVFAIL for a request that parsed, echoing its id and opcode so the client can match it.
pub(crate) fn servfail(request: &Message) -> Message {
    Message::error_msg(
        request.metadata.id,
        request.metadata.op_code,
        ResponseCode::ServFail,
    )
}

/// SERVFAIL for a datagram whose handling blew up after it was received.
pub(crate) fn error_response_for_payload(payload: &[u8]) -> Message {
    match Message::from_vec(payload) {
        Ok(request) => servfail(&request),
        Err(_) => Message::error_msg(0, OpCode::Query, ResponseCode::ServFail),
    }
}

pub(crate) fn build_base_response(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    // We are a forwarder, never the zone's authority, and we always accept recursion. The RD bit is
    // echoed from the request because RFC 1035 requires the response to mirror it.
    response.metadata.authoritative = false;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    // Assigned rather than merged: `merge_response_code` folds in the EDNS high-order bits, which
    // would change what a blocked answer reports.
    response.metadata.response_code = code;
    for query in &request.queries {
        response.add_query(query.clone());
    }
    response
}

/// The answer a blocked name gets, per the policy's mode.
///
/// `null_ip` is the only mode that fills the answer section, and it answers the all-zeros address
/// of the family that was asked for — any other record type gets NOERROR with nothing, because
/// there is no "this is blocked" value to put in an MX or a TXT. The one-minute TTL is a stub's
/// memory of the block, short so that unblocking a name is visible in about a minute rather than
/// for however long a client decided to hold it.
pub(crate) fn build_blocked_response(request: &Message, mode: BlockMode) -> Message {
    let code = match mode {
        BlockMode::NxDomain => ResponseCode::NXDomain,
        BlockMode::Refused => ResponseCode::Refused,
        BlockMode::NullIp | BlockMode::NoData => ResponseCode::NoError,
    };
    let mut response = build_base_response(request, code);
    if mode == BlockMode::NullIp {
        for query in &request.queries {
            let unspecified = match query.query_type() {
                RecordType::A => RData::A(A(Ipv4Addr::UNSPECIFIED)),
                RecordType::AAAA => RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                _ => continue,
            };
            response.add_answer(Record::from_rdata(query.name().clone(), 60, unspecified));
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CachedWire;
    use cogwheel_policy::{Reason, Verdict};
    use hickory_proto::op::{MessageType, Query};
    use hickory_proto::rr::Name;
    use std::time::Instant;

    fn response_with_ttls(ttls: &[u32]) -> Message {
        let mut message = Message::query();
        let name = Name::from_ascii("example.com.").expect("name");
        for ttl in ttls {
            message.add_answer(Record::from_rdata(
                name.clone(),
                *ttl,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
            ));
        }
        message
    }

    /// The shortest-lived record decides: a response is only wholly valid
    /// until its first record expires.
    #[test]
    fn cache_lifetime_follows_the_smallest_record_ttl() {
        assert_eq!(
            cacheable_for(&response_with_ttls(&[300, 60, 900])),
            Duration::from_secs(60)
        );
        assert_eq!(
            cacheable_for(&response_with_ttls(&[120])),
            Duration::from_secs(120)
        );
    }

    /// A CDN answering with TTL 0 or 1 would otherwise mean an upstream query
    /// per name per page load -- a TLS round trip each, on DoT.
    #[test]
    fn a_tiny_ttl_is_raised_to_the_floor() {
        assert_eq!(cacheable_for(&response_with_ttls(&[0])), MIN_CACHE_TTL);
        assert_eq!(cacheable_for(&response_with_ttls(&[1])), MIN_CACHE_TTL);
    }

    /// Bounds the worst case: an appliance nobody restarts must not pin the
    /// household to an address for a day because a record said so.
    #[test]
    fn a_huge_ttl_is_capped_at_the_ceiling() {
        assert_eq!(cacheable_for(&response_with_ttls(&[86_400])), MAX_CACHE_TTL);
        assert_eq!(
            cacheable_for(&response_with_ttls(&[u32::MAX])),
            MAX_CACHE_TTL
        );
    }

    /// NXDOMAIN and NODATA carry no answers. Caching "does not exist" for an
    /// hour keeps a freshly-provisioned host unreachable long after it is up.
    #[test]
    fn a_response_with_no_answers_uses_the_shorter_negative_lifetime() {
        assert_eq!(cacheable_for(&response_with_ttls(&[])), NEGATIVE_CACHE_TTL);
        assert!(NEGATIVE_CACHE_TTL < MAX_CACHE_TTL);
    }

    /// The regression this whole change exists for: before it, nothing in the
    /// DNS path read a TTL at all, and an entry lived until 10,000 other names
    /// evicted it.
    #[test]
    fn every_cached_entry_has_a_deadline_in_the_future_but_bounded() {
        let response = response_with_ttls(&[300]);
        let lifetime = cacheable_for(&response);
        assert!(lifetime >= MIN_CACHE_TTL && lifetime <= MAX_CACHE_TTL);
        let entry = CachedWire::from_message(&response, lifetime, Verdict::allow(Reason::NoMatch))
            .expect("encode");
        assert!(entry.fresh_until > Instant::now());
        assert!(entry.fresh_until <= Instant::now() + MAX_CACHE_TTL);
    }

    #[test]
    fn error_response_uses_original_request_id() {
        let mut request = Message::new(17, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("example.com").expect("valid test name"),
            RecordType::A,
        ));
        let response = error_response_for_payload(&request.to_vec().expect("wire request"));
        assert_eq!(response.metadata.id, request.metadata.id);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }

    /// Every block mode answers the question it was asked, and only `null_ip`
    /// puts an address in the answer section.
    #[test]
    fn blocked_responses_echo_the_question_and_answer_per_mode() {
        let mut request = Message::new(9, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("ads.example.com").expect("valid test name"),
            RecordType::A,
        ));

        let null_ip = build_blocked_response(&request, BlockMode::NullIp);
        assert_eq!(null_ip.metadata.response_code, ResponseCode::NoError);
        assert!(matches!(
            null_ip.answers.first().map(|record| &record.data),
            Some(RData::A(A(address))) if address.is_unspecified()
        ));

        for (mode, code) in [
            (BlockMode::NxDomain, ResponseCode::NXDomain),
            (BlockMode::NoData, ResponseCode::NoError),
            (BlockMode::Refused, ResponseCode::Refused),
        ] {
            let response = build_blocked_response(&request, mode);
            assert_eq!(response.metadata.response_code, code, "{mode:?}");
            assert!(response.answers.is_empty(), "{mode:?}");
            assert_eq!(response.queries, request.queries, "{mode:?}");
        }
    }
}
