//! A counting allocator, so the hot path's allocations can be asserted rather than described.
//!
//! A `#[global_allocator]` is a crate-wide decision and gets a file of its own for that reason.
//! This one is `#[cfg(test)]`, so it is installed in the unit-test binary and nowhere else.
//!
//! It counts per thread, not globally: `cargo test` runs tests in parallel, and a global counter
//! would be measuring whatever else the binary happened to be doing at the time. A test that
//! measures with [`counted`] must therefore do its work on the thread it measures from — which
//! for an async test means a `current_thread` runtime and no `await` inside the measured block,
//! since nothing else can then run in the middle of it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    /// Allocations this thread has made. Never reset; tests read the difference.
    ///
    /// `const`-initialised and holding a `Cell<usize>`, which has no destructor: the allocator
    /// runs before and after everything, and a thread-local that allocated to initialise itself
    /// or registered a destructor would be re-entering the allocator from inside it.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

/// How many allocations `work` made on this thread.
pub(crate) fn counted<T>(work: impl FnOnce() -> T) -> usize {
    let before = ALLOCATIONS.with(Cell::get);
    let value = work();
    let after = ALLOCATIONS.with(Cell::get);
    drop(value);
    after - before
}

/// The system allocator, plus one counter increment per allocation.
struct Counting;

/// Resizes count as allocations: a `Vec` that grows has taken memory it did not have, whether or
/// not the system managed it in place.
#[global_allocator]
static COUNTING: Counting = Counting;

// SAFETY: every method forwards to `System` with the layout it was given; the counter is a
// thread-local `Cell<usize>` and allocates nothing itself.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        bump();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        bump();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump();
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// `try_with` rather than `with`: a thread tearing down its locals must not panic inside the
/// allocator, whatever the counter is worth by then.
fn bump() {
    let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
mod tests {
    use super::counted;
    use crate::response::{BLOCKED_CACHE_TTL, build_blocked_response};
    use crate::serve::wire_for;
    use crate::tests::{name, policy, resolver_for};
    use crate::{CacheKey, CachedWire, DnsRuntime, Probe};
    use cogwheel_policy::{BlockMode, Reason, SCOPE_HOUSEHOLD, Verdict};
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::RecordType;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Instant;

    /// What one cache hit allocates, counted rather than asserted about.
    ///
    /// The hit path is a parse, a probe and a memcpy, and this is the whole of what it takes from the
    /// allocator. It replaces a test that grepped these functions for `to_string` and `format!` and
    /// passed while `admit` was building a `String` per query anyway: a name spelled with `to_ascii`
    /// is a `String` neither pattern matches. A number that goes up here is a regression the
    /// benchmarks would take a release to notice.
    #[tokio::test(flavor = "current_thread")]
    async fn one_cache_hit_makes_three_allocations() {
        let (runtime, _log_rx) = DnsRuntime::new(
            resolver_for("127.0.0.1:1".parse().expect("addr")),
            policy(&["ads.test"], &[], HashMap::new()),
        );
        let client: IpAddr = "10.0.0.4".parse().expect("ip");
        let mut request = Message::new(1, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name("ads.test"), RecordType::A));
        let payload = request.to_vec().expect("encode");
        // Seeded by hand: the miss that would otherwise put it there is not what is being measured.
        let blocked = build_blocked_response(&request, BlockMode::NullIp);
        let wire =
            CachedWire::from_message(&blocked, BLOCKED_CACHE_TTL, Verdict::Block(Reason::List, 0))
                .expect("encode");
        let key = CacheKey {
            scope: SCOPE_HOUSEHOLD,
            qtype: u16::from(RecordType::A),
            domain: Arc::from("ads.test"),
        };
        runtime.cache.insert(key, Arc::new(wire));

        let hit = || {
            let admitted = runtime
                .admit(&payload, client, Instant::now())
                .expect("a well-formed query is admitted");
            let Probe::Hit(entry) = runtime.probe(&admitted.key, Instant::now()) else {
                unreachable!("the entry was just seeded");
            };
            runtime.count_hit(&entry);
            let bytes = wire_for(&entry, &admitted.request, admitted.edns_max);
            runtime.log(&admitted, entry.verdict);
            bytes
        };
        // The first hit also pays for what the path allocates once and then keeps — the log
        // channel's first block of slots — so the hit that is counted is the second.
        let first = counted(hit);
        let steady = counted(hit);
        assert!(first >= steady, "first hit {first}, steady hit {steady}");
        assert_eq!(
            steady, 3,
            "a cache hit allocates the parsed question, the name the key and the log entry share, \
             and the answer's bytes — nothing else"
        );
    }
}
