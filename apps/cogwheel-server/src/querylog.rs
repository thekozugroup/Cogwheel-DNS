//! The query-log writer and the live event bus (§7).
//!
//! One task owns everything that happens after a query is answered. The hot path hands entries
//! over with `try_send` and never waits, so a slow SD card shows up as `log_dropped_total` and
//! never as DNS latency. Rows are batched into one transaction every five seconds; the hourly
//! rollups in that same transaction are what every count in the UI is read from, so a cleared
//! log or a pruned week never changes the numbers on the Overview.

use crate::state::ServerState;
use cogwheel_dns_core::LogEntry;
use cogwheel_policy::Reason;
use cogwheel_storage::QueryLogEntry;
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

/// Upper bound on simultaneous SSE subscribers.
///
/// Each connection holds a broadcast receiver and a task. A household needs one or two; the cap
/// exists so a misbehaving client cannot open thousands and exhaust the appliance's memory.
pub const MAX_EVENT_SUBSCRIBERS: usize = 32;

/// Buffered events per subscriber before the slowest one starts missing frames.
///
/// A slow reader lags rather than applying backpressure to the DNS path: losing display frames
/// is always preferable to slowing resolution.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Entries taken off the channel in one go.
///
/// The same figure as [`FLUSH_ROWS`] so the buffer is bounded by construction: a receive can add
/// at most one drain to a batch that was under the flush threshold, which caps `pending` just
/// under two batches — about 100 KB — however fast the hot path is feeding it.
const DRAIN_BATCH: usize = FLUSH_ROWS;

/// Rows that force a flush before the timer would (§7).
const FLUSH_ROWS: usize = 500;

/// How often the batch is written even when it is short.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// One answered query, as the live stream publishes it.
///
/// The only camelCase payload on the wire, because this is the one frame the UI consumes
/// directly rather than through a typed table.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamQueryEvent {
    pub ts: i64,
    pub client: String,
    pub device_name: Option<String>,
    pub domain: String,
    pub qtype: u16,
    pub blocked: bool,
    pub reason: Reason,
    pub list: Option<String>,
}

/// Fan-out for the live query stream, with a bounded subscriber count.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Arc<StreamQueryEvent>>,
    subscribers: Arc<AtomicUsize>,
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("subscribers", &self.subscribers.load(Ordering::Relaxed))
            .finish()
    }
}

impl EventBus {
    /// A bus with no subscribers.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            sender,
            subscribers: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Whether anyone is listening. Frames are only built when this is true.
    pub fn listening(&self) -> bool {
        self.sender.receiver_count() > 0
    }

    /// Publish a frame. Never blocks and never fails: with no subscribers the send is a no-op.
    pub fn publish(&self, event: StreamQueryEvent) {
        let _ = self.sender.send(Arc::new(event));
    }

    /// Take a subscriber slot, or `None` when [`MAX_EVENT_SUBSCRIBERS`] are already connected.
    ///
    /// The guard is what releases the slot: an SSE handler returns as soon as the stream is
    /// constructed, so teardown cannot live in the handler body.
    pub fn subscribe(
        &self,
    ) -> Option<(broadcast::Receiver<Arc<StreamQueryEvent>>, SubscriberGuard)> {
        let previous = self.subscribers.fetch_add(1, Ordering::Relaxed);
        if previous >= MAX_EVENT_SUBSCRIBERS {
            self.subscribers.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some((
            self.sender.subscribe(),
            SubscriberGuard(Arc::clone(&self.subscribers)),
        ))
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// A subscriber slot, released when the stream it belongs to is dropped.
#[derive(Debug)]
pub struct SubscriberGuard(Arc<AtomicUsize>);

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Drain answered queries into the live stream and the database, forever (§7).
pub async fn writer(state: ServerState, mut log_rx: mpsc::Receiver<LogEntry>) {
    let write_rows = state.config.logging();
    if !write_rows {
        tracing::info!(
            "COGWHEEL_RETENTION__HISTORY_DAYS is 0: query rows are not written, only hourly counts"
        );
    }
    let mut shutdown = state.shutdown.clone();
    let mut received = Vec::with_capacity(DRAIN_BATCH);
    let mut pending: Vec<QueryLogEntry> = Vec::with_capacity(FLUSH_ROWS);
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);

    loop {
        tokio::select! {
            count = log_rx.recv_many(&mut received, DRAIN_BATCH) => {
                if count == 0 {
                    break;
                }
                absorb(&state, &mut received, &mut pending, write_rows);
                if pending.len() >= FLUSH_ROWS {
                    flush(&state, &mut pending, write_rows).await;
                }
            }
            _ = ticker.tick() => flush(&state, &mut pending, write_rows).await,
            () = crate::state::stopped(&mut shutdown) => break,
        }
    }
    flush(&state, &mut pending, write_rows).await;
}

/// Turn a drained batch into rows, publishing frames on the way past.
///
/// The device-name table is read once per batch rather than per entry: it is swapped wholesale,
/// and a batch spans milliseconds. The list name is not resolved here at all — the runtime
/// stamped it on each entry under the policy that decided it, because a list toggled inside the
/// flush window renumbers the slots these rows were attributed with.
fn absorb(
    state: &ServerState,
    received: &mut Vec<LogEntry>,
    pending: &mut Vec<QueryLogEntry>,
    write_rows: bool,
) {
    let streaming = state.events.listening();
    let names = streaming.then(|| state.device_names());

    for entry in received.drain(..) {
        let reason = entry.verdict.reason();
        let blocked = entry.verdict.is_blocked();
        let ts = i64::from(entry.ts);
        let client = entry.client.to_string();

        if let Some(names) = names.as_ref() {
            state.events.publish(StreamQueryEvent {
                ts,
                client: client.clone(),
                device_name: names.get(&entry.client).map(|name| name.to_string()),
                domain: entry.domain.to_string(),
                qtype: entry.qtype,
                blocked,
                reason,
                list: entry.list.as_deref().map(str::to_owned),
            });
        }

        // With `HISTORY_DAYS=0` the flush writes hourly counts and no rows, and those read only
        // the client, the hour and whether it was blocked — so the rest is left at its default
        // rather than built. Building it would be two `String`s per answered query, allocated and
        // dropped without anything ever reading them, on the one configuration whose whole point
        // is to keep no browsing history.
        pending.push(if write_rows {
            QueryLogEntry {
                ts,
                client,
                domain: entry.domain.to_string(),
                qtype: entry.qtype,
                blocked,
                reason: reason.as_u8(),
                list: entry.list.as_deref().map(str::to_owned),
            }
        } else {
            QueryLogEntry {
                ts,
                client,
                blocked,
                ..QueryLogEntry::default()
            }
        });
    }
}

/// Write one batch. A database failure drops the batch with a warning: DNS must never wait on
/// the log, and a retry queue would grow without bound behind a full disk.
async fn flush(state: &ServerState, pending: &mut Vec<QueryLogEntry>, write_rows: bool) {
    if pending.is_empty() {
        return;
    }
    let batch = std::mem::take(pending);
    let rows = batch.len();
    // `take` leaves an empty vector with no capacity; giving the next batch its buffer back here
    // keeps the writer from regrowing one every five seconds for the life of the process.
    pending.reserve(FLUSH_ROWS);
    if let Err(error) = state
        .storage
        .insert_batch_with_rollups(batch, write_rows)
        .await
    {
        tracing::warn!(%error, rows, "dropped a batch of query-log rows");
    }
}

#[cfg(test)]
mod tests {
    use super::{EventBus, MAX_EVENT_SUBSCRIBERS, StreamQueryEvent};
    use cogwheel_policy::Reason;

    fn frame() -> StreamQueryEvent {
        StreamQueryEvent {
            ts: 1_800_000_000,
            client: "192.168.1.20".to_owned(),
            device_name: Some("Kitchen tablet".to_owned()),
            domain: "ads.example.com".to_owned(),
            qtype: 1,
            blocked: true,
            reason: Reason::List,
            list: Some("oisd small".to_owned()),
        }
    }

    #[test]
    fn publishing_without_subscribers_is_a_no_op() {
        let bus = EventBus::new();
        assert!(!bus.listening());
        bus.publish(frame());
    }

    #[test]
    fn a_subscriber_receives_query_frames() {
        let bus = EventBus::new();
        let (mut receiver, _guard) = bus.subscribe().expect("a slot is free");
        assert!(bus.listening());
        bus.publish(frame());
        let received = receiver.try_recv().expect("the frame arrives");
        assert_eq!(received.domain, "ads.example.com");
        assert!(received.blocked);
    }

    #[test]
    fn the_subscriber_cap_is_enforced_and_slots_come_back() {
        let bus = EventBus::new();
        let held: Vec<_> = (0..MAX_EVENT_SUBSCRIBERS)
            .map(|_| bus.subscribe().expect("under the cap"))
            .collect();
        assert!(
            bus.subscribe().is_none(),
            "the cap must refuse the next one"
        );
        drop(held);
        assert!(
            bus.subscribe().is_some(),
            "dropping a stream must return its slot"
        );
    }

    #[test]
    fn the_frame_is_camel_case_on_the_wire() {
        let json = serde_json::to_string(&frame()).expect("frames serialise");
        assert!(json.contains("\"deviceName\":\"Kitchen tablet\""));
        assert!(json.contains("\"reason\":\"list\""));
    }
}
