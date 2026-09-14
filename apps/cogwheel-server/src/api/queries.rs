//! The query log: one page, one clear, one live stream (§3 routes 6–8).

use crate::http::{ApiError, ApiQuery, ApiResult, ok};
use crate::state::ServerState;
use axum::extract::State;
use axum::response::Sse;
use axum::response::sse::{Event, KeepAlive};
use cogwheel_policy::Reason;
use cogwheel_storage::{QueryFilter, QueryLogRow};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

/// Rows per page when the caller does not say.
const DEFAULT_LIMIT: u32 = 200;

/// Rows per page the caller may ask for at most: one screen of scrollback, not an export.
///
/// Asking for more is refused rather than clamped. A caller handed 1,000 rows after asking for
/// 5,000 has no way to tell that it was cut short — it sees a full page and a `next_before`, and
/// an export loop written against it silently drops four fifths of the log.
const MAX_LIMIT: u32 = 1_000;

/// How often a keep-alive comment goes out on an idle stream, so proxies do not close it.
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// `?limit=&before=&client=&unnamed=&blocked=&q=`.
#[derive(Debug, Default, Deserialize)]
pub struct QueryParams {
    pub limit: Option<u32>,
    /// Keyset cursor: rows older than this id.
    pub before: Option<i64>,
    pub client: Option<String>,
    pub unnamed: Option<bool>,
    pub blocked: Option<bool>,
    /// Substring of the domain.
    pub q: Option<String>,
}

/// One logged query, with its reason spelled the way every other route spells it.
///
/// Storage keeps `reason` as the numeric code it was written with and does not interpret it;
/// the wire contract is the snake_case name, so the translation happens here.
#[derive(Debug, Clone, Serialize)]
pub struct QueryRow {
    pub id: i64,
    pub ts: i64,
    pub client: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub domain: String,
    pub qtype: u16,
    pub blocked: bool,
    pub reason: Reason,
    pub list: Option<String>,
}

impl From<QueryLogRow> for QueryRow {
    fn from(row: QueryLogRow) -> Self {
        Self {
            id: row.id,
            ts: row.ts,
            client: row.client,
            device_id: row.device_id,
            device_name: row.device_name,
            domain: row.domain,
            qtype: row.qtype,
            blocked: row.blocked,
            // A code this build does not know is a row written by a newer one; showing it as
            // "nothing matched" is wrong in the least confusing direction.
            reason: Reason::from_u8(row.reason).unwrap_or(Reason::NoMatch),
            list: row.list,
        }
    }
}

/// One page of the log.
#[derive(Debug, Clone, Serialize)]
pub struct QueryPage {
    pub rows: Vec<QueryRow>,
    pub next_before: Option<i64>,
    /// False when `COGWHEEL_RETENTION__HISTORY_DAYS=0`: only the live stream exists.
    pub logging: bool,
}

/// How many rows were cleared.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Cleared {
    pub deleted: usize,
}

/// Route 6: a keyset page of the log, most recently logged first (see `Storage::query_page` on
/// why that is not quite the same as newest by timestamp).
pub async fn list(
    State(state): State<ServerState>,
    ApiQuery(params): ApiQuery<QueryParams>,
) -> ApiResult<QueryPage> {
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(ApiError::bad_request(format!(
            "Ask for between 1 and {MAX_LIMIT} rows."
        )));
    }
    let page = state
        .storage
        .query_page(QueryFilter {
            limit,
            before: params.before,
            client: params
                .client
                .map(|client| client.trim().to_owned())
                .filter(|client| !client.is_empty()),
            unnamed: params.unnamed.unwrap_or(false),
            blocked: params.blocked,
            contains: params
                .q
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty()),
        })
        .await?;
    ok(QueryPage {
        rows: page.rows.into_iter().map(QueryRow::from).collect(),
        next_before: page.next_before,
        logging: state.config.logging(),
    })
}

/// Route 7: clear the log. The hourly rollups stay: they are counts, and every figure in the UI
/// is read from them, so clearing browsing history must not zero the dashboard.
pub async fn clear(State(state): State<ServerState>) -> ApiResult<Cleared> {
    let deleted = state.storage.clear_query_log().await?;
    // The Overview's top-domain tables are scanned from the log, so a cleared log has to clear
    // the memo with it or the page shows domains that are no longer anywhere on the appliance.
    state.top_domains.clear();
    tracing::info!(deleted, "query log cleared");
    ok(Cleared { deleted })
}

/// Route 8: the live query stream.
///
/// 503 once the subscriber cap is reached rather than accepting unbounded clients. The stream
/// ends on the shutdown signal, because an SSE connection never ends on its own and one open
/// browser tab would otherwise make a graceful stop hang until the supervisor sent SIGKILL.
pub async fn stream(
    State(state): State<ServerState>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let Some((receiver, guard)) = state.events.subscribe() else {
        return Err(ApiError::unavailable(
            "Too many live streams are open already.",
        ));
    };
    let mut shutdown = state.shutdown.clone();
    let stream = BroadcastStream::new(receiver)
        .take_until(async move {
            let _ = shutdown.wait_for(|stopping| *stopping).await;
        })
        .filter_map(move |item| {
            // The guard lives as long as the stream, which is what releases the subscriber slot
            // when the client disconnects: the handler itself returned long before.
            let _guard = &guard;
            let frame = match item {
                Ok(event) => Event::default().event("query").json_data(&*event),
                // A slow reader missed frames. Skip them and keep the connection alive rather
                // than tearing down a working stream over dropped display rows.
                Err(BroadcastStreamRecvError::Lagged(_)) => return std::future::ready(None),
            };
            std::future::ready(frame.ok().map(Ok))
        });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(KEEP_ALIVE).text("keep-alive")))
}
