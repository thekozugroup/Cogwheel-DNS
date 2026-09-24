import type { QueryRow, StreamQueryEvent } from "@/lib/api";
import { ACTIVITY_BUFFER_LIMIT } from "@/lib/constants";
import type { StreamStatus } from "@/hooks/use-event-stream";

/*
 * The Activity log's data: a row, the feed of them, the rows held back while
 * someone is in the list, and the pure functions that merge the live stream
 * into the history the server pages out.
 */

export type Verdict = "all" | "blocked" | "allowed";

export const VERDICTS: readonly Verdict[] = ["all", "blocked", "allowed"];

export type Filters = { client?: string; unnamed?: true; blocked?: boolean; q?: string };

/** A log row and a live frame rendered as one thing. Live frames have no log id. */
export type Row = Omit<QueryRow, "id"> & { key: string; id: number | null };

/** The rows on screen and the "Load older" cursor, which have to move together. */
export type Feed = { rows: Row[]; cursor: number | null };

/** Rows that arrived while the list was held, newest first, and how many there were in all. */
export type Held = { rows: Row[]; total: number; overflow: boolean };

export type RowAction = (row: Row, action: string) => void;

export const NOTHING_HELD: Held = { rows: [], total: 0, overflow: false };

let liveSequence = 0;

export function fromFrame(frame: StreamQueryEvent): Row {
  liveSequence += 1;
  return {
    key: `live-${liveSequence}`,
    id: null,
    ts: frame.ts,
    client: frame.client,
    device_id: null,
    device_name: frame.deviceName,
    domain: frame.domain,
    qtype: frame.qtype,
    blocked: frame.blocked,
    reason: frame.reason,
    list: frame.list,
  };
}

export function fromLog(row: QueryRow): Row {
  return { ...row, key: `log-${row.id}` };
}

export const rowKey = (row: Row) => row.key;

export const signature = (row: Row) => `${row.ts}|${row.client}|${row.domain}`;

/** The server's filters, asked of a row the browser already has. */
export function matches(row: Row, filters: Filters): boolean {
  if (filters.client && row.client !== filters.client) return false;
  // Device = Unnamed asks for the clients with no `devices` row; a live frame
  // carries the name when there is one, which is the same question.
  if (filters.unnamed && row.device_name) return false;
  if (filters.blocked !== undefined && row.blocked !== filters.blocked) return false;
  if (filters.q && !row.domain.toLowerCase().includes(filters.q.toLowerCase())) return false;
  return true;
}

/**
 * Drops the oldest rows past the buffer limit. "Load older" pages by log id,
 * and the rows that fall off the end are exactly the ones it must be able to
 * fetch back, so the cursor moves to just after the newest log row dropped.
 * (It used to stay where the first page left it, which after a busy minute
 * put a gap of several hundred rows between the list and the next page.)
 */
export function cap(feed: Feed): Feed {
  if (feed.rows.length <= ACTIVITY_BUFFER_LIMIT) return feed;
  const rows = feed.rows.slice(0, ACTIVITY_BUFFER_LIMIT);
  const firstDropped = feed.rows.slice(ACTIVITY_BUFFER_LIMIT).find((row) => row.id !== null);
  return { rows, cursor: firstDropped && firstDropped.id !== null ? firstDropped.id + 1 : feed.cursor };
}

/** Newest-first live rows onto the top of the list. */
export function prepend(feed: Feed, incoming: Row[]): Feed {
  if (incoming.length === 0) return feed;
  // The writer flushes to SQLite every 5 s, so a frame and its log row can
  // both arrive; the newest 50 rows are the only window where they overlap.
  // Only log rows are compared: two identical frames in the same second are
  // two queries, not one query twice.
  const logged = new Set<string>();
  for (const row of feed.rows.slice(0, 50)) if (row.id !== null) logged.add(signature(row));
  const fresh = logged.size > 0 ? incoming.filter((row) => !logged.has(signature(row))) : incoming;
  if (fresh.length === 0) return feed;
  return cap({ rows: [...fresh, ...feed.rows], cursor: feed.cursor });
}

/**
 * A fresh page of history plus the live rows it cannot contain yet: the ones
 * answered after the newest row the writer had flushed. Everything older than
 * that is in the page, or behind its cursor.
 */
export function withHistory(page: QueryRow[], live: Row[], cursor: number | null): Feed {
  const rows = page.map(fromLog);
  const newest = rows[0]?.ts ?? 0;
  const logged = new Set(rows.map(signature));
  const fresh = live.filter((row) => row.ts >= newest && !logged.has(signature(row)));
  return cap({ rows: [...fresh, ...rows], cursor });
}

/**
 * Whether focus on this element means someone is working in the list. Keyboard
 * focus does, and so does an open row menu. Focus a mouse click left behind
 * does not: after a menu opened with the mouse closes, focus returns to its
 * trigger and stays there when the person walks away, and the log would hold
 * until someone came back and clicked elsewhere. The Live switch never holds.
 */
export function holdsFocus(element: Element): boolean {
  if (element.closest("[data-live-control]")) return false;
  return element.matches(":focus-visible") || Boolean(element.closest('[role="menu"]'));
}

/** Whether the newest row has been scrolled out of sight, i.e. someone is reading further down. */
export function scrolledIntoList(region: HTMLElement): boolean {
  const scroller = region.querySelector<HTMLElement>('[data-slot="table-wrapper"]');
  if (scroller && scroller.scrollTop > 8) return true;
  const newest = region.querySelector<HTMLElement>("[data-row-actions]");
  if (!newest) return false;
  // The page scrolls under the sticky top bar, which is <main>'s sibling, so
  // the top of what can be seen is whichever of the two ends lower.
  const main = document.getElementById("main");
  const top = Math.max(
    main?.getBoundingClientRect().top ?? 0,
    main?.previousElementSibling?.getBoundingClientRect().bottom ?? 0,
  );
  return newest.getBoundingClientRect().bottom < top;
}

/**
 * The words after "Live". `long` is the rest of the sentence where there is
 * room for it; below sm the line is the switch, one word and "Show N new".
 */
export function streamWords(live: boolean, status: StreamStatus, interacting: boolean): { short: string; long?: string } {
  if (!live) return { short: "paused", long: " — new queries wait above the list" };
  if (status === "open") return interacting ? { short: "holding", long: " new rows while you're in the list" } : { short: "connected" };
  if (status === "reconnecting") return { short: "reconnecting" };
  return { short: "connecting" };
}
