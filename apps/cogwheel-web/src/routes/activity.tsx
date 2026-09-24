import React from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ActivityIcon, SearchXIcon, Trash2Icon } from "lucide-react";
import { api, errorMessage, type Device, type StreamQueryEvent } from "@/lib/api";
import { checkSentence } from "@/lib/derive";
import { formatClock, formatCount, pluralize } from "@/lib/format";
import { notify } from "@/lib/toast";
import {
  ACTIVITY_ANNOUNCE_INTERVAL_MS,
  ACTIVITY_BUFFER_LIMIT,
  ACTIVITY_PAGE_SIZE,
  ACTIVITY_VISIBLE_STEP,
} from "@/lib/constants";
import { useCogwheelActions, useSnapshot } from "@/data/context";
import { useQueryStream } from "@/hooks/use-event-stream";
import { ROW_TRIGGER, useRovingMenus } from "@/hooks/use-roving-menus";
import { Button } from "@/components/ui/button";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, type Column } from "@/components/app/data-table";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { NoticeBanner } from "@/components/app/states";
import {
  NOTHING_HELD,
  fromFrame,
  fromLog,
  holdsFocus,
  matches,
  prepend,
  rowKey,
  scrolledIntoList,
  withHistory,
  type Feed,
  type Filters,
  type Held,
  type Row,
  type RowAction,
  type Verdict,
  VERDICTS,
  streamWords,
} from "./activity/model";
import {
  AnsweredWatcher,
  DeviceCell,
  DomainCell,
  LiveLine,
  NarrowQueryRow,
  RowActions,
  TimeCell,
  VerdictCell,
} from "./activity/rows";
import { QueryFilters } from "./activity/filters";

/** How long a still mouse over the list keeps holding it. */
const POINTER_IDLE_MS = 15_000;

/**
 * The filters are in the URL — `?q=`, `?verdict=`, `?client=` (an address, or
 * `unnamed`) — so a link can open the log already filtered. Overview's "Show
 * in Activity" linked to `?q=youtube.com&verdict=blocked` and landed on the
 * whole unfiltered log.
 */
export function ActivityScreen() {
  const { devices } = useSnapshot("devices");

  const [params, setParams] = useSearchParams();
  const [device, setDevice] = React.useState(() => params.get("client") || "all");
  const [verdict, setVerdict] = React.useState<Verdict>(() => {
    const asked = params.get("verdict");
    return VERDICTS.find((option) => option === asked) ?? "all";
  });
  const [search, setSearch] = React.useState(() => params.get("q") ?? "");
  React.useEffect(() => {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        const set = (key: string, value: string | null) => (value ? next.set(key, value) : next.delete(key));
        set("q", search.trim() || null);
        set("verdict", verdict === "all" ? null : verdict);
        set("client", device === "all" ? null : device);
        return next.toString() === current.toString() ? current : next;
      },
      { replace: true },
    );
  }, [device, search, setParams, verdict]);

  const filters = React.useMemo<Filters>(
    () => ({
      client: device !== "all" && device !== "unnamed" ? device : undefined,
      unnamed: device === "unnamed" ? true : undefined,
      blocked: verdict === "all" ? undefined : verdict === "blocked",
      q: search.trim() || undefined,
    }),
    [device, search, verdict],
  );

  const filtered = device !== "all" || verdict !== "all" || filters.q !== undefined;

  const clearFilters = React.useCallback(() => {
    setDevice("all");
    setVerdict("all");
    setSearch("");
  }, []);

  // Built here rather than inside the feed, which renders a few times a second
  // while the stream runs: an element React has already seen is passed through
  // untouched, so the filters are not rendered again with every batch of rows.
  const [initiallyOpen] = React.useState(() => params.has("client") || params.has("verdict"));
  const controls = (
    <QueryFilters
      device={device}
      devices={devices}
      initiallyOpen={initiallyOpen}
      onDevice={setDevice}
      onSearch={setSearch}
      onVerdict={setVerdict}
      search={search}
      verdict={verdict}
    />
  );

  return (
    <PageShell>
      <PageHeader
        description="Every query the resolver answered, most recently answered first."
        title="Activity"
      />
      <QueryFeed
        controls={controls}
        devices={devices}
        filtered={filtered}
        filters={filters}
        onClearFilters={clearFilters}
      />
    </PageShell>
  );
}

/**
 * The log, live.
 *
 * Live, but never under someone's hand. While keyboard focus or an open row
 * menu is in the list, the pointer is over it, or the newest row has been
 * scrolled out of sight, arriving rows wait above it behind "Show N new"
 * instead of pushing everything down. At ten queries a second a focused
 * row used to slide two thousand pixels in six seconds, fall past row 50,
 * unmount, and drop focus on <body>. Leaving the list lets them in.
 *
 * Switching Live off keeps the stream connected and holds every row that
 * arrives, so switching it back on shows what was missed; it used to close the
 * stream, and what was answered in between never appeared at all.
 */
function QueryFeed({
  filters,
  filtered,
  onClearFilters,
  controls,
  devices,
}: {
  filters: Filters;
  filtered: boolean;
  onClearFilters: () => void;
  controls: React.ReactNode;
  devices: Device[];
}) {
  const { mutate } = useCogwheelActions();
  const navigate = useNavigate();

  const [live, setLive] = React.useState(true);
  const [feed, setFeed] = React.useState<Feed>({ rows: [], cursor: null });
  const [logging, setLogging] = React.useState(true);
  const [loading, setLoading] = React.useState(true);
  const [loadingOlder, setLoadingOlder] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [attempt, setAttempt] = React.useState(0);
  const [clearing, setClearing] = React.useState(false);
  const [clearedAt, setClearedAt] = React.useState<number | null>(null);
  const [why, setWhy] = React.useState<string | null>(null);
  // A page of history is 200 rows; the table draws 50 of them until asked for
  // more. On a phone that is the difference between a page eleven screens long
  // and one forty-nine screens long.
  const [visible, setVisible] = React.useState(ACTIVITY_VISIBLE_STEP);
  const [heldCount, setHeldCount] = React.useState(0);
  const [interacting, setInteracting] = React.useState(false);
  const [announcement, setAnnouncement] = React.useState("");

  const hintId = React.useId();

  const regionRef = React.useRef<HTMLDivElement>(null);
  const held = React.useRef<Held>(NOTHING_HELD);
  const liveRef = React.useRef(true);
  const holdingRef = React.useRef(false);
  const filtersRef = React.useRef(filters);
  const loggingRef = React.useRef(true);
  const arrived = React.useRef(0);
  const presence = React.useRef({ focus: false, pointer: false, scroll: false, hidden: false });
  const listedRef = React.useRef(false);
  const [answeredBefore, setAnsweredBefore] = React.useState(false);

  React.useEffect(() => {
    filtersRef.current = filters;
    loggingRef.current = logging;
  });

  /* ---------------------------------------------------------------- rows */

  /**
   * Lets the held rows in. Everything that decides *when* ends up here.
   * `urgent` skips the transition, for "Show N new": the rows it lets in are
   * the ones focus is about to move to.
   */
  const release = React.useCallback((urgent = false) => {
    const { rows, overflow } = held.current;
    if (rows.length === 0) return;
    held.current = NOTHING_HELD;
    setHeldCount(0);
    arrived.current += rows.length;

    if (overflow && loggingRef.current) {
      // More arrived than the buffer keeps. The log has every one of them, so
      // it is read again rather than showing 500 rows with a hole behind them.
      api
        .queries({ ...filtersRef.current, limit: ACTIVITY_PAGE_SIZE })
        .then((page) =>
          React.startTransition(() =>
            setFeed((current) =>
              withHistory(page.rows, [...rows, ...current.rows.filter((row) => row.id === null)], page.next_before),
            ),
          ),
        )
        .catch(() => React.startTransition(() => setFeed((current) => prepend(current, rows))));
      return;
    }
    if (urgent) setFeed((current) => prepend(current, rows));
    else React.startTransition(() => setFeed((current) => prepend(current, rows)));
  }, []);

  /** Recomputes whether rows are held, from the refs the event handlers keep current. */
  const settle = React.useCallback(() => {
    const { focus, pointer, scroll, hidden } = presence.current;
    // An empty list has no row to keep still, so the first rows always come in.
    const busy = (listedRef.current && (focus || pointer || scroll)) || hidden;
    holdingRef.current = !liveRef.current || busy;
    setInteracting(busy);
    if (!holdingRef.current) release();
  }, [release]);

  const listed = feed.rows.length > 0;
  React.useEffect(() => {
    listedRef.current = listed;
    settle();
  }, [listed, settle]);

  const onFrames = React.useCallback((frames: StreamQueryEvent[]) => {
    const current = filtersRef.current;
    const rows: Row[] = [];
    for (let index = frames.length - 1; index >= 0; index -= 1) {
      const row = fromFrame(frames[index]);
      if (matches(row, current)) rows.push(row);
    }
    if (rows.length === 0) return;

    if (holdingRef.current) {
      const previous = held.current;
      const next = [...rows, ...previous.rows];
      held.current = {
        rows: next.slice(0, ACTIVITY_BUFFER_LIMIT),
        total: previous.total + rows.length,
        overflow: previous.overflow || next.length > ACTIVITY_BUFFER_LIMIT,
      };
      setHeldCount(held.current.total);
      return;
    }

    arrived.current += rows.length;
    // A transition: typing in the search field or opening a menu is never
    // queued behind drawing a batch of rows.
    React.startTransition(() => setFeed((feedNow) => prepend(feedNow, rows)));
  }, []);

  // Connected for as long as the screen is open; Live decides what is shown,
  // not whether anything is received.
  const stream = useQueryStream(true, onFrames);

  // History. Debounced because the search field drives it keystroke by
  // keystroke, and every filter is answered by the server, not in the browser.
  React.useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setLoading(true);
      api
        .queries({ ...filters, limit: ACTIVITY_PAGE_SIZE }, { signal: controller.signal })
        .then((page) => {
          // Rows held so far were held under the previous filters. The page
          // has every one of them that was logged; the rest are the newest
          // few seconds the writer has not flushed, kept if they still match.
          const waiting = held.current.rows;
          held.current = NOTHING_HELD;
          setHeldCount(0);
          setFeed((current) =>
            withHistory(
              page.rows,
              [...waiting, ...current.rows.filter((row) => row.id === null)].filter((row) => matches(row, filters)),
              page.next_before,
            ),
          );
          setLogging(page.logging);
          setError(null);
        })
        .catch((cause) => {
          if (cause instanceof DOMException && cause.name === "AbortError") return;
          setError(errorMessage(cause));
        })
        .finally(() => {
          if (!controller.signal.aborted) setLoading(false);
        });
    }, 250);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [filters, attempt]);

  React.useEffect(() => setVisible(ACTIVITY_VISIBLE_STEP), [filters]);

  /* ------------------------------------------------------------- holding */

  React.useEffect(() => {
    const region = regionRef.current;
    let frame = 0;
    const measure = () => {
      frame = 0;
      if (!region) return;
      const scroll = scrolledIntoList(region);
      if (scroll !== presence.current.scroll) {
        presence.current.scroll = scroll;
        settle();
      }
    };
    const onScroll = () => {
      if (!frame) frame = requestAnimationFrame(measure);
    };
    const onVisibility = () => {
      // Nobody is reading a background tab; drawing rows into it is work for
      // nothing, and they are all let in the moment it is looked at again.
      presence.current.hidden = document.hidden;
      settle();
    };
    presence.current.hidden = document.hidden;
    // Capture, so the table's own scroll container reports too: scroll does
    // not bubble, but it is still captured on the way down.
    window.addEventListener("scroll", onScroll, { capture: true, passive: true });
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("scroll", onScroll, { capture: true });
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [settle]);

  const blurTimer = React.useRef<number | undefined>(undefined);
  React.useEffect(() => () => window.clearTimeout(blurTimer.current), []);

  /* --------------------------------------------------------- tab stops */

  // One tab stop for the whole list, not fifty (hooks/use-roving-menus.ts).
  const roving = useRovingMenus(regionRef);

  const onFocus = (event: React.FocusEvent<HTMLDivElement>) => {
    window.clearTimeout(blurTimer.current);
    const target = event.target as HTMLElement;
    roving.noteFocus(target);
    // Focus arriving from a portaled row menu bubbles here through React too.
    const focus = holdsFocus(target);
    if (focus !== presence.current.focus) {
      presence.current.focus = focus;
      settle();
    }
  };

  const onBlur = () => {
    // Checked a moment later: a menu closing hands focus back to its trigger
    // on the next frame, and letting rows in during that gap would move the
    // row the person just acted on.
    window.clearTimeout(blurTimer.current);
    blurTimer.current = window.setTimeout(() => {
      const region = regionRef.current;
      if (!region) return;
      const active = document.activeElement;
      const inside = Boolean(active && region.contains(active) && holdsFocus(active));
      const menuOpen = Boolean(region.querySelector('[aria-haspopup="menu"][aria-expanded="true"]'));
      const focus = inside || menuOpen;
      if (!inside && !menuOpen) {
        // Tabbing back in lands on the newest row, not wherever the last
        // visit ended — in a live log that row may be hundreds down by now.
        roving.leave();
      }
      if (focus !== presence.current.focus) {
        presence.current.focus = focus;
        settle();
      }
    }, 150);
  };

  // A pointer resting on the list holds it only while it is being used: a
  // mouse left parked over a log on a spare screen is not someone reading it,
  // and the list would otherwise stop being live for as long as it sat there.
  const lastMove = React.useRef(0);
  const idleTimer = React.useRef<number | undefined>(undefined);
  React.useEffect(() => () => window.clearTimeout(idleTimer.current), []);

  const expirePointer = React.useCallback(() => {
    const idle = performance.now() - lastMove.current;
    if (idle < POINTER_IDLE_MS) {
      idleTimer.current = window.setTimeout(expirePointer, POINTER_IDLE_MS - idle);
      return;
    }
    idleTimer.current = undefined;
    if (!presence.current.pointer) return;
    presence.current.pointer = false;
    settle();
  }, [settle]);

  const onPointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    if (event.pointerType !== "mouse") return;
    lastMove.current = performance.now();
    if (idleTimer.current === undefined) idleTimer.current = window.setTimeout(expirePointer, POINTER_IDLE_MS);
    // Over the rows, a row's position is about to be clicked on. Over the
    // Live switch, it is Live that is about to change.
    const pointer = !(event.target as HTMLElement).closest?.("[data-live-control]");
    if (pointer !== presence.current.pointer) {
      presence.current.pointer = pointer;
      settle();
    }
  };

  const onPointerLeave = () => {
    if (!presence.current.pointer) return;
    presence.current.pointer = false;
    settle();
  };

  const toggleLive = React.useCallback(
    (on: boolean) => {
      liveRef.current = on;
      setLive(on);
      if (on) arrived.current = 0;
      settle();
    },
    [settle],
  );

  const showNew = React.useCallback(
    (event: React.MouseEvent<HTMLButtonElement>) => {
      const region = regionRef.current;
      const scroller = region?.querySelector<HTMLElement>('[data-slot="table-wrapper"]');
      if (scroller) scroller.scrollTop = 0;
      release(true);
      // From the keyboard, the button is about to disappear under focus, and
      // the rows it let in are the ones that were asked for.
      if (event.detail === 0) {
        requestAnimationFrame(() => region?.querySelector<HTMLElement>(ROW_TRIGGER)?.focus());
      }
    },
    [release],
  );

  /* ------------------------------------------------------ announcements */

  // Screen readers and a live table do not mix: wrapping the table in a live
  // region read out every column of every arriving row. A periodic count
  // carries the one thing the region was there to say.
  React.useEffect(() => {
    const timer = window.setInterval(() => {
      const waiting = held.current.total;
      setAnnouncement(
        waiting > 0
          ? `${pluralize(waiting, "new query", "new queries")} waiting above the list.`
          : liveRef.current && arrived.current > 0
            ? `${pluralize(arrived.current, "new query", "new queries")} since Live was switched on.`
            : "",
      );
    }, ACTIVITY_ANNOUNCE_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, []);

  /* ------------------------------------------------------------ actions */

  const loadOlder = async () => {
    if (feed.cursor === null) return;
    setLoadingOlder(true);
    try {
      const page = await api.queries({ ...filters, before: feed.cursor, limit: ACTIVITY_PAGE_SIZE });
      setFeed((current) => ({ rows: [...current.rows, ...page.rows.map(fromLog)], cursor: page.next_before }));
    } catch (cause) {
      notify.error("Could not load older rows", errorMessage(cause));
    } finally {
      setLoadingOlder(false);
    }
  };

  const clearLog = async () => {
    const result = await mutate({
      key: "clear-log",
      action: () => api.clearQueries(),
      after: "light",
      successTitle: "Query log cleared",
      successDetail: (outcome) => `${pluralize(outcome.deleted, "row")} deleted.`,
      failureTitle: "Could not clear the log",
    });
    if (result) {
      held.current = NOTHING_HELD;
      setHeldCount(0);
      setFeed({ rows: [], cursor: null });
      setVisible(ACTIVITY_VISIBLE_STEP);
      setClearedAt(Math.floor(Date.now() / 1000));
    }
  };

  const byIp = React.useMemo(() => {
    const map = new Map<string, { id: string; name: string }>();
    for (const entry of devices) map.set(entry.ip_address, { id: entry.id, name: entry.name });
    return map;
  }, [devices]);

  // Read through a ref so the handler every row holds never changes identity:
  // a new one would re-render every memoised row.
  const handlers = React.useRef({ byIp, mutate, navigate });
  React.useEffect(() => {
    handlers.current = { byIp, mutate, navigate };
  });

  const onAction = React.useCallback<RowAction>((row, action) => {
    const { byIp: named, mutate: run, navigate: go } = handlers.current;
    const deviceId = named.get(row.client)?.id;
    const addRule = (verb: "allow" | "block", scoped?: string) =>
      void run({
        key: `rule-${row.domain}`,
        action: () => api.createRule({ domain: row.domain, action: verb, device_id: scoped }),
        successTitle: verb === "allow" ? "Allow rule saved" : "Block rule saved",
        successDetail: row.domain,
        failureTitle: "Could not save the rule",
      });

    if (action === "allow") addRule("allow");
    else if (action === "block") addRule("block");
    else if (action === "allow-device") addRule("allow", deviceId);
    else if (action === "block-device") addRule("block", deviceId);
    else if (action === "name") go(`/devices?ip=${encodeURIComponent(row.client)}`);
    else {
      api
        .check(row.domain, row.client)
        .then((result) => setWhy(checkSentence(result)))
        .catch((cause) => notify.error("Could not check that domain", errorMessage(cause)));
    }
  }, []);

  /* -------------------------------------------------------------- table */

  const columns = React.useMemo<Column<Row>[]>(
    () => [
      { key: "ts", header: "Time", render: (row) => <TimeCell ts={row.ts} /> },
      { key: "domain", header: "Domain", render: (row) => <DomainCell domain={row.domain} /> },
      {
        key: "device",
        header: "Device",
        render: (row) => <DeviceCell client={row.client} name={row.device_name} />,
      },
      {
        key: "verdict",
        header: "Verdict",
        render: (row) => <VerdictCell blocked={row.blocked} list={row.list} reason={row.reason} />,
      },
      {
        key: "actions",
        header: "Actions",
        hideHeader: true,
        align: "end",
        stackHeader: true,
        render: (row) => <RowActions deviceName={byIp.get(row.client)?.name} onAction={onAction} row={row} />,
      },
    ],
    [byIp, onAction],
  );

  const card = React.useCallback(
    (row: Row) => <NarrowQueryRow deviceName={byIp.get(row.client)?.name} onAction={onAction} row={row} />,
    [byIp, onAction],
  );

  const retry = React.useCallback(() => setAttempt((count) => count + 1), []);

  const empty = React.useMemo(() => {
    if (filtered) {
      return {
        icon: SearchXIcon,
        title: "No queries match these filters",
        description: logging
          ? "Nothing in the log matches them, and nothing that does has arrived since."
          : "Nothing that matches them has arrived since this page was opened.",
        action: (
          <Button onClick={onClearFilters} size="sm" variant="outline">
            Clear filters
          </Button>
        ),
      };
    }
    if (clearedAt !== null) {
      return {
        icon: ActivityIcon,
        title: "Log cleared",
        description: `Queries answered after ${formatClock(clearedAt)} appear here ${
          live ? "as they happen" : "when Live is switched back on"
        }.`,
      };
    }
    if (!logging) {
      return {
        icon: ActivityIcon,
        title: "Waiting for queries",
        description: "Nothing is stored while query logging is off, so this list fills from the live stream.",
      };
    }
    if (answeredBefore) {
      // The appliance has answered queries (the 24-hour counters, which are
      // kept apart from the log, say so) but none are in the log: it was
      // cleared before this page was opened, or aged out. Telling this person
      // to point a device's DNS here would be telling them what they did.
      return {
        icon: ActivityIcon,
        title: "The log is empty",
        description: `Queries answered from now on appear here ${live ? "as they happen" : "when Live is switched back on"}.`,
      };
    }
    return {
      icon: ActivityIcon,
      title: "No queries yet",
      description:
        "Point a device's DNS at the address on Overview, then reload a page on it — the queries land here within seconds.",
    };
  }, [answeredBefore, clearedAt, filtered, live, logging, onClearFilters]);

  const shown = React.useMemo(() => feed.rows.slice(0, visible), [feed.rows, visible]);

  // Memoised as a whole: the table re-renders every row it holds, so the
  // status line changing under the pointer must not reach it.
  const table = React.useMemo(
    () => (
      <DataTable
        card={card}
        columns={columns}
        empty={empty}
        error={error}
        errorTitle="Could not load the query log"
        loading={loading}
        onRetry={retry}
        rowKey={rowKey}
        rows={shown}
        // The narrow row below 768px of card: at 1024px with the sidebar open
        // the table was 722px in a 638px card, and the row menu — the only
        // route to Allow, Block and Why? — sat behind a nested scroll.
        stackBelow="3xl"
        stickyHeader
      />
    ),
    [card, columns, empty, error, loading, retry, shown],
  );

  const rows = feed.rows;
  const oldest = rows.at(-1);
  const status = streamWords(live, stream.status, interacting);

  return (
    <PageSections>
      {logging ? null : (
        <NoticeBanner
          detail="Only the live stream is shown, and nothing survives a reload. Set COGWHEEL_RETENTION__HISTORY_DAYS to a non-zero number of days and restart to keep history."
          title="Query logging is off"
          tone="warn"
        />
      )}

      {/* No description: the count is stated once, in the footer beside the
          controls that change it, and the page header already says what the
          rows are and what order they are in. */}
      <SectionCard title="Queries">
        <AnsweredWatcher onChange={setAnsweredBefore} />
        {controls}

        {stream.error ? <NoticeBanner className="mb-4" title={stream.error} tone="warn" /> : null}

        {/* Above the table, not up with the page header: the answer is about
            one of the rows below and has to be read next to them. */}
        {why ? (
          <NoticeBanner
            actions={
              <Button onClick={() => setWhy(null)} size="sm" variant="outline">
                Dismiss
              </Button>
            }
            className="mb-4"
            title={why}
            tone="neutral"
          />
        ) : null}

        <p aria-live="polite" className="sr-only">
          {announcement}
        </p>
        <p className="sr-only" id={hintId}>
          Arrow keys move between rows. While you are in the list, new queries wait above it.
        </p>

        <div
          aria-describedby={hintId}
          aria-label="Query log"
          onBlur={onBlur}
          onFocus={onFocus}
          onKeyDownCapture={roving.onKeyDownCapture}
          onPointerLeave={onPointerLeave}
          onPointerMove={onPointerMove}
          ref={regionRef}
          role="group"
        >
          <LiveLine
            held={heldCount}
            live={live}
            onShowNew={showNew}
            onToggle={toggleLive}
            short={status.short}
            long={status.long}
          />

          {table}
        </div>

        {/* Under the rows but inside the card. Clear log is here, last in the
            tab order and at the far end of the row from the two benign
            buttons: in the header it was the first control on the page. */}
        {rows.length > 0 || filtered || clearedAt !== null ? (
          <div className="mt-4 flex flex-wrap items-center gap-3 border-border border-t pt-4">
            {rows.length > visible ? (
              <Button onClick={() => setVisible((current) => current + ACTIVITY_VISIBLE_STEP)} variant="outline">
                Show {ACTIVITY_VISIBLE_STEP} more
              </Button>
            ) : null}
            {/* The first draws more of what is already loaded; this one goes
                back to the server for rows older than the oldest loaded, and
                says which time that is. It used to format the log cursor — a
                row id — as a time, and printed an hour in 1970. */}
            {rows.length > 0 ? (
              <Button
                disabled={feed.cursor === null}
                isLoading={loadingOlder}
                onClick={() => void loadOlder()}
                variant="outline"
              >
                {feed.cursor !== null && oldest ? `Load older than ${formatClock(oldest.ts)}` : "No older rows"}
              </Button>
            ) : null}
            {rows.length > 0 ? (
              <span className="tabular text-muted-foreground text-xs">
                Showing {formatCount(shown.length)} of {pluralize(rows.length, "loaded row")}
              </span>
            ) : null}
            {logging ? (
              <Button className="ms-auto" onClick={() => setClearing(true)} variant="destructive">
                <Trash2Icon aria-hidden />
                Clear log
              </Button>
            ) : null}
          </div>
        ) : null}
      </SectionCard>

      <ConfirmDialog
        confirmLabel="Clear log"
        consequence="The 24-hour counters on Overview and Devices are kept — they are stored separately from the log."
        description="Every stored query row is deleted. This cannot be undone."
        tone="bad"
        onConfirm={clearLog}
        onOpenChange={setClearing}
        open={clearing}
        title="Clear the query log?"
      />
    </PageSections>
  );
}
