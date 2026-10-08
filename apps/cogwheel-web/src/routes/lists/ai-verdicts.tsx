import React from "react";
import { ListChecksIcon, SearchXIcon } from "lucide-react";
import {
  api,
  errorMessage,
  type AiListState,
  type AiState,
  type AiVerdictPage,
  type AiVerdictRow,
  type RuleAction,
} from "@/lib/api";
import { aiForgetSentence, checkSentence } from "@/lib/derive";
import { formatCount, formatRelative, formatSure } from "@/lib/format";
import { notify } from "@/lib/toast";
import { useCogwheelActions, useSnapshot } from "@/data/context";
import { ROW_TRIGGER, useRovingMenus } from "@/hooks/use-roving-menus";
import { Button } from "@/components/ui/button";
import { SegmentGroup, SegmentGroupItem, SegmentGroupItemText } from "@/components/ui/segment-group";
import { Status } from "@/components/ui/status";
import { DataTable, NarrowRow, type Column } from "@/components/app/data-table";
import { DomainName } from "@/components/app/domain-name";
import { GroupLabel } from "@/components/app/form-field";
import { RowMenu } from "@/components/app/row-menu";
import { NoticeBanner } from "@/components/app/states";
import { StatusPill } from "@/components/app/status-indicator";
import { TextField } from "@/components/app/text-field";

/** The newest this many rows are shown; the footer says so when there are more. */
const LIMIT = 200;

type View = "changes" | "all";

/** A Why? answer and the row it is about; `text` is null while /check is asked. */
type Why = { domain: string; text: string | null };

/**
 * The muted notes under a verdict: why it is not what DNS does, or why the
 * lists still decide. Several can be true at once, so they are all said.
 */
function notesFor(row: AiVerdictRow): string[] {
  const notes: string[] = [];
  if (row.not_applied === "off") notes.push("not applied: AI review is off");
  if (row.outranked_by === "household_rule") notes.push("your rule decides");
  if (row.outranked_by === "protected") notes.push("protected: never blocked");
  if (row.why === "contested") {
    notes.push(row.site && row.conflict_site ? `core on ${row.site}, not on ${row.conflict_site}` : "two websites disagreed");
  }
  if (row.why === "agrees") notes.push("agrees with your lists");
  if (row.why === "limit") notes.push("skipped: today's limit on overriding your lists");
  if (row.not_applied === "lists_changed") notes.push("your lists changed; judged again next time");
  if (row.not_applied === "lists_agree") notes.push("your lists block it too");
  if (row.not_applied === "below_bar") notes.push("the model was not sure enough for it to apply");
  if (row.not_applied === "pending") notes.push("applying: DNS picks it up in a few seconds");
  return notes;
}

const site = (row: AiVerdictRow) => (row.site ? `for ${row.site}` : "for a website no longer recorded");

/** The model's confidence, never Cogwheel's: an ignore row says which way it leaned. */
function sureWords(row: AiVerdictRow, narrow: boolean): string {
  if (row.verdict === "ignore") {
    return `leaned ${row.choice}${row.confidence === null ? "" : ` · ${formatSure(row.confidence)}`}`;
  }
  if (row.confidence === null) return narrow ? "model did not say how sure" : "—";
  return narrow ? `model ${formatSure(row.confidence)} sure` : formatSure(row.confidence);
}

function ListsWord({ state }: { state: AiListState }) {
  if (state === "block") return <>block</>;
  if (state === "exception") return <>exception</>;
  return (
    <span className="text-muted-foreground">
      <span aria-hidden>—</span>
      <span className="sr-only">Not on a list</span>
    </span>
  );
}

/**
 * The AI list's rows: Changes (the blocks and allows that disagree with the
 * lists) or everything judged, searched on the server, newest first. Fetched
 * as the page's own state, the way Activity fetches the log, and never cached.
 */
export function AiVerdicts({
  state,
  counts,
  version,
  onChanged,
}: {
  state: AiState;
  /** The card's counts, until this table's first answer brings its own. */
  counts: { block: number; allow: number; ignore: number };
  /** Changes when the card learns of new or removed verdicts. */
  version: string;
  onChanged: () => void;
}) {
  const rules = useSnapshot("rules");
  const { mutate } = useCogwheelActions();
  const [view, setView] = React.useState<View>("changes");
  const [search, setSearch] = React.useState("");
  const [q, setQ] = React.useState("");
  const [page, setPage] = React.useState<AiVerdictPage | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [attempt, setAttempt] = React.useState(0);
  const [why, setWhy] = React.useState<Why | null>(null);
  const inflight = React.useRef<AbortController | null>(null);
  const viewLabel = React.useId();
  const hintId = React.useId();
  const rootRef = React.useRef<HTMLDivElement>(null);
  // Up to 200 row menus are one tab stop, as on Activity and Overview.
  const regionRef = React.useRef<HTMLDivElement>(null);
  const roving = useRovingMenus(regionRef);
  // Where the forgotten row was, until the page that no longer has it arrives.
  const forgot = React.useRef<number | null>(null);

  React.useEffect(() => () => inflight.current?.abort(), []);

  // Server-side search, a moment after the typing stops.
  React.useEffect(() => {
    const timer = window.setTimeout(() => setQ(search.trim()), 300);
    return () => window.clearTimeout(timer);
  }, [search]);

  // Read again when a rule changes too: "your rule decides" is worked out by the server.
  React.useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    api
      .aiVerdicts({ view, q: q || undefined, limit: LIMIT }, { signal: controller.signal })
      .then((next) => {
        setPage(next);
        setError(null);
      })
      .catch((cause) => {
        if (cause instanceof DOMException && cause.name === "AbortError") return;
        setError(errorMessage(cause));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [view, q, version, attempt, rules]);

  // Forget removes the row whose ⋯ held focus. The next row's ⋯ takes it, or
  // the search field once none is left, rather than the page body.
  React.useEffect(() => {
    const index = forgot.current;
    if (index === null || !page) return;
    forgot.current = null;
    if (document.activeElement && document.activeElement !== document.body) return;
    const triggers = regionRef.current?.querySelectorAll<HTMLElement>(ROW_TRIGGER) ?? [];
    const next = triggers[Math.min(index, triggers.length - 1)];
    (next ?? rootRef.current?.querySelector<HTMLElement>('input[type="text"]'))?.focus();
  }, [page]);

  const handlers = React.useRef({ rules, mutate, state, onChanged, rows: page?.rows ?? [] });
  React.useEffect(() => {
    handlers.current = { rules, mutate, state, onChanged, rows: page?.rows ?? [] };
  });

  const onAction = React.useCallback((row: AiVerdictRow, action: string) => {
    const { rules: current, mutate: run, state: now, onChanged: changed, rows: shown } = handlers.current;
    if (action === "allow" || action === "block") {
      const verb: RuleAction = action;
      const existing = current.find((rule) => rule.device_id === null && rule.domain === row.domain);
      if (existing?.action === verb) {
        notify.info("Already a rule", `${row.domain} is already ${verb === "allow" ? "allowed" : "blocked"} for everyone.`);
        return;
      }
      void run({
        key: `ai-rule-${row.domain}`,
        action: () => api.createRule({ domain: row.domain, action: verb }),
        successTitle: verb === "allow" ? "Allow rule saved" : "Block rule saved",
        successDetail: `${row.domain}; your rule beats the AI list.`,
        failureTitle: "Could not save the rule",
        // One click, every device, no confirmation: the toast can take it back.
        undo: (created) =>
          existing
            ? api.createRule({ domain: row.domain, action: existing.action })
            : api.deleteRule(created.id),
      });
    } else if (action === "forget") {
      void run({
        key: `ai-forget-${row.domain}`,
        action: () => api.forgetAiVerdict(row.domain),
        successTitle: "Forgotten",
        successDetail: `${row.domain} — ${aiForgetSentence(row, now)}`,
        failureTitle: "Could not forget the verdict",
        after: "light",
      }).then((done) => {
        if (!done) return;
        forgot.current = Math.max(0, shown.findIndex((entry) => entry.domain === row.domain));
        changed();
      });
    } else {
      inflight.current?.abort();
      const controller = new AbortController();
      inflight.current = controller;
      // Mounted saying "Checking…", so the answer lands as a change to a live
      // region a screen reader announces, under the row it is about.
      setWhy({ domain: row.domain, text: null });
      api
        .check(row.domain, undefined, { signal: controller.signal })
        .then((result) => {
          if (!controller.signal.aborted) setWhy({ domain: row.domain, text: checkSentence(result) });
        })
        .catch((cause) => {
          if (controller.signal.aborted) return;
          setWhy(null);
          notify.error("Could not check that domain", errorMessage(cause));
        });
    }
  }, []);

  // The answer sits under its own row, as on Overview's cards: above a
  // 200-row table it landed thousands of pixels from the row that asked.
  const answer = React.useCallback(
    (row: AiVerdictRow) =>
      why?.domain === row.domain ? (
        <div className="mt-2 scroll-mb-2" data-why>
          <NoticeBanner
            actions={
              <Button
                onClick={(event) => {
                  // Dismiss goes with the banner; focus goes back to the row's ⋯.
                  const trigger = event.currentTarget.closest("tr, li")?.querySelector<HTMLElement>(ROW_TRIGGER);
                  inflight.current?.abort();
                  setWhy(null);
                  trigger?.focus();
                }}
                size="sm"
                variant="outline"
              >
                Dismiss
              </Button>
            }
            title={why.text ?? `Checking ${row.domain}…`}
            tone="neutral"
          />
        </div>
      ) : null,
    [why],
  );

  // Under the last row on screen, the answer would land below the fold.
  React.useEffect(() => {
    if (why) regionRef.current?.querySelector("[data-why]")?.scrollIntoView({ block: "nearest" });
  }, [why]);

  const menu = React.useCallback(
    (row: AiVerdictRow) => (
      <span className="inline-flex" data-row-actions>
        <RowMenu
          actions={[
            { value: "allow", label: "Allow for everyone", group: "For everyone" },
            { value: "block", label: "Block for everyone", group: "For everyone" },
            { value: "forget", label: "Forget this verdict", group: "AI list" },
            { value: "why", label: "Why?", group: "AI list" },
          ]}
          label={`Actions for ${row.domain}`}
          onSelect={(value) => onAction(row, value)}
        />
      </span>
    ),
    [onAction],
  );

  const columns = React.useMemo<Column<AiVerdictRow>[]>(
    () => [
      {
        key: "name",
        header: "Name",
        primary: true,
        wrap: true,
        render: (row) => (
          <>
            <span className="block min-w-0">
              <span className="block font-mono text-sm [overflow-wrap:anywhere]">
                <DomainName name={row.domain} />
              </span>
              <span className="block truncate text-muted-foreground text-xs">{site(row)}</span>
            </span>
            {answer(row)}
          </>
        ),
      },
      {
        key: "verdict",
        header: "Verdict",
        wrap: true,
        // Room for a note to read as a phrase rather than a word a line.
        className: "min-w-44",
        render: (row) => {
          const notes = notesFor(row);
          return (
            <span className="flex flex-col items-start gap-1">
              {row.verdict === "ignore" ? (
                // No fourth hue for "the lists decide": it is words.
                <span className="text-muted-foreground text-sm">Lists decide</span>
              ) : (
                <StatusPill
                  label={row.verdict === "block" ? "Block" : "Allow"}
                  tone={row.verdict === "block" ? "bad" : "good"}
                  verdict
                />
              )}
              {notes.length > 0 ? <span className="text-muted-foreground text-xs">{notes.join(" · ")}</span> : null}
            </span>
          );
        },
      },
      {
        key: "sure",
        header: "Model's confidence",
        align: "end",
        render: (row) => (
          <span className={row.verdict === "ignore" ? "text-muted-foreground text-xs" : "tabular"}>
            {sureWords(row, false)}
          </span>
        ),
      },
      { key: "lists", header: "Your lists", render: (row) => <ListsWord state={row.lists_now} /> },
      {
        key: "judged",
        header: "Judged",
        align: "end",
        hideBelow: "lg",
        render: (row) => <span className="text-muted-foreground text-xs">{formatRelative(row.judged_at)}</span>,
      },
      { key: "actions", header: "Actions", hideHeader: true, align: "end", stackHeader: true, render: menu },
    ],
    [menu, answer],
  );

  // Domain first; under it the verdict, the model's confidence and the website,
  // as one line of words; the notes, when there are any, on a line of their own.
  const card = React.useCallback(
    (row: AiVerdictRow) => {
      const notes = notesFor(row);
      return (
        <NarrowRow
          actions={menu(row)}
          detail={
            <>
              <span className="block">
                {row.verdict === "ignore" ? (
                  "Lists decide"
                ) : (
                  <span className="font-medium text-foreground">{row.verdict === "block" ? "Block" : "Allow"}</span>
                )}{" "}
                · {sureWords(row, true)} · {site(row)}
              </span>
              {notes.length > 0 ? <span className="mt-1 block">{notes.join(" · ")}</span> : null}
              {answer(row)}
            </>
          }
          lead={
            row.verdict === "ignore" ? null : (
              <Status size="sm" variant={row.verdict === "block" ? "destructive" : "success"} />
            )
          }
          meta={formatRelative(row.judged_at)}
          title={<DomainName name={row.domain} />}
          titleClassName="font-mono"
          wrapTitle
        />
      );
    },
    [menu, answer],
  );

  const shown = page?.counts ?? counts;
  const changes = shown.block + shown.allow;
  const all = changes + shown.ignore;
  const rows = page?.rows ?? [];

  const clearSearch = (
    <Button onClick={() => setSearch("")} size="sm" variant="outline">
      Clear search
    </Button>
  );
  // Changes holds only blocks and allows: a name the model left to the lists
  // is in the AI list, under All judged, and is not said to be missing.
  const empty = q
    ? view === "changes"
      ? {
          icon: SearchXIcon,
          title: "No changes match",
          description: `No blocks or allows contain "${q}".`,
          action: (
            <div className="flex flex-wrap justify-center gap-2">
              <Button onClick={() => setView("all")} size="sm">
                Search all judged
              </Button>
              {clearSearch}
            </div>
          ),
        }
      : {
          icon: SearchXIcon,
          title: "No verdicts match",
          description: `Nothing in the AI list contains "${q}".`,
          action: clearSearch,
        }
    : view === "changes" && all > 0
      ? {
          icon: ListChecksIcon,
          title: "No changes",
          description: "So far the model has left every name it judged to your lists.",
          action: (
            <Button onClick={() => setView("all")} size="sm" variant="outline">
              Show all judged
            </Button>
          ),
        }
      : {
          icon: ListChecksIcon,
          title: "No verdicts yet",
          description:
            state === "reviewing"
              ? "A website's names are usually judged within a minute of a device first opening it."
              : "None are being judged right now; the line under the title says why.",
        };

  return (
    <div className="space-y-4" ref={rootRef}>
      <div className="flex flex-wrap items-start gap-x-gutter gap-y-4">
        <div className="flex flex-col gap-2">
          <GroupLabel id={viewLabel}>Show</GroupLabel>
          <SegmentGroup
            aria-labelledby={viewLabel}
            className="w-fit rounded-lg border p-0.5 pointer-fine:h-8"
            onValueChange={(details) => {
              if (details.value === "changes" || details.value === "all") setView(details.value);
            }}
            value={view}
          >
            <SegmentGroupItem className="px-3" value="changes">
              <SegmentGroupItemText className="text-sm">
                Changes (<span className="tabular">{formatCount(changes)}</span>)
              </SegmentGroupItemText>
            </SegmentGroupItem>
            <SegmentGroupItem className="px-3" value="all">
              <SegmentGroupItemText className="text-sm">
                All judged (<span className="tabular">{formatCount(all)}</span>)
              </SegmentGroupItemText>
            </SegmentGroupItem>
          </SegmentGroup>
        </div>
        <TextField
          className="min-w-0 max-w-md flex-1 basis-56"
          label="Find a name"
          onChange={setSearch}
          placeholder="example.com"
          value={search}
        />
      </div>

      <p className="sr-only" id={hintId}>
        Arrow keys move between rows.
      </p>
      <div
        aria-describedby={hintId}
        aria-label="AI list verdicts"
        onBlur={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget as Node | null)) roving.leave();
        }}
        onFocus={(event) => roving.noteFocus(event.target)}
        onKeyDownCapture={roving.onKeyDownCapture}
        ref={regionRef}
        role="group"
      >
        <DataTable
          card={card}
          columns={columns}
          empty={empty}
          error={error}
          errorTitle="Could not load the AI list"
          loading={loading}
          onRetry={() => setAttempt((count) => count + 1)}
          rowKey={(row) => row.domain}
          rows={rows}
          stackBelow="2xl"
        />
      </div>

      {page && page.total > rows.length ? (
        <p className="text-muted-foreground text-sm">
          Showing the {formatCount(rows.length)} newest of <span className="tabular">{formatCount(page.total)}</span>.
        </p>
      ) : null}
    </div>
  );
}
