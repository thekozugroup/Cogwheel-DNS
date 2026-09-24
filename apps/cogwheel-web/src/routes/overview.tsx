import React from "react";
import { Link } from "react-router-dom";
import { PlayIcon, RotateCwIcon } from "lucide-react";
import { api, type Overview } from "@/lib/api";
import type { Tone } from "@/components/app/status-indicator";
import { formatCount, formatDuration, formatRelative, formatShare, pluralize } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useCogwheelActions, useCogwheelStatus, useSnapshot } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Status } from "@/components/ui/status";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { StatTile } from "@/components/app/stat-tile";
import { LoadingSkeleton } from "@/components/app/states";
import { emptyOverview } from "@/lib/constants";
import { usesNoLists } from "@/lib/derive";
import { useProtectionSummary } from "@/components/layout/protection-state";
import { useProtectionActions } from "@/hooks/use-protection";
import { ConnectCard } from "./overview/connect";
import { DomainCard } from "./overview/domain-card";
import { HourStrip } from "./overview/hour-strip";

/**
 * Overview answers one question first — is the household protected right
 * now — and then shows the day behind the answer.
 *
 * The protection state used to be the smallest type in a row of four equal
 * tiles, the same weight as a query count. Now it is the page's first line, in
 * words, with the one action that changes it beside it; the tiles under it are
 * the detail.
 *
 * There is no page-level "Refresh lists" any more. Re-downloading every list is
 * list maintenance, and Lists has it ("Refresh all") beside the lists it
 * refreshes, with the busy rule on the card that changes. Overview offers it in
 * exactly one state: when the lists have never downloaded, where it is the
 * remedy for the answer on the first line.
 */
export function OverviewScreen() {
  const overview = useSnapshot("overview");
  const settings = useSnapshot("settings");
  const { phase } = useCogwheelStatus();
  const { mutate } = useCogwheelActions();
  const day = overview.last_24h;
  const loading = phase === "loading";

  // Nothing has resolved through the appliance in a day: the chart and both
  // top tables would each say "point a device at the address below", and the
  // address was the last thing on the page. So the address comes first.
  // Nothing has ever loaded — the appliance has not answered and there is no
  // cached copy. The answer says so; the address card and the "nothing to
  // show yet" line under it were claims about an appliance nobody had heard
  // from ("No address to advertise").
  const never = !loading && overview === emptyOverview;
  const firstRun = !loading && !never && day.queries === 0;
  // The counters come from hourly rollups and outlive Clear log; the top
  // tables come from the log itself. Traffic with an empty log is a cleared
  // log (or one that is switched off), not a household with no traffic.
  const logEmpty = !loading && !firstRun && overview.top_queried.length === 0;
  const loggingOff = settings.version !== "" && settings.retention.history_days === 0;

  const addRule = (domain: string, action: "allow" | "block") =>
    void mutate({
      key: `rule-${domain}`,
      action: () => api.createRule({ domain, action }),
      successTitle: action === "allow" ? "Allowed for everyone" : "Blocked for everyone",
      successDetail: `${domain} — the rule beats every list.`,
      failureTitle: "Could not save the rule",
    });

  const connect = <ConnectCard port={overview.connect.port} targets={overview.connect.targets} />;

  return (
    <PageShell>
      <PageHeader title="Overview" />

      <PageSections>
        <Answer />

        {loading ? (
          <LoadingSkeleton rows={4} variant="cards" />
        ) : never ? null : firstRun ? (
          <>
            {connect}
            <Note title="Nothing to show yet.">
              The hourly chart and the top blocked and queried names appear once a device resolves through
              Cogwheel.
            </Note>
          </>
        ) : (
          <>
            <Tiles overview={overview} />

            <SectionCard title="Queries by hour">
              <HourStrip blocked={day.blocked} buckets={day.per_hour} queries={day.queries} />
            </SectionCard>

            {logEmpty ? (
              loggingOff ? (
                <Note title="Query logging is off.">
                  Top blocked and top queried are read from the log. Set COGWHEEL_RETENTION__HISTORY_DAYS to a
                  number of days and restart to keep one.
                </Note>
              ) : (
                <Note title="Log cleared.">
                  Top blocked and top queried fill again as queries arrive; the counts above still cover the whole
                  24 hours.
                </Note>
              )
            ) : (
              <div className="@container">
                <div className="grid grid-cols-1 gap-gutter @4xl:grid-cols-2">
                  <DomainCard
                    blocked
                    empty={
                      day.blocked === 0
                        ? {
                            title: "Nothing blocked in the last 24 hours",
                            description: "Every name your devices asked for was allowed.",
                          }
                        : {
                            title: "No blocks in the log since it was cleared",
                            description: `The ${formatCount(day.blocked)} counted above came before that. New ones appear here as they happen.`,
                          }
                    }
                    onAllow={(domain) => addRule(domain, "allow")}
                    onBlock={(domain) => addRule(domain, "block")}
                    rows={overview.top_blocked}
                    title="Top blocked"
                  />
                  <DomainCard
                    blocked={false}
                    empty={{
                      title: "No queries in the log yet",
                      description: "Names appear here as devices resolve through Cogwheel.",
                    }}
                    onAllow={(domain) => addRule(domain, "allow")}
                    onBlock={(domain) => addRule(domain, "block")}
                    rows={overview.top_queried}
                    title="Top queried"
                  />
                </div>
              </div>
            )}

            {connect}
          </>
        )}
      </PageSections>
    </PageShell>
  );
}

/* -------------------------------------------------------------------------- */

const DOT: Record<Tone, "success" | "warning" | "destructive" | "default"> = {
  good: "success",
  warn: "warning",
  bad: "destructive",
  idle: "default",
};

const names = new Intl.ListFormat(undefined, { style: "long", type: "conjunction" });

type AnswerParts = { tone: Tone; headline: React.ReactNode; support: React.ReactNode; action?: React.ReactNode };

/**
 * The first line of the page. Its own component so the pause countdown, which
 * ticks once a second, re-renders this card and nothing else.
 *
 * Every sentence here is one the code can verify. "Protected" is not said of
 * an appliance no device is using, or one whose lists have not downloaded:
 * those are true states with their own words.
 */
function Answer() {
  const overview = useSnapshot("overview");
  const { devices } = useSnapshot("devices");
  const catalogue = useSnapshot("lists");
  // Built exactly as the Devices page builds it, so both pages agree on which
  // devices have a list behind them.
  const enabledLists = React.useMemo(
    () => new Set(catalogue.lists.filter((list) => list.enabled).map((list) => list.id)),
    [catalogue.lists],
  );
  const { phase, busy, upstreamFailing } = useCogwheelStatus();
  const { mutate, reload } = useCogwheelActions();
  const { resume } = useProtectionActions();
  const { state, paused, remaining, offline } = useProtectionSummary();
  const headingId = React.useId();

  if (phase === "loading") {
    return (
      <div aria-busy="true" aria-label="Loading" className="rounded-xl border border-border bg-card p-gutter">
        <Skeleton className="h-6 w-2/3 max-w-80" />
        <Skeleton className="mt-3 h-4 w-full max-w-96" />
      </div>
    );
  }

  const { lists, last_24h: day } = overview;

  const refreshLists = () =>
    void mutate({
      // The Lists page's key, so its "Refresh all" shows the same run.
      key: "list-refresh-all",
      action: () => api.refreshLists(),
      successTitle: "Lists refreshed",
      successDetail: (results) =>
        results.length === 1 ? `Checked ${results[0].name}.` : `Checked ${results.length} lists.`,
      failureTitle: "Could not refresh lists",
    });

  const toLists = (
    <Button asChild variant="outline">
      <Link to="/lists">Go to Lists</Link>
    </Button>
  );

  const parts: AnswerParts = offline
    ? {
        tone: "bad",
        headline: "Cogwheel is not answering",
        support: state.detail,
        action: (
          <Button onClick={() => void reload()} variant="outline">
            <RotateCwIcon aria-hidden />
            Try again
          </Button>
        ),
      }
    : paused
      ? {
          tone: "warn",
          headline: (
            <>
              Protection is paused · <span className="tabular">{formatDuration(remaining)}</span> left
            </>
          ),
          support: "Every device resolves unfiltered until then.",
          action: (
            <Button isLoading={busy === "resume-runtime"} onClick={() => void resume()} variant="outline">
              <PlayIcon aria-hidden />
              Resume protection
            </Button>
          ),
        }
      : upstreamFailing
        ? {
            // Blocking still answers; everything else goes to the upstream,
            // and the upstream is not answering. Said as what the household
            // sees — pages that do not load — and where the upstream is set.
            tone: "bad",
            headline: "Lookups are failing",
            support:
              "The upstream server has not answered most of the lookups sent to it in the last minute, so names that are not blocked do not resolve. Blocking still works.",
            action: (
              <Button asChild variant="outline">
                <Link to="/settings">See the upstream</Link>
              </Button>
            ),
          }
        : lists.enabled === 0
          ? {
              tone: "warn",
              headline: lists.total === 0 ? "No blocklists yet" : "Every blocklist is switched off",
              support: "Only your own rules are blocking anything.",
              action: toLists,
            }
          : !lists.downloaded
            ? {
                tone: "warn",
                headline: "Your blocklists have not downloaded yet",
                support: "Until one does, only your own rules are blocking anything.",
                action: (
                  <Button isLoading={busy === "list-refresh-all"} onClick={refreshLists} variant="outline">
                    <RotateCwIcon aria-hidden />
                    Refresh lists
                  </Button>
                ),
              }
            : day.queries === 0
              ? {
                  tone: "idle",
                  headline: (
                    <>
                      Cogwheel is ready
                      <span className="font-normal text-muted-foreground"> · no device is using it yet</span>
                    </>
                  ),
                  support: `Any device that uses the address below is filtered by ${pluralize(lists.enabled, "blocklist")}.`,
                }
              : {
                  tone: "good",
                  headline: (
                    <>
                      Your household is protected
                      <span className="font-normal text-muted-foreground">
                        {" · "}
                        {day.blocked === 0 ? "nothing blocked" : `${formatCount(day.blocked)} blocked`} in the last
                        24 hours
                      </span>
                    </>
                  ),
                  support: filteredSentence(
                    devices.filter((device) => !device.filtering).map((device) => device.name),
                    devices
                      .filter((device) => device.filtering && usesNoLists(device, enabledLists))
                      .map((device) => device.name),
                  ),
                };

  // Warning and problem states take the §2 tint, as the sidebar's paused
  // block does: the one card on the page that must not be read past. On a
  // tint, secondary text is the foreground at 80%, never grey.
  const tinted = parts.tone === "warn" || parts.tone === "bad";

  return (
    <section
      aria-labelledby={headingId}
      className={cn(
        "flex flex-wrap items-center justify-between gap-x-gutter gap-y-4 rounded-xl border p-gutter",
        parts.tone === "warn"
          ? "border-warning/40 bg-warning/10"
          : parts.tone === "bad"
            ? "border-destructive/24 bg-destructive/8"
            : "border-border bg-card",
      )}
    >
      <div className="min-w-0 flex-1 basis-80">
        {/* The dot runs inline with the words rather than in a column of its
            own: at 200% text that column cost a third of a phone's width and
            set the answer eight lines tall. */}
        <h2 className="font-semibold text-foreground text-xl" id={headingId}>
          <Status className="me-3 inline-block align-middle ring-0" size="md" variant={DOT[parts.tone]} />
          {parts.headline}
        </h2>
        <p className={cn("mt-1 text-sm", tinted ? "text-foreground/80" : "text-muted-foreground")}>
          {parts.support}
        </p>
      </div>
      {parts.action ? <div className="shrink-0">{parts.action}</div> : null}
    </section>
  );
}

/**
 * "Every device using Cogwheel is filtered except Work Laptop (filtering off)."
 * Only a claim the device list backs. A device with filtering on but no list
 * behind it blocks by rules alone, and the Devices page already calls that a
 * warning — so it is an exception here too, named in the Devices page's words.
 * Counting only the filtering-off devices had this line call such a device
 * filtered directly under a headline that promises the household is protected.
 */
function filteredSentence(off: string[], noLists: string[]): string {
  const total = off.length + noLists.length;
  if (total === 0) return "Every device using Cogwheel is filtered.";
  if (total <= 3) {
    const named = [...off.map((name) => `${name} (filtering off)`), ...noLists.map((name) => `${name} (no lists)`)];
    return `Every device using Cogwheel is filtered except ${names.format(named)}.`;
  }
  const counts = [
    off.length > 0 ? `${formatCount(off.length)} with filtering off` : null,
    noLists.length > 0 ? `${formatCount(noLists.length)} with no lists` : null,
  ].filter((part): part is string => part !== null);
  return `Every device using Cogwheel is filtered except ${names.format(counts)}.`;
}

/* -------------------------------------------------------------------------- */

/**
 * The day in four numbers. Each label says what it counts: "Devices" printed
 * 5 while the Devices page printed 3, because one counts every address seen in
 * a day and the other the devices someone named.
 *
 * Laid out against the width they actually get, in rem, so large text is a
 * narrower container: one column when a tile would be too tight for its own
 * number, two, and four only when four fit.
 */
function Tiles({ overview }: { overview: Overview }) {
  const { last_24h: day, lists, runtime } = overview;

  return (
    <div className="@container">
      <div className="grid grid-cols-1 gap-gutter @2xs:grid-cols-2 @3xl:grid-cols-4">
        <StatTile
          // Suppressed when it says nothing new: at zero, because "2,946 /
          // since last restart: 0" reads as a contradiction to anyone who has
          // not been told the 24-hour figure outlives the process; and when it
          // equals the 24-hour count, because then it is the same number twice.
          hint={
            runtime.queries_total > 0 && runtime.queries_total !== day.queries
              ? `${formatCount(runtime.queries_total)} since this process started`
              : undefined
          }
          label={"Queries (24\u00a0h)"}
          value={formatCount(day.queries)}
        />
        <StatTile
          delta={`${formatShare(day.blocked, day.queries)} of queries`}
          label={"Blocked (24\u00a0h)"}
          value={formatCount(day.blocked)}
        />
        <StatTile
          delta={
            // On a touch screen the link is as tall as a finger needs; it was
            // a 17px line of text, the one link on the page under 44px.
            <Link
              className="underline decoration-border underline-offset-4 hover:decoration-current pointer-coarse:inline-flex pointer-coarse:min-h-11 pointer-coarse:items-center"
              to="/devices"
            >
              {formatCount(day.named_devices)} named · {formatCount(day.unnamed_clients)} unnamed
            </Link>
          }
          label={"Devices seen (24\u00a0h)"}
          value={formatCount(day.active_clients)}
        />
        <StatTile
          delta={`${pluralize(lists.rules_loaded, "rule")} loaded`}
          hint={updatedLabel(lists.last_ok_at)}
          label="Blocklists"
          value={lists.total > lists.enabled ? `${lists.enabled} of ${lists.total} on` : formatCount(lists.enabled)}
        />
      </div>
    </div>
  );
}

/** When a list last downloaded. "Updated now" is not a sentence anyone says. */
function updatedLabel(lastOk: number | null): string {
  if (lastOk === null) return "Not downloaded yet";
  if (Date.now() / 1000 - lastOk < 60) return "Updated under a minute ago";
  return `Updated ${formatRelative(lastOk)}`;
}

/** One line standing in for a section that has nothing to show, and saying why. */
function Note({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <p className="rounded-xl border border-border bg-card px-gutter py-4 text-muted-foreground text-sm">
      <span className="font-medium text-foreground">{title}</span> {children}
    </p>
  );
}
