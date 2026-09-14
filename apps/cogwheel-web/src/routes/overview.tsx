import React from "react";
import { Link } from "react-router-dom";
import { ActivityIcon, CheckIcon, CopyIcon, PlayIcon, RotateCwIcon, ShieldOffIcon } from "lucide-react";
import { api, type DomainCount } from "@/lib/api";
import { checkSentence, looksIpv6, protectionState } from "@/lib/derive";
import { formatCompact, formatCount, formatDuration, formatShare, pluralize } from "@/lib/format";
import { notify } from "@/lib/toast";
import { cn } from "@/lib/utils";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { StatTile } from "@/components/app/stat-tile";
import { RowMenu } from "@/components/app/row-menu";
import { EmptyState, LoadingSkeleton, NoticeBanner } from "@/components/app/states";
import { usePauseCountdown, useProtectionActions } from "@/hooks/use-protection";

/** Three hints cover every platform in the house; more is a manual, not a page. */
const PLATFORMS = [
  { name: "Android", steps: "Wi-Fi settings → modify network → IP settings Static → DNS 1." },
  { name: "iPhone, iPad and Mac", steps: "Wi-Fi → the info icon → Configure DNS → Manual." },
  { name: "Windows", steps: "Network & Internet → Hardware properties → DNS server assignment → Edit." },
];

export function OverviewScreen() {
  const { data, phase, busy, mutate, reload } = useCogwheel();
  const { resume } = useProtectionActions();
  const remaining = usePauseCountdown();
  const overview = data.overview;
  const day = overview.last_24h;
  const state = protectionState(overview.protection.paused_until, false);
  const loading = phase === "loading";

  const refreshLists = () =>
    mutate({
      key: "refresh-lists",
      action: () => api.refreshLists(),
      successTitle: "Lists refreshed",
      successDetail: (results) =>
        results.length === 1 ? `Checked ${results[0].name}.` : `Checked ${results.length} lists.`,
      failureTitle: "Could not refresh lists",
    });

  const addRule = (domain: string, action: "allow" | "block") =>
    mutate({
      key: `rule-${domain}`,
      action: () => api.createRule({ domain, action }),
      successTitle: action === "allow" ? "Allowed for everyone" : "Blocked for everyone",
      successDetail: `${domain} — the rule beats every list.`,
      failureTitle: "Could not save the rule",
    });

  return (
    <PageShell>
      <PageHeader
        actions={
          <>
            <Button isLoading={busy === "refresh-lists"} onClick={() => void refreshLists()} variant="outline">
              <RotateCwIcon aria-hidden />
              Refresh lists
            </Button>
            <Button onClick={() => void reload()} variant="outline">
              Reload
            </Button>
          </>
        }
        description="What the appliance is doing right now, and how to point devices at it."
        title="Overview"
      />

      <PageSections>
        {loading ? (
          <LoadingSkeleton rows={4} variant="cards" />
        ) : (
          <div className="grid gap-6 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile
              footer={
                state.paused ? (
                  <Button
                    className="w-full"
                    isLoading={busy === "resume-runtime"}
                    onClick={() => void resume()}
                    size="sm"
                    variant="outline"
                  >
                    <PlayIcon aria-hidden />
                    Resume
                  </Button>
                ) : null
              }
              hint={
                overview.lists.downloaded ? undefined : (
                  <span className="flex items-center gap-1.5 text-warning-foreground">
                    <Status size="sm" variant="warning" />
                    Lists not downloaded yet
                  </span>
                )
              }
              label="Protection"
              tone={state.tone === "idle" ? "neutral" : state.tone}
              value={state.paused ? `Paused ${formatDuration(remaining)}` : "Protected"}
            />
            <StatTile
              // Suppressed at zero: "2,946 / since last restart: 0" is true, and
              // reads as a contradiction to anyone who has not been told that the
              // 24-hour figure outlives the process.
              hint={
                overview.runtime.queries_total > 0
                  ? `${formatCount(overview.runtime.queries_total)} since this process started`
                  : undefined
              }
              label="Queries (24 h)"
              value={formatCompact(day.queries)}
            />
            <StatTile
              delta={`${formatShare(day.blocked, day.queries)} of queries`}
              label="Blocked (24 h)"
              value={formatCompact(day.blocked)}
            />
            <StatTile
              delta={
                <Link className="hover:underline" to="/devices">
                  {formatCount(day.named_devices)} named · {formatCount(day.unnamed_clients)} unnamed
                </Link>
              }
              label="Devices"
              value={formatCount(day.active_clients)}
            />
          </div>
        )}

        <SectionCard
          description={`${pluralize(day.queries, "query", "queries")}, ${formatCount(day.blocked)} blocked.`}
          title="Last 24 hours"
        >
          <HourStrip buckets={day.per_hour} />
        </SectionCard>

        <div className="grid gap-6 xl:grid-cols-2">
          <DomainCard
            emptyTitle="Nothing blocked yet"
            emptyDescription="Blocked destinations appear once devices resolve through Cogwheel."
            onAllow={(domain) => void addRule(domain, "allow")}
            onBlock={(domain) => void addRule(domain, "block")}
            rows={overview.top_blocked}
            title="Top blocked"
          />
          <DomainCard
            emptyTitle="No queries yet"
            emptyDescription="Point a device at the address below and its traffic shows up here."
            onAllow={(domain) => void addRule(domain, "allow")}
            onBlock={(domain) => void addRule(domain, "block")}
            rows={overview.top_queried}
            title="Top queried"
          />
        </div>

        <SectionCard
          description="Set this as the DNS server on a device, or hand it out over DHCP."
          title="Connect your devices"
        >
          <Targets port={overview.connect.port} targets={overview.connect.targets} />
        </SectionCard>
      </PageSections>
    </PageShell>
  );
}

/* -------------------------------------------------------------------------- */

/**
 * Twenty-four plain divs. A chart library is three hundred kilobytes to draw
 * stacked bars with no axes, no tooltip and no interaction.
 */
function HourStrip({ buckets }: { buckets: { hour: number; queries: number; blocked: number }[] }) {
  const busiest = Math.max(0, ...buckets.map((bucket) => bucket.queries));

  // Twenty-four flat columns and a legend read as a component that failed to
  // load rather than as "nothing has happened yet", so a silent box gets the
  // same empty state the two cards below it get.
  if (buckets.length === 0 || busiest === 0) {
    return (
      <EmptyState
        description="Point a device at the address below; its traffic appears here within the hour."
        icon={ActivityIcon}
        title="No traffic yet"
      />
    );
  }

  const peak = Math.max(1, busiest);

  return (
    <div>
      <div className="flex h-32 items-end gap-1">
        {buckets.map((bucket) => {
          const total = Math.round((bucket.queries / peak) * 100);
          const blocked = bucket.queries === 0 ? 0 : Math.round((bucket.blocked / bucket.queries) * 100);

          return (
            <div
              className="flex h-full flex-1 flex-col justify-end"
              key={bucket.hour}
              title={`${pluralize(bucket.queries, "query", "queries")}, ${formatCount(bucket.blocked)} blocked`}
            >
              {/* Blocked is stacked at the foot of the hour's own bar, so the
                  dark portion reads as a share of that hour, not of the day. */}
              <div
                className="flex w-full flex-col justify-end overflow-hidden rounded-sm bg-neutral-200 dark:bg-neutral-700"
                // An hour with no traffic draws nothing at all; the row of
                // labels below is the axis. A one-percent sliver reads as a
                // little traffic, which is the one thing it is not.
                style={{ height: `${bucket.queries === 0 ? 0 : Math.max(total, 2)}%` }}
              >
                <div
                  className="w-full bg-neutral-900 dark:bg-neutral-100"
                  style={{ height: `${blocked}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-2 flex gap-1">
        {buckets.map((bucket, index) => (
          <span className="tabular flex-1 text-center text-muted-foreground text-xs" key={bucket.hour}>
            {index % 6 === 0 ? new Date(bucket.hour * 1000).getHours() : ""}
          </span>
        ))}
      </div>

      <p className="mt-3 flex flex-wrap items-center gap-4 text-muted-foreground text-xs">
        <span className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm bg-neutral-900 dark:bg-neutral-100" />
          Blocked
        </span>
        <span className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-sm bg-neutral-200 dark:bg-neutral-700" />
          Answered
        </span>
      </p>
    </div>
  );
}

function DomainCard({
  title,
  rows,
  emptyTitle,
  emptyDescription,
  onAllow,
  onBlock,
}: {
  title: string;
  rows: DomainCount[];
  emptyTitle: string;
  emptyDescription: string;
  onAllow: (domain: string) => void;
  onBlock: (domain: string) => void;
}) {
  // Held per card, not per page. A domain in both Top blocked and Top queried
  // is one domain but two rows, and one shared answer printed itself under both
  // of them.
  const [why, setWhy] = React.useState<{ domain: string; sentence: string } | null>(null);

  const explain = async (domain: string) => {
    try {
      setWhy({ domain, sentence: checkSentence(await api.check(domain)) });
    } catch {
      notify.error("Could not check that domain", "The control plane did not answer.");
    }
  };

  return (
    <SectionCard title={title}>
      {rows.length === 0 ? (
        <EmptyState description={emptyDescription} icon={ShieldOffIcon} title={emptyTitle} />
      ) : (
        <ul className="divide-y divide-border">
          {rows.map((row) => (
            <li className="py-1.5" key={row.domain}>
              <div className="flex items-center gap-3">
                <span className="min-w-0 flex-1 truncate font-mono text-xs" title={row.domain}>
                  {row.domain}
                </span>
                <span className="tabular shrink-0 text-sm">{formatCount(row.count)}</span>
                <RowMenu
                  actions={[
                    { value: "allow", label: "Allow for everyone" },
                    { value: "block", label: "Block for everyone" },
                    { value: "why", label: "Why?" },
                  ]}
                  label={`Actions for ${row.domain}`}
                  onSelect={(value) => {
                    if (value === "allow") onAllow(row.domain);
                    else if (value === "block") onBlock(row.domain);
                    else void explain(row.domain);
                  }}
                />
              </div>
              {why?.domain === row.domain ? (
                <NoticeBanner
                  actions={
                    <Button onClick={() => setWhy(null)} size="sm" variant="outline">
                      Dismiss
                    </Button>
                  }
                  className="mt-2"
                  title={why.sentence}
                  tone="neutral"
                />
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}

function Targets({ targets, port }: { targets: string[]; port: number }) {
  const [copied, setCopied] = React.useState<string | null>(null);

  if (targets.length === 0) {
    return (
      <EmptyState
        description="The appliance could not work out its own address. Set COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS and restart."
        icon={ShieldOffIcon}
        title="No address to advertise"
      />
    );
  }

  const copy = async (target: string) => {
    try {
      await navigator.clipboard.writeText(target);
      setCopied(target);
      window.setTimeout(() => setCopied(null), 2_000);
    } catch {
      notify.error("Could not copy", "Select the address and copy it by hand.");
    }
  };

  return (
    <div className="space-y-6">
      <ul className="grid gap-6 sm:grid-cols-2">
        {targets.map((target) => (
          <li
            className="flex items-center justify-between gap-3 rounded-lg border border-border px-3 py-2"
            key={target}
          >
            <div className="min-w-0">
              <span className="block text-muted-foreground text-xs">
                {looksIpv6(target) ? "IPv6" : "IPv4"} · port {port}
              </span>
              <span className="block truncate font-mono text-foreground text-sm">{target}</span>
            </div>
            <Button
              aria-label={`Copy ${target}`}
              className={cn("shrink-0")}
              onClick={() => void copy(target)}
              size="icon-sm"
              variant="ghost"
            >
              {copied === target ? <CheckIcon aria-hidden /> : <CopyIcon aria-hidden />}
            </Button>
          </li>
        ))}
      </ul>

      <ul className="grid gap-6 sm:grid-cols-3">
        {PLATFORMS.map((platform) => (
          <li className="rounded-lg border border-border p-3" key={platform.name}>
            <p className="font-medium text-foreground text-sm">{platform.name}</p>
            <p className="mt-1 text-muted-foreground text-sm">{platform.steps}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}
