import React from "react";
import { ActivityIcon, HardDriveIcon, PlayIcon, RotateCwIcon, ShieldOffIcon } from "lucide-react";
import { api } from "@/lib/api";
import { blockedRatio, protectionState } from "@/lib/derive";
import { formatCompact, formatCount, formatDuration, formatPercent } from "@/lib/format";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { StatTile } from "@/components/app/stat-tile";
import { StatusIndicator } from "@/components/app/status-indicator";
import { DataTable, type Column } from "@/components/app/data-table";
import { EmptyState, LoadingSkeleton } from "@/components/app/states";
import { usePauseCountdown, useProtectionActions } from "@/hooks/use-protection";
import type { DomainInsightEntry } from "@/lib/api";

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Same heuristic the previous UI used: a colon and no dot means IPv6. */
const looksIpv6 = (target: string) => target.includes(":") && !target.includes(".");

export function OverviewScreen() {
  const { data, phase, error, busy, mutate, reload } = useCogwheel();
  const { resume } = useProtectionActions();
  const remaining = usePauseCountdown();

  const loading = phase === "loading";
  const dashboard = data.dashboard;
  const snapshot = dashboard.runtime;
  const state = protectionState(dashboard, false);

  const domainColumns = (countHeader: string, tone: "neutral" | "blocked"): Column<DomainInsightEntry>[] => [
    {
      key: "domain",
      header: "Domain",
      render: (row) => <span className="font-mono text-xs">{row.domain}</span>,
      sortValue: (row) => row.domain,
    },
    {
      key: "count",
      header: countHeader,
      align: "end",
      render: (row) => (
        <span className={tone === "blocked" ? "tabular font-medium" : "tabular"}>
          {formatCount(row.count)}
        </span>
      ),
      sortValue: (row) => row.count,
    },
  ];

  const refreshSources = () =>
    mutate({
      key: "refresh-sources",
      action: () => api.refreshSources(),
      successTitle: "Sources refreshed",
      successDetail: (result) => result.notes[0] ?? `Outcome: ${result.outcome}.`,
      failureTitle: "Could not refresh sources",
    });

  // If the server reports no advertised targets, fall back to whatever address the operator is
  // already reaching this page on — that is almost always the resolver's address too, and it is
  // always true for the person reading it, unlike a hardcoded hostname.
  const primaryTarget =
    data.resolverAccess.dns_targets[0] ?? window.location.hostname;
  const ipv4Target = data.resolverAccess.dns_targets.find((target) => IPV4.test(target)) ?? primaryTarget;
  const ipv6Target = data.resolverAccess.dns_targets.find(looksIpv6);

  const platforms = [
    {
      platform: "Android",
      target: ipv4Target,
      instructions: ipv6Target
        ? "Wi-Fi settings → modify network → IP settings Static, then set DNS 1. Also add the IPv6 resolver below on dual-stack networks. Do not use Android Private DNS unless Cogwheel is serving DNS-over-TLS."
        : "Wi-Fi settings → modify network → IP settings Static, then set DNS 1. Do not use Android Private DNS unless Cogwheel is serving DNS-over-TLS.",
    },
    {
      platform: "iPhone / iPad",
      target: primaryTarget,
      instructions: "Wi-Fi → tap the info icon → Configure DNS → Manual.",
    },
    {
      platform: "Mac",
      target: primaryTarget,
      instructions: "System Settings → Wi-Fi → Details → DNS, then add this resolver.",
    },
    {
      platform: "Windows",
      target: primaryTarget,
      instructions: "Network & Internet → Hardware properties → DNS server assignment → Edit.",
    },
  ];

  return (
    <PageShell>
      <PageHeader
        actions={
          <>
            <Button isLoading={busy === "refresh-sources"} onClick={() => void refreshSources()} variant="outline">
              <RotateCwIcon aria-hidden />
              Refresh sources
            </Button>
            <Button onClick={() => void reload()} variant="outline">
              Reload data
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
                state.paused && remaining > 0 ? (
                  <Button
                    className="w-full"
                    isLoading={busy === "resume-runtime"}
                    onClick={() => void resume()}
                    size="sm"
                    variant="outline"
                  >
                    <PlayIcon aria-hidden />
                    Resume now
                  </Button>
                ) : null
              }
              label="Protection"
              tone={state.tone === "idle" ? "neutral" : state.tone}
              toneLabel={state.label}
              value={
                state.paused && remaining > 0 ? (
                  <span className="tabular">Paused {formatDuration(remaining)}</span>
                ) : (
                  state.label
                )
              }
            />
            <StatTile
              delta={`${formatCount(data.settings.blocklists.length)} configured sources`}
              label="Enabled sources"
              value={formatCount(dashboard.enabled_source_count)}
            />
            <StatTile
              delta={`${formatPercent(blockedRatio(dashboard), 2)} of ${formatCompact(snapshot.queries_total)} queries`}
              hint="Observed by this node since it started"
              label="Blocked queries"
              value={formatCompact(snapshot.blocked_total)}
            />
            <StatTile
              delta={`${formatCount(data.settings.devices.length)} named`}
              hint="Currently visible to the control plane"
              label="Devices"
              value={formatCount(dashboard.device_count)}
            />
          </div>
        )}

        <div className="grid gap-6 xl:grid-cols-2">
          <SectionCard
            description="Busiest destinations seen by this resolver."
            title="Top queried domains"
          >
            <DataTable
              columns={domainColumns("Queries", "neutral")}
              empty={{
                icon: ActivityIcon,
                title: "No query activity yet",
                description:
                  "Activity appears once devices begin sending traffic through Cogwheel. Check the connection instructions below.",
              }}
              error={error}
              loading={loading}
              onRetry={() => void reload()}
              rowKey={(row) => row.domain}
              rows={dashboard.domain_insights.top_queried_domains}
            />
          </SectionCard>

          <SectionCard description="Where filtering is engaging most." title="Top blocked domains">
            <DataTable
              columns={domainColumns("Blocked", "blocked")}
              empty={{
                icon: ShieldOffIcon,
                title: "Nothing blocked yet",
                description:
                  "When filtering engages, the busiest blocked destinations will appear here.",
              }}
              error={error}
              loading={loading}
              onRetry={() => void reload()}
              rowKey={(row) => row.domain}
              rows={dashboard.domain_insights.top_blocked_domains}
            />
          </SectionCard>
        </div>

        <SectionCard
          description="Point a device's DNS setting at one of these addresses."
          title="How to connect devices"
        >
          {data.resolverAccess.dns_targets.length === 0 ? (
            <EmptyState
              description="Resolver targets appear here once the control plane reports reachable DNS addresses."
              icon={HardDriveIcon}
              title="No resolver targets reported"
            />
          ) : (
            <div className="space-y-5">
              <dl className="grid gap-6 sm:grid-cols-2">
                {data.resolverAccess.dns_targets.map((target) => (
                  <div
                    className="flex items-center justify-between gap-3 rounded-lg border border-border px-3 py-2"
                    key={target}
                  >
                    <dt className="text-muted-foreground text-xs">
                      {looksIpv6(target) ? "DNS server (IPv6)" : "DNS server"}
                    </dt>
                    <dd className="truncate font-mono text-foreground text-sm">{target}</dd>
                  </div>
                ))}
              </dl>

              {data.resolverAccess.notes.length > 0 ? (
                <p className="text-muted-foreground text-sm">{data.resolverAccess.notes.join(" ")}</p>
              ) : null}

              <div className="space-y-2">
                <h3 className="font-medium text-foreground text-sm">Per-platform steps</h3>
                <ul className="grid gap-6 sm:grid-cols-2">
                  {platforms.map((entry) => (
                    <li className="rounded-lg border border-border p-3" key={entry.platform}>
                      <p className="font-medium text-foreground text-sm">{entry.platform}</p>
                      <p className="mt-1 text-muted-foreground text-sm">{entry.instructions}</p>
                      <p className="mt-2 font-mono text-foreground text-xs">{entry.target}</p>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </SectionCard>

        <SectionCard description="Counters reported by the DNS runtime." title="Resolver summary">
          <dl className="divide-y divide-border">
            <SummaryRow label="Protection">
              <StatusIndicator label={state.label} tone={state.tone} />
            </SummaryRow>
            <SummaryRow label="Cache hits">
              <span className="tabular">{formatCount(snapshot.cache_hits_total)}</span>
            </SummaryRow>
            <SummaryRow label="Stale served">
              <span className="tabular">{formatCount(snapshot.stale_served_total)}</span>
            </SummaryRow>
            <SummaryRow label="Upstream failures">
              <span className="tabular">{formatCount(snapshot.upstream_failures_total)}</span>
            </SummaryRow>
          </dl>
        </SectionCard>

        <p className="text-muted-foreground text-xs">
          {loading
            ? "Loading control plane data…"
            : `${formatCount(dashboard.enabled_source_count)} enabled blocklists and ${formatCount(
                data.settings.devices.length,
              )} named devices.`}
          {error ? " (showing last-known values)" : null}
        </p>
      </PageSections>
    </PageShell>
  );
}

function SummaryRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2">
      <dt className="text-muted-foreground text-sm">{label}</dt>
      <dd className="text-foreground text-sm">{children}</dd>
    </div>
  );
}
