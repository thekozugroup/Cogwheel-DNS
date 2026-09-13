import React from "react";
import { ChevronDownIcon, Trash2Icon } from "lucide-react";
import { api } from "@/lib/api";
import { formatBytes, formatCount, formatInterval } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { ThemeToggle } from "@/components/layout/theme-toggle";

/**
 * Read-only by design: configuration is environment-only, so every value here
 * is shown next to the variable that sets it rather than behind an input that
 * could not save anyway.
 */
export function SettingsScreen() {
  const { data, mutate } = useCogwheel();
  const settings = data.settings;
  const [clearing, setClearing] = React.useState(false);
  const [showProtected, setShowProtected] = React.useState(false);

  const logging = settings.retention.history_days > 0;

  return (
    <PageShell>
      <PageHeader
        description="How this appliance is configured. Change these in the environment, then restart."
        title="Settings"
      />

      <PageSections>
        <SectionCard
          footer={
            <p className="text-muted-foreground text-sm">
              Set via <Mono>COGWHEEL_*</Mono> in <Mono>/etc/cogwheel/cogwheel.env</Mono> (installer) or{" "}
              <Mono>.env</Mono> (compose), then restart.
            </p>
          }
          title="Resolver"
        >
          <dl className="divide-y divide-border">
            <Row env="COGWHEEL_UPSTREAM__SERVERS" label="Upstream servers">
              {settings.upstreams.length === 0 ? (
                <span className="text-muted-foreground">—</span>
              ) : (
                <ul className="space-y-1">
                  {settings.upstreams.map((upstream) => (
                    <li className="flex flex-wrap items-center gap-2" key={upstream.spec}>
                      <span className="font-mono text-xs">{upstream.spec}</span>
                      <Badge variant={upstream.encrypted ? "success" : "warning"}>
                        {protocolLabel(upstream.protocol)}
                      </Badge>
                      {upstream.encrypted ? null : (
                        <span className="text-muted-foreground text-xs">
                          cleartext — anyone on the path can read these lookups
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </Row>
            <Row env="COGWHEEL_BLOCKING__MODE" label="Block response">
              <Mono>{settings.block_mode || "—"}</Mono>
            </Row>
            <Row env="COGWHEEL_SERVER__HTTP_BIND_ADDR" label="HTTP bind">
              <Mono>{settings.http_bind || "—"}</Mono>
            </Row>
            <Row env="COGWHEEL_SERVER__DNS_UDP_BIND_ADDR" label="DNS bind (UDP)">
              <Mono>{settings.dns_udp_bind || "—"}</Mono>
            </Row>
            <Row env="COGWHEEL_SERVER__DNS_TCP_BIND_ADDR" label="DNS bind (TCP)">
              <Mono>{settings.dns_tcp_bind || "—"}</Mono>
            </Row>
            <Row env="COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS" label="Advertised to devices">
              <Mono>{settings.advertised_targets.join(", ") || "detected at startup"}</Mono>
            </Row>
            <Row env="COGWHEEL_SERVER__ADVERTISED_DNS_PORT" label="Advertised port">
              <Mono>{settings.advertised_port}</Mono>
            </Row>
            <Row env="COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS" label="List refresh interval">
              <Mono>{formatInterval(settings.refresh_interval_secs)}</Mono>
            </Row>
          </dl>
        </SectionCard>

        <SectionCard
          actions={
            <Button onClick={() => setClearing(true)} variant="destructive">
              <Trash2Icon aria-hidden />
              Clear log
            </Button>
          }
          title="Activity log"
        >
          <dl className="divide-y divide-border">
            <Row env="COGWHEEL_RETENTION__HISTORY_DAYS" label="Logging">
              {logging ? `on · ${settings.retention.history_days} days` : "off (0)"}
            </Row>
            <Row env="COGWHEEL_RETENTION__QUERY_LOG_MAX_ROWS" label="Row cap">
              <span className="tabular">{formatCount(settings.retention.max_rows)}</span>
            </Row>
            <Row env="COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS" label="Prune every">
              <Mono>{formatInterval(settings.retention.prune_interval_secs)}</Mono>
            </Row>
            <Row env="COGWHEEL_STORAGE__DATABASE_URL" label="Database">
              <span>
                <Mono>{settings.db_path || "—"}</Mono>{" "}
                <span className="tabular text-muted-foreground">
                  ({formatBytes(settings.db_size_bytes)})
                </span>
              </span>
            </Row>
            <Row env="COGWHEEL_STORAGE__DATABASE_URL" label="Cached list bodies">
              <Mono>{settings.lists_dir || "—"}</Mono>
            </Row>
          </dl>
        </SectionCard>

        <SectionCard title="Protected domains">
          <p className="text-muted-foreground text-sm">
            These {settings.protected_suffixes.length} suffixes are never blocked by a subscribed list —
            they carry updates, captive portals and certificate checks. Your own rules still outrank
            them.
          </p>
          <Button
            className="mt-3"
            onClick={() => setShowProtected((current) => !current)}
            size="sm"
            variant="outline"
          >
            <ChevronDownIcon aria-hidden className={cn("transition-transform", showProtected && "rotate-180")} />
            {showProtected ? "Hide the list" : "Show the list"}
          </Button>
          {showProtected ? (
            <ul className="mt-3 grid gap-1 sm:grid-cols-2 lg:grid-cols-3">
              {settings.protected_suffixes.map((suffix) => (
                <li className="font-mono text-muted-foreground text-xs" key={suffix}>
                  {suffix}
                </li>
              ))}
            </ul>
          ) : null}
        </SectionCard>

        <SectionCard title="About">
          <dl className="divide-y divide-border">
            <Row label="Version">
              <Mono>{settings.version || "—"}</Mono>
            </Row>
            <Row label="Database schema">
              <Mono>v{settings.schema_version}</Mono>
            </Row>
            <Row label="Theme">
              <ThemeToggle />
            </Row>
          </dl>
        </SectionCard>
      </PageSections>

      <ConfirmDialog
        confirmLabel="Clear log"
        consequence="The 24-hour counters are kept — they are stored separately from the log."
        description="Every stored query row is deleted. This cannot be undone."
        destructive
        onConfirm={async () => {
          await mutate({
            key: "clear-log",
            action: () => api.clearQueries(),
            after: "light",
            successTitle: "Query log cleared",
            successDetail: (result) => `${formatCount(result.deleted)} rows deleted.`,
            failureTitle: "Could not clear the log",
          });
        }}
        onOpenChange={setClearing}
        open={clearing}
        title="Clear the query log?"
      />
    </PageShell>
  );
}

const Mono = ({ children }: { children: React.ReactNode }) => (
  <span className="font-mono text-foreground text-xs">{children}</span>
);

function Row({
  label,
  env,
  children,
}: {
  label: string;
  /** The environment variable that sets this value, shown in mono beneath it. */
  env?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-6">
      <dt className="min-w-0">
        <span className="block font-medium text-foreground text-sm">{label}</span>
        {env ? <span className="block font-mono text-muted-foreground text-xs">{env}</span> : null}
      </dt>
      <dd className="min-w-0 text-foreground text-sm sm:text-right">{children}</dd>
    </div>
  );
}

function protocolLabel(protocol: string): string {
  if (protocol === "tls") return "DoT";
  if (protocol === "https") return "DoH";
  return protocol.toUpperCase();
}
