import React from "react";
import { ChevronDownIcon, Trash2Icon } from "lucide-react";
import { api } from "@/lib/api";
import { formatBytes, formatCount, formatInterval, pluralize } from "@/lib/format";
import { blockModeLabel } from "@/lib/derive";
import { cn } from "@/lib/utils";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { StatusPill } from "@/components/app/status-indicator";
import { NoticeBanner } from "@/components/app/states";

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
  const cleartext = settings.upstreams.some((upstream) => !upstream.encrypted);

  return (
    <PageShell>
      <PageHeader
        description="How this appliance is configured. Change these in the environment, then restart."
        title="Settings"
      />

      <PageSections>
        <ConfigCard
          footer={
            // The file the reader actually has, named correctly. This said
            // cogwheel.env for the installer, which is the file
            // scripts/install.sh migrates AWAY from -- editing it would have
            // been a silent no-op on every Docker install. cogwheel.env is the
            // native systemd install's file and nothing else's.
            <p className="text-muted-foreground text-sm">
              Set via <Mono>COGWHEEL_*</Mono> in <Mono>/etc/cogwheel/.env</Mono> — the installer and
              Compose both read it — or <Mono>/etc/cogwheel/cogwheel.env</Mono> for a native systemd
              install. Restart afterwards.
            </p>
          }
          title="Resolver"
        >
          {/* The one finding on this page a person should act on, at the top of
              the card. It used to be 12px grey at the right-hand edge of one
              row — styled as the least important thing on it. */}
          {cleartext ? (
            <NoticeBanner
              className="mb-4"
              detail="Anyone between this appliance and the upstream server — your ISP, a hotel network, whoever runs the Wi-Fi — can read every domain the household looks up. A DoT or DoH upstream encrypts them."
              title="Upstream lookups leave here in cleartext"
              tone="warn"
            />
          ) : null}
          <dl className="max-w-[45rem] divide-y divide-border">
            <Row env="COGWHEEL_UPSTREAM__SERVERS" label="Upstream servers">
              {settings.upstreams.length === 0 ? (
                <span className="text-muted-foreground">—</span>
              ) : (
                <ul className="w-fit space-y-1 sm:ml-auto">
                  {settings.upstreams.map((upstream) => (
                    <li className="flex flex-wrap items-center gap-2" key={upstream.spec}>
                      <span className="font-mono text-sm">{upstream.spec}</span>
                      {/* One status grammar for the whole product. This was the
                          only chromatic Badge left, saying the same kind of
                          thing the neutral pill says on three other pages. */}
                      <StatusPill
                        label={protocolLabel(upstream.protocol)}
                        tone={upstream.encrypted ? "good" : "warn"}
                      />
                    </li>
                  ))}
                </ul>
              )}
            </Row>
            <Row env="COGWHEEL_BLOCKING__MODE" label="Block response">
              {blockModeLabel(settings.block_mode)}
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
            <Row env="COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS" label="List refresh">
              {formatInterval(settings.refresh_interval_secs)}
            </Row>
          </dl>
        </ConfigCard>

        <ConfigCard
          actions={
            <Button onClick={() => setClearing(true)} variant="destructive">
              <Trash2Icon aria-hidden />
              Clear log
            </Button>
          }
          title="Activity log"
        >
          <dl className="max-w-[45rem] divide-y divide-border">
            <Row env="COGWHEEL_RETENTION__HISTORY_DAYS" label="Logging">
              {logging ? `on · ${settings.retention.history_days} days` : "off (0)"}
            </Row>
            <Row env="COGWHEEL_RETENTION__QUERY_LOG_MAX_ROWS" label="Row cap">
              <span className="tabular">{formatCount(settings.retention.max_rows)}</span>
            </Row>
            <Row env="COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS" label="Pruned">
              {formatInterval(settings.retention.prune_interval_secs)}
            </Row>
            <Row env="COGWHEEL_STORAGE__DATABASE_URL" label="Database">
              <span>
                <Mono>{settings.db_path || "—"}</Mono>{" "}
                <span className="tabular text-muted-foreground">
                  ({formatBytes(settings.db_size_bytes)})
                </span>
              </span>
            </Row>
            <Row label="Cached list bodies" note="A lists/ directory beside the database.">
              <Mono>{settings.lists_dir || "—"}</Mono>
            </Row>
          </dl>
        </ConfigCard>

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

        {/* The theme control used to be repeated here. The sidebar copy is
            visible from every page, which is the whole argument for its
            placement; a second one is a second place to change one setting. */}
        <SectionCard title="About">
          <dl className="max-w-[45rem] divide-y divide-border">
            <Row label="Version">
              <Mono>{settings.version || "—"}</Mono>
            </Row>
            <Row label="Database schema">
              <Mono>v{settings.schema_version}</Mono>
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
            successDetail: (result) => `${pluralize(result.deleted, "row")} deleted.`,
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

/**
 * Whether this card is currently showing the `COGWHEEL_*` name behind each row.
 *
 * Nineteen env names printed under nineteen human labels made the machine name
 * the heavier of the two on every row — a long mono string against a short sans
 * one — and turned the page a household owns into a reference card. They are
 * still here, one disclosure per card, closed until asked for.
 */
const ShowEnvNames = React.createContext(false);

function ConfigCard({
  title,
  actions,
  footer,
  children,
}: {
  title: string;
  actions?: React.ReactNode;
  footer?: React.ReactNode;
  children: React.ReactNode;
}) {
  const [showEnv, setShowEnv] = React.useState(false);

  return (
    <SectionCard
      actions={
        <>
          {actions}
          <Button onClick={() => setShowEnv((current) => !current)} size="sm" variant="outline">
            <ChevronDownIcon aria-hidden className={cn("transition-transform", showEnv && "rotate-180")} />
            {showEnv ? "Hide the variable names" : "Show the variable names"}
          </Button>
        </>
      }
      footer={footer}
      title={title}
    >
      <ShowEnvNames.Provider value={showEnv}>{children}</ShowEnvNames.Provider>
    </SectionCard>
  );
}

const Mono = ({ children }: { children: React.ReactNode }) => (
  <span className="font-mono text-foreground text-xs">{children}</span>
);

function Row({
  label,
  env,
  note,
  children,
}: {
  label: string;
  /** The environment variable that sets this value, shown in mono beneath it. */
  env?: string;
  /** Shown in place of `env` for a value nothing sets directly. */
  note?: string;
  children: React.ReactNode;
}) {
  const showEnv = React.useContext(ShowEnvNames);

  return (
    // Only the value may break mid-token. A database path or a list of upstream
    // urls is one unbroken word wider than the card, so it needs `wrap-anywhere`;
    // an env var name is the one string on this page a reader has to retype
    // exactly, so it gets `wrap-break-word`, which breaks only as a last resort
    // and, unlike `anywhere`, still reports its full width as min-content. The
    // label track is floored at that min-content: a value track sized to whatever
    // the path needed used to starve the label column to nothing, which rendered
    // `COGWHEEL_STORAGE__DATABASE_URL` one character per line.
    <div className="grid gap-1 py-3 sm:grid-cols-[minmax(min-content,1fr)_minmax(0,2fr)] sm:gap-6">
      <dt className="min-w-0">
        <span className="block font-medium text-foreground text-sm">{label}</span>
        {env && showEnv ? (
          <span className="block wrap-break-word font-mono text-muted-foreground text-xs">
            {env}
          </span>
        ) : null}
        {note ? <span className="block text-muted-foreground text-xs">{note}</span> : null}
      </dt>
      <dd className="min-w-0 wrap-anywhere text-foreground text-sm sm:text-right">{children}</dd>
    </div>
  );
}

function protocolLabel(protocol: string): string {
  if (protocol === "tls") return "DoT";
  if (protocol === "https") return "DoH";
  return protocol.toUpperCase();
}
