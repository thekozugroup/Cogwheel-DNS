import React from "react";
import { ChevronDownIcon, Trash2Icon } from "lucide-react";
import { api, type Settings } from "@/lib/api";
import { emptySettings } from "@/lib/constants";
import { formatBytes, formatCount, formatInterval, pluralize } from "@/lib/format";
import { blockModeLabel } from "@/lib/derive";
import { cn } from "@/lib/utils";
import { useCogwheelActions, useCogwheelStatus, useSnapshot } from "@/data/context";
import { Button } from "@/components/ui/button";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { StatusPill } from "@/components/app/status-indicator";
import { ErrorState, LoadingSkeleton, NoticeBanner } from "@/components/app/states";

/**
 * The one measure every paragraph on this page is set to.
 *
 * The cards are the full column, and so are their rows: a label at the start,
 * its value at the end, on the same edge as the card's own buttons. Prose is
 * the exception, because a line of it is read end to end: at the full card it
 * ran 146–153 characters, twice what an eye tracks back from comfortably. `ch`
 * is Inter's zero, which is wider than its average letter: 56ch sets 14px body
 * copy at 70–74 characters a line, measured on the rendered page. The banner's copy is capped to
 * the same value from its call site (Tailwind needs that class spelled out).
 */
const MEASURE = "max-w-[56ch]";

/**
 * Read-only by design: configuration is environment-only, so every value here
 * is shown next to the variable that sets it rather than behind an input that
 * could not save anyway.
 */
export function SettingsScreen() {
  // One field, not the whole snapshot: the overview moves every five seconds
  // under traffic, and nothing on this page reads it.
  const settings = useSnapshot("settings");
  const { phase, error } = useCogwheelStatus();
  const { mutate, reload } = useCogwheelActions();
  const [clearing, setClearing] = React.useState(false);

  return (
    <PageShell>
      <PageHeader
        description="How this appliance is configured. Change these in the environment, then restart."
        title="Settings"
      />

      {/* Until the appliance has answered once there is nothing true to print.
          The empty defaults used to render as settings — "Logging off (0)",
          "These 0 suffixes" — which is a status the code had not checked. */}
      {settings === emptySettings ? (
        phase === "loading" ? (
          <PageSections>
            <SectionCard title="Resolver">
              <LoadingSkeleton rows={4} variant="text" />
            </SectionCard>
            <SectionCard title="Activity log">
              <LoadingSkeleton rows={3} variant="text" />
            </SectionCard>
          </PageSections>
        ) : (
          <ErrorState
            detail={error ?? undefined}
            onRetry={() => void reload()}
            title="Could not read the settings"
          />
        )
      ) : (
        <Loaded onClear={() => setClearing(true)} settings={settings} />
      )}

      <ConfirmDialog
        confirmLabel="Clear log"
        consequence="The 24-hour counters are kept — they are stored separately from the log."
        description="Every stored query row is deleted. This cannot be undone."
        tone="bad"
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

function Loaded({ settings, onClear }: { settings: Settings; onClear: () => void }) {
  const [showProtected, setShowProtected] = React.useState(false);
  const protectedId = React.useId();

  const days = settings.retention.history_days;
  const cleartext = settings.upstreams.some((upstream) => !upstream.encrypted);

  return (
    <PageSections>
      <ConfigCard
        footer={
          // The file the reader actually has, named correctly. This said
          // cogwheel.env for the installer, which is the file
          // scripts/install.sh migrates AWAY from -- editing it would have
          // been a silent no-op on every Docker install. cogwheel.env is the
          // native systemd install's file and nothing else's.
          // `min-w-0` because the footer is a flex row: without it the sentence
          // could not be narrower than /etc/cogwheel/cogwheel.env, which at
          // 200% text is wider than a phone's card.
          <p className={cn(MEASURE, "min-w-0 wrap-break-word text-muted-foreground text-sm")}>
            Set via <Mono>COGWHEEL_*</Mono> in <Mono>/etc/cogwheel/.env</Mono> — the installer and
            Compose both read it — or <Mono>/etc/cogwheel/cogwheel.env</Mono> for a native systemd
            install. Restart afterwards.
          </p>
        }
        notice={
          // The one finding on this page a person should act on, at the top of
          // the card. It used to be 12px grey at the right-hand edge of one
          // row — styled as the least important thing on it. The banner keeps
          // the card's width; its sentences keep the page's measure.
          cleartext ? (
            <NoticeBanner
              className="mb-4 [&_p]:max-w-[56ch]"
              detail="Anyone between this appliance and the upstream server — your ISP, a hotel network, whoever runs the Wi-Fi — can read every domain the household looks up. A DoT or DoH upstream encrypts them."
              title="Upstream lookups leave here in cleartext"
              tone="warn"
            />
          ) : null
        }
        title="Resolver"
      >
        <Row env="COGWHEEL_UPSTREAM__SERVERS" label="Upstream servers">
          {settings.upstreams.length === 0 ? (
            <NotReported />
          ) : (
            <ul className="space-y-1">
              {settings.upstreams.map((upstream) => (
                // Pills on the value edge, so a second upstream's lines up
                // under the first's however long either address is.
                <li className="flex flex-wrap items-center gap-x-2 gap-y-1 sm:justify-end" key={upstream.spec}>
                  <Mono>{upstream.spec}</Mono>
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
          <Address value={settings.http_bind} />
        </Row>
        <Row env="COGWHEEL_SERVER__DNS_UDP_BIND_ADDR" label="DNS bind (UDP)">
          <Address value={settings.dns_udp_bind} />
        </Row>
        <Row env="COGWHEEL_SERVER__DNS_TCP_BIND_ADDR" label="DNS bind (TCP)">
          <Address value={settings.dns_tcp_bind} />
        </Row>
        <Row env="COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS" label="Advertised to devices">
          {/* The fallback is a sentence, not an address, so it is not set in
              mono: the face means "read this character by character". */}
          {settings.advertised_targets.length > 0 ? (
            <Mono>{settings.advertised_targets.join(", ")}</Mono>
          ) : (
            "detected at startup"
          )}
        </Row>
        <Row env="COGWHEEL_SERVER__ADVERTISED_DNS_PORT" label="Advertised port">
          <span className="tabular">{settings.advertised_port}</span>
        </Row>
        <Row env="COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS" label="List refresh">
          {formatInterval(settings.refresh_interval_secs)}
        </Row>
      </ConfigCard>

      <ConfigCard
        actions={
          <Button onClick={onClear} variant="destructive">
            <Trash2Icon aria-hidden />
            Clear log
          </Button>
        }
        title="Activity log"
      >
        <Row env="COGWHEEL_RETENTION__HISTORY_DAYS" label="Logging">
          {days > 0 ? (
            <>
              on · <span className="tabular">{pluralize(days, "day")}</span>
            </>
          ) : (
            "off (0)"
          )}
        </Row>
        <Row env="COGWHEEL_RETENTION__QUERY_LOG_MAX_ROWS" label="Row cap">
          <span className="tabular">{formatCount(settings.retention.max_rows)}</span>
        </Row>
        <Row env="COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS" label="Pruned">
          {formatInterval(settings.retention.prune_interval_secs)}
        </Row>
        <Row env="COGWHEEL_STORAGE__DATABASE_URL" label="Database">
          {settings.db_path ? (
            <>
              <Mono>{settings.db_path}</Mono>{" "}
              <span className="tabular whitespace-nowrap text-muted-foreground">
                ({formatBytes(settings.db_size_bytes)})
              </span>
            </>
          ) : (
            <NotReported />
          )}
        </Row>
        <Row label="Cached list bodies" note="A lists/ directory beside the database.">
          <Address value={settings.lists_dir} />
        </Row>
      </ConfigCard>

      {/* The third disclosure sits where the other two do, at the end of its
          card's title row. It used to sit under the paragraph at the start
          edge, so the page had two places to look for "show me more". */}
      <SectionCard
        actions={
          <Button
            aria-controls={protectedId}
            aria-expanded={showProtected}
            onClick={() => setShowProtected((current) => !current)}
            variant="outline"
          >
            <Chevron open={showProtected} />
            {showProtected ? "Hide the list" : "Show the list"}
          </Button>
        }
        title="Protected domains"
      >
        <p className={cn(MEASURE, "text-muted-foreground text-sm")}>
          These {settings.protected_suffixes.length} suffixes are never blocked by a subscribed list —
          they carry updates, captive portals and certificate checks. Your own rules still outrank
          them.
        </p>
        {/* Rendered closed rather than not at all, so the button's
            aria-controls always names an element that exists. The names are
            the same role as every address on the page: 14px mono, in the
            foreground, because reading one exactly is the reason to open it. */}
        <ul
          className="mt-4 grid gap-x-6 gap-y-1 sm:grid-cols-2 lg:grid-cols-3"
          hidden={!showProtected}
          id={protectedId}
        >
          {settings.protected_suffixes.map((suffix) => (
            <li className="min-w-0 wrap-anywhere font-mono text-foreground text-sm" key={suffix}>
              {suffix}
            </li>
          ))}
        </ul>
      </SectionCard>

      {/* The theme control used to be repeated here. The sidebar copy is
          visible from every page, which is the whole argument for its
          placement; a second one is a second place to change one setting. */}
      <SectionCard title="About">
        <DetailList>
          {/* A version and a schema number are numbers, not addresses: no one
              reads "0.1.0" character by character, so they are not in mono. */}
          <Row label="Version">
            {settings.version ? <span className="tabular">{settings.version}</span> : <NotReported />}
          </Row>
          <Row label="Database schema">
            <span className="tabular">v{settings.schema_version}</span>
          </Row>
        </DetailList>
      </SectionCard>
    </PageSections>
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
  notice,
  footer,
  children,
}: {
  title: string;
  actions?: React.ReactNode;
  /** A banner above the rows, inside the card. */
  notice?: React.ReactNode;
  footer?: React.ReactNode;
  /** The card's `Row`s. */
  children: React.ReactNode;
}) {
  const [showEnv, setShowEnv] = React.useState(false);
  const listId = React.useId();

  return (
    <SectionCard
      actions={
        <>
          {actions}
          <Button
            aria-controls={listId}
            aria-expanded={showEnv}
            onClick={() => setShowEnv((current) => !current)}
            variant="outline"
          >
            <Chevron open={showEnv} />
            {showEnv ? "Hide the variable names" : "Show the variable names"}
          </Button>
        </>
      }
      footer={footer}
      title={title}
    >
      {notice}
      <ShowEnvNames.Provider value={showEnv}>
        <DetailList id={listId}>{children}</DetailList>
      </ShowEnvNames.Provider>
    </SectionCard>
  );
}

/**
 * The rows run the card's full width, so a value ends on the same edge as the
 * card's buttons. They were capped at 45rem, which left every value about
 * 360px short of the button above it at 1440 — two right edges in one card.
 */
function DetailList({ id, children }: { id?: string; children: React.ReactNode }) {
  return (
    <dl className="divide-y divide-border" id={id}>
      {children}
    </dl>
  );
}

function Chevron({ open }: { open: boolean }) {
  return <ChevronDownIcon aria-hidden className={cn("transition-transform", open && "rotate-180")} />;
}

/**
 * An address or a path: the one kind of value set in mono, because reading it
 * character by character is the point. It takes the size of the text around
 * it — 14px in a value, 14px in a sentence — where it used to be 12px beside
 * 14px sans values in the same column, as if it were a footnote to them.
 */
function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono">{children}</span>;
}

function Address({ value }: { value: string }) {
  return value ? <Mono>{value}</Mono> : <NotReported />;
}

/** A value the server did not send. Said, not just drawn: a bare dash reads as nothing. */
function NotReported() {
  return (
    <span className="text-muted-foreground">
      <span aria-hidden>—</span>
      <span className="sr-only">Not reported</span>
    </span>
  );
}

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
      {/* The value hugs the end edge while it fits on one line. When it has to
          wrap — a long database path — it takes the whole track and wraps
          left-aligned: right-aligned lines of a path start at a different place
          each time, which is the one thing a path must not do. */}
      <dd className="min-w-0 text-foreground text-sm sm:flex sm:justify-end">
        <div className="min-w-0 wrap-anywhere">{children}</div>
      </dd>
    </div>
  );
}

function protocolLabel(protocol: string): string {
  if (protocol === "tls") return "DoT";
  if (protocol === "https") return "DoH";
  return protocol.toUpperCase();
}
