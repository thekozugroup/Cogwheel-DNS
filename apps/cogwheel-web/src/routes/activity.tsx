import React from "react";
import { useNavigate } from "react-router-dom";
import { ActivityIcon, Trash2Icon } from "lucide-react";
import { api, errorMessage, type QueryRow, type StreamQueryEvent } from "@/lib/api";
import { checkSentence, qtypeLabel, reasonLabel } from "@/lib/derive";
import { formatClock, pluralize } from "@/lib/format";
import { notify } from "@/lib/toast";
import { ACTIVITY_BUFFER_LIMIT, ACTIVITY_PAGE_SIZE } from "@/lib/constants";
import { useCogwheel } from "@/data/context";
import { useQueryStream } from "@/hooks/use-event-stream";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { SegmentGroup, SegmentGroupItem, SegmentGroupItemText } from "@/components/ui/segment-group";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, type Column } from "@/components/app/data-table";
import { SelectField } from "@/components/app/select-field";
import { TextField } from "@/components/app/text-field";
import { RowMenu } from "@/components/app/row-menu";
import { StatusPill } from "@/components/app/status-indicator";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { NoticeBanner } from "@/components/app/states";

type Verdict = "all" | "blocked" | "allowed";

/** A log row and a live frame rendered as one thing. Live frames have no log id. */
type Row = Omit<QueryRow, "id"> & { key: string };

let liveSequence = 0;

function fromFrame(frame: StreamQueryEvent): Row {
  liveSequence += 1;
  return {
    key: `live-${liveSequence}`,
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

export function ActivityScreen() {
  const { data, mutate, reload } = useCogwheel();
  const navigate = useNavigate();

  const [live, setLive] = React.useState(true);
  const [device, setDevice] = React.useState("all");
  const [verdict, setVerdict] = React.useState<Verdict>("all");
  const [search, setSearch] = React.useState("");

  const [rows, setRows] = React.useState<Row[]>([]);
  const [nextBefore, setNextBefore] = React.useState<number | null>(null);
  const [logging, setLogging] = React.useState(true);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [clearing, setClearing] = React.useState(false);
  const [why, setWhy] = React.useState<string | null>(null);

  const filters = React.useMemo(
    () => ({
      client: device !== "all" && device !== "unnamed" ? device : undefined,
      unnamed: device === "unnamed" ? true : undefined,
      blocked: verdict === "all" ? undefined : verdict === "blocked",
      q: search.trim() || undefined,
    }),
    [device, search, verdict],
  );

  // History reload. Debounced because the search field drives it keystroke by
  // keystroke, and every filter is answered by the server, not in the browser.
  React.useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setLoading(true);
      api
        .queries({ ...filters, limit: ACTIVITY_PAGE_SIZE }, { signal: controller.signal })
        .then((page) => {
          setRows(page.rows.map((row) => ({ ...row, key: `log-${row.id}` })));
          setNextBefore(page.next_before);
          setLogging(page.logging);
          setError(null);
        })
        .catch((cause) => {
          if (cause instanceof DOMException && cause.name === "AbortError") return;
          setError(errorMessage(cause));
        })
        .finally(() => setLoading(false));
    }, 250);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [filters]);

  const onFrame = React.useCallback(
    (frame: StreamQueryEvent) => {
      if (filters.client && frame.client !== filters.client) return;
      // Device = Unnamed asks for the clients with no `devices` row; a live
      // frame carries the name when there is one, which is the same question.
      if (filters.unnamed && frame.deviceName) return;
      if (filters.blocked !== undefined && frame.blocked !== filters.blocked) return;
      if (filters.q && !frame.domain.toLowerCase().includes(filters.q.toLowerCase())) return;

      setRows((current) => {
        // The writer flushes to SQLite every 5 s, so a frame and its log row can
        // both arrive; the newest 50 rows are the only window where they overlap.
        const duplicate = current
          .slice(0, 50)
          .some((row) => row.ts === frame.ts && row.client === frame.client && row.domain === frame.domain);
        if (duplicate) return current;
        return [fromFrame(frame), ...current].slice(0, ACTIVITY_BUFFER_LIMIT);
      });
    },
    [filters],
  );

  const stream = useQueryStream(live, onFrame);

  const loadOlder = async () => {
    if (nextBefore === null) return;
    try {
      const page = await api.queries({ ...filters, before: nextBefore, limit: ACTIVITY_PAGE_SIZE });
      setRows((current) => [...current, ...page.rows.map((row) => ({ ...row, key: `log-${row.id}` }))]);
      setNextBefore(page.next_before);
    } catch (cause) {
      notify.error("Could not load older rows", errorMessage(cause));
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
      setRows([]);
      setNextBefore(null);
    }
  };

  const addRule = (domain: string, action: "allow" | "block", deviceId?: string) =>
    mutate({
      key: `rule-${domain}`,
      action: () => api.createRule({ domain, action, device_id: deviceId }),
      successTitle: action === "allow" ? "Allow rule saved" : "Block rule saved",
      successDetail: domain,
      failureTitle: "Could not save the rule",
    });

  const explain = async (row: Row) => {
    try {
      setWhy(checkSentence(await api.check(row.domain, row.client)));
    } catch (cause) {
      notify.error("Could not check that domain", errorMessage(cause));
    }
  };

  const columns: Column<Row>[] = [
    {
      key: "ts",
      header: "Time",
      render: (row) => <span className="tabular text-muted-foreground text-xs">{formatClock(row.ts)}</span>,
    },
    {
      key: "domain",
      header: "Domain",
      render: (row) => (
        <span className="font-mono text-xs" title={row.domain}>
          {row.domain}
        </span>
      ),
    },
    {
      key: "device",
      header: "Device",
      render: (row) =>
        row.device_name ? (
          row.device_name
        ) : (
          <span className="flex items-center gap-2">
            <span className="font-mono text-xs">{row.client}</span>
            <span className="text-muted-foreground text-xs">unnamed</span>
          </span>
        ),
    },
    {
      key: "qtype",
      header: "Type",
      hideBelow: "xl",
      render: (row) => <span className="text-muted-foreground text-xs">{qtypeLabel(row.qtype)}</span>,
    },
    {
      key: "verdict",
      header: "Verdict",
      render: (row) => {
        const reason = reasonLabel(row.reason, row.list);
        return (
          <span className="flex flex-wrap items-center gap-2">
            <StatusPill label={row.blocked ? "Blocked" : "Allowed"} tone={row.blocked ? "bad" : "good"} />
            {reason ? <span className="text-muted-foreground text-xs">{reason}</span> : null}
          </span>
        );
      },
    },
    {
      key: "actions",
      header: "",
      align: "end",
      stackHeader: true,
      render: (row) => {
        const named = data.devices.devices.find((entry) => entry.ip_address === row.client);
        return (
          <RowMenu
            actions={[
              { value: "allow", label: "Allow for everyone" },
              { value: "block", label: "Block for everyone" },
              ...(named
                ? [
                    { value: "allow-device", label: `Allow on ${named.name}` },
                    { value: "block-device", label: `Block on ${named.name}` },
                  ]
                : [{ value: "name", label: "Name this device…" }]),
              { value: "why", label: "Why?" },
            ]}
            label={`Actions for ${row.domain}`}
            onSelect={(value) => {
              if (value === "allow") void addRule(row.domain, "allow");
              else if (value === "block") void addRule(row.domain, "block");
              else if (value === "allow-device") void addRule(row.domain, "allow", named?.id);
              else if (value === "block-device") void addRule(row.domain, "block", named?.id);
              else if (value === "name") navigate(`/devices?ip=${encodeURIComponent(row.client)}`);
              else void explain(row);
            }}
          />
        );
      },
    },
  ];

  return (
    <PageShell>
      <PageHeader
        description="Every query the resolver answered, most recently answered first."
        title="Activity"
      />

      <PageSections>
        {logging ? null : (
          <NoticeBanner
            detail="Only the live stream is shown. Set a non-zero value and restart to keep history."
            title="Query logging is off (COGWHEEL_RETENTION__HISTORY_DAYS=0)"
            tone="warn"
          />
        )}

        <SectionCard
          actions={
            <span className="flex items-center gap-2 text-sm">
              <Switch
                aria-label="Live"
                checked={live}
                onCheckedChange={(details) => setLive(details.checked)}
              />
              Live
              {live ? (
                <span className="text-muted-foreground text-xs">
                  {stream.status === "open" ? "connected" : stream.status}
                </span>
              ) : null}
            </span>
          }
          description={`${pluralize(rows.length, "row")} shown.`}
          footer={
            <div className="flex flex-wrap items-center gap-2">
              <Button disabled={nextBefore === null} onClick={() => void loadOlder()} variant="outline">
                Load older
              </Button>
              <Button onClick={() => setClearing(true)} variant="destructive">
                <Trash2Icon aria-hidden />
                Clear log
              </Button>
            </div>
          }
          title="Queries"
        >
          {/* `min-w-0` on the columns: without it the Verdict segment group sizes
              to its own content and pushes "Allowed" past the card's edge. */}
          <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 [&>*]:min-w-0">
            <TextField
              label="Domain contains"
              onChange={setSearch}
              placeholder="example.com"
              searchTarget
              value={search}
            />
            <SelectField
              label="Device"
              onChange={setDevice}
              options={[
                { value: "all", label: "All devices" },
                ...data.devices.devices.map((entry) => ({
                  value: entry.ip_address,
                  label: `${entry.name} (${entry.ip_address})`,
                })),
                { value: "unnamed", label: "Unnamed clients" },
              ]}
              value={device}
            />
            <div className="flex flex-col justify-end gap-2">
              <span className="font-medium text-foreground text-sm">Verdict</span>
              <SegmentGroup
                className="rounded-lg border border-border p-0.5"
                onValueChange={(details) => {
                  if (details.value) setVerdict(details.value as Verdict);
                }}
                value={verdict}
              >
                {(["all", "blocked", "allowed"] as const).map((option) => (
                  <SegmentGroupItem className="min-w-0 flex-1 px-2 py-1.5" key={option} value={option}>
                    <SegmentGroupItemText className="text-sm capitalize">{option}</SegmentGroupItemText>
                  </SegmentGroupItem>
                ))}
              </SegmentGroup>
            </div>
          </div>

          {stream.error && live ? (
            <NoticeBanner className="mb-4" title={stream.error} tone="warn" />
          ) : null}

          {/* Above the table, not up with the page header: the answer is about one
              of the rows below and has to be read next to them. */}
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

          <div aria-live="polite" role="log">
            <DataTable
              columns={columns}
              empty={{
                icon: ActivityIcon,
                title: "No queries yet",
                description:
                  "Point a device's DNS at the address on Overview, then reload a page on it — the queries land here within seconds.",
              }}
              error={error}
              loading={loading}
              onRetry={() => void reload()}
              rowKey={(row) => row.key}
              rows={rows}
              stackBelow="xl"
            />
          </div>
        </SectionCard>
      </PageSections>

      <ConfirmDialog
        confirmLabel="Clear log"
        consequence="The 24-hour counters on Overview and Devices are kept — they are stored separately from the log."
        description="Every stored query row is deleted. This cannot be undone."
        destructive
        onConfirm={clearLog}
        onOpenChange={setClearing}
        open={clearing}
        title="Clear the query log?"
      />
    </PageShell>
  );
}
