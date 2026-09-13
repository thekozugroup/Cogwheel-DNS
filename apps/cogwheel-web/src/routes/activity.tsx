import React from "react";
import { ActivityIcon, PauseIcon, PlayIcon, RadioIcon, Trash2Icon } from "lucide-react";
import { formatCount, formatTime } from "@/lib/format";
import { ACTIVITY_BUFFER_LIMIT } from "@/lib/constants";
import { useEventStream, type ActivityRow } from "@/hooks/use-event-stream";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, type Column } from "@/components/app/data-table";
import { SelectField } from "@/components/app/select-field";
import { TextField } from "@/components/app/text-field";
import { EmptyState, NoticeBanner } from "@/components/app/states";
import { StatusIndicator, StatusPill } from "@/components/app/status-indicator";

type VerdictFilter = "all" | "blocked" | "allowed";

const STREAM_TONE = {
  open: { tone: "good" as const, label: "Live", detail: "Receiving events as they happen." },
  connecting: { tone: "idle" as const, label: "Connecting", detail: "Opening the event stream…" },
  reconnecting: {
    tone: "warn" as const,
    label: "Reconnecting",
    detail: "The stream dropped. Retrying with a growing delay.",
  },
  paused: { tone: "idle" as const, label: "Paused", detail: "New rows are buffered until you resume." },
};

export function ActivityScreen() {
  const { data } = useCogwheel();
  const [paused, setPaused] = React.useState(false);
  const [verdict, setVerdict] = React.useState<VerdictFilter>("all");
  const [device, setDevice] = React.useState("all");
  const [search, setSearch] = React.useState("");

  const stream = useEventStream(paused);

  const clients = React.useMemo(() => {
    const seen = new Map<string, string>();
    for (const device of data.settings.devices) seen.set(device.ip_address, device.name);
    for (const row of stream.rows) {
      if (!seen.has(row.client)) seen.set(row.client, row.deviceName ?? row.client);
    }
    return [...seen.entries()];
  }, [data.settings.devices, stream.rows]);

  const filtered = React.useMemo(() => {
    const needle = search.trim().toLowerCase();
    return stream.rows.filter((row) => {
      if (device !== "all" && row.client !== device) return false;
      if (verdict === "blocked" && !row.blocked) return false;
      if (verdict === "allowed" && row.blocked) return false;
      if (needle && !row.domain.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [device, search, stream.rows, verdict]);

  const streamColumns: Column<ActivityRow>[] = [
    {
      key: "time",
      header: "Time",
      render: (row) => <span className="tabular text-muted-foreground text-xs">{formatTime(row.observedAt)}</span>,
      sortValue: (row) => row.observedAt,
    },
    {
      key: "domain",
      header: "Domain",
      render: (row) => <span className="font-mono text-xs">{row.domain}</span>,
    },
    {
      key: "client",
      header: "Device",
      render: (row) => row.deviceName ?? row.client,
      hideOnStack: false,
    },
    {
      key: "verdict",
      header: "Verdict",
      render: (row) =>
        row.blocked ? <StatusPill label="Blocked" tone="bad" /> : <StatusPill label="Allowed" tone="good" />,
    },
    {
      key: "detail",
      header: "Detail",
      align: "end",
      hideOnStack: true,
      render: (row) => <span className="text-muted-foreground text-xs">{row.reason ?? "—"}</span>,
    },
  ];

  const status = STREAM_TONE[stream.status];

  return (
    <PageShell>
      <PageHeader
        actions={
          <>
            <Button onClick={() => setPaused((current) => !current)} variant={paused ? "default" : "outline"}>
              {paused ? <PlayIcon aria-hidden /> : <PauseIcon aria-hidden />}
              {paused ? "Resume stream" : "Pause stream"}
            </Button>
            <Button disabled={stream.rows.length === 0} onClick={stream.clear} variant="outline">
              <Trash2Icon aria-hidden />
              Clear
            </Button>
          </>
        }
        description="Every query the resolver answers, streamed live. The buffer holds the most recent 500 rows."
        title="Activity"
      />

      <PageSections>
        {stream.error && stream.status === "reconnecting" ? (
          <NoticeBanner detail={stream.error} title="Live stream unavailable" tone="warn" />
        ) : null}

        <SectionCard
          actions={<StatusIndicator description={status.detail} label={status.label} tone={status.tone} />}
          description={`Showing ${formatCount(filtered.length)} of ${formatCount(stream.rows.length)} buffered rows (cap ${ACTIVITY_BUFFER_LIMIT}).`}
          title="Live query stream"
        >
          <div className="mb-4 grid gap-3 sm:grid-cols-3">
            <TextField
              label="Domain contains"
              onChange={setSearch}
              placeholder="Filter by domain"
              searchTarget
              value={search}
            />
            <SelectField
              label="Device"
              onChange={setDevice}
              options={[
                { value: "all", label: "All devices" },
                ...clients.map(([ip, name]) => ({
                  value: ip,
                  label: name === ip ? ip : `${name} (${ip})`,
                })),
              ]}
              value={device}
            />
            <SelectField
              label="Verdict"
              onChange={(next) => setVerdict(next as VerdictFilter)}
              options={[
                { value: "all", label: "All verdicts" },
                { value: "blocked", label: "Blocked only" },
                { value: "allowed", label: "Allowed only" },
              ]}
              value={verdict}
            />
          </div>

          {paused && stream.pendingCount > 0 ? (
            <NoticeBanner
              actions={
                <Button onClick={() => setPaused(false)} size="sm" variant="outline">
                  Resume and merge
                </Button>
              }
              className="mb-4"
              detail="They will be merged into the list when you resume."
              title={`${formatCount(stream.pendingCount)} row(s) arrived while paused`}
              tone="neutral"
            />
          ) : null}

          {/* Announced politely so a screen reader is told about new rows
              without the list stealing focus mid-read. */}
          <div aria-label="Live query stream" aria-live="polite" role="log">
            {stream.rows.length === 0 && stream.status !== "reconnecting" ? (
              <EmptyState
                description="Queries appear the moment a device resolves through Cogwheel. If nothing arrives, check the connection instructions on Overview."
                icon={RadioIcon}
                title="Waiting for the first query"
              />
            ) : (
              <DataTable
                columns={streamColumns}
                stackBelow="xl"
                empty={{
                  icon: ActivityIcon,
                  title: "No rows match these filters",
                  description: "Widen the domain filter, device or verdict to see buffered traffic.",
                }}
                rowKey={(row) => row.id}
                rows={filtered}
              />
            )}
          </div>
        </SectionCard>
      </PageSections>
    </PageShell>
  );
}
