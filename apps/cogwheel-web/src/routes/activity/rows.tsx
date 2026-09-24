import React from "react";
import { ArrowUpIcon } from "lucide-react";
import { reasonLabel } from "@/lib/derive";
import { formatClock, formatCount } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useSnapshot } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Status } from "@/components/ui/status";
import { NarrowRow } from "@/components/app/data-table";
import { RowMenu } from "@/components/app/row-menu";
import { StatusPill } from "@/components/app/status-indicator";
import type { Row, RowAction } from "./model";

/**
 * The switch, what the stream is doing, and "Show N new". A fixed height
 * whatever it says, so "Show 12 new" arriving never moves the rows under the
 * pointer it is holding them for. Memoised: the feed renders with every batch
 * of rows, and this changes only when its words do.
 */
export const LiveLine = React.memo(function LiveLine({
  live,
  short,
  long,
  held,
  onToggle,
  onShowNew,
}: {
  live: boolean;
  short: string;
  long?: string;
  held: number;
  onToggle: (on: boolean) => void;
  onShowNew: (event: React.MouseEvent<HTMLButtonElement>) => void;
}) {
  const labelId = React.useId();
  const statusId = React.useId();
  return (
    <div className="mb-2 flex h-8 min-w-0 items-center gap-3 pointer-coarse:h-11">
      <span className="flex shrink-0 items-center gap-2" data-live-control>
        <Switch
          aria-describedby={statusId}
          aria-labelledby={labelId}
          checked={live}
          onCheckedChange={(details) => onToggle(details.checked)}
        />
        <span className="font-medium text-foreground text-sm" id={labelId}>
          Live
        </span>
      </span>
      <span
        className={cn("min-w-0 truncate text-xs", live ? "text-muted-foreground" : "font-medium text-foreground")}
        id={statusId}
      >
        {short}
        {long ? <span className="max-sm:hidden">{long}</span> : null}
      </span>
      {held > 0 ? (
        <Button className="ms-auto shrink-0" onClick={onShowNew} size="sm" variant="outline">
          <ArrowUpIcon aria-hidden />
          {/* One text run: the button spaces its children apart. */}
          <span>
            Show <span className="tabular">{formatCount(held)}</span> new
          </span>
        </Button>
      ) : null}
    </div>
  );
});

/**
 * Reports whether the appliance has answered anything in the last 24 hours.
 * Its own component so that the overview, which changes with every poll,
 * re-renders this and nothing else; the feed hears only when the answer flips.
 */
export function AnsweredWatcher({ onChange }: { onChange: (answered: boolean) => void }) {
  const answered = useSnapshot("overview").last_24h.queries > 0;
  React.useEffect(() => onChange(answered), [answered, onChange]);
  return null;
}

/* ------------------------------------------------------------------ rows */

// Each cell is its own memoised component with primitive props, so a batch of
// new rows renders the new rows and nothing else. Every row used to render in
// full on every frame: ~1,500 components a commit at ten queries a second.

export const TimeCell = React.memo(function TimeCell({ ts }: { ts: number }) {
  return <span className="tabular text-muted-foreground text-xs">{formatClock(ts)}</span>;
});

export const DomainCell = React.memo(function DomainCell({ domain }: { domain: string }) {
  return (
    <span className="font-mono text-sm" title={domain}>
      {domain}
    </span>
  );
});

export const DeviceCell = React.memo(function DeviceCell({ name, client }: { name: string | null; client: string }) {
  if (name) return <>{name}</>;
  return (
    <span className="flex items-center gap-2">
      <span className="font-mono text-sm">{client}</span>
      <span className="text-muted-foreground text-xs">unnamed</span>
    </span>
  );
});

/**
 * A pill only for Blocked. Colour marks the exception, never the rule: a
 * column of two hundred green "Allowed" pills pulls the eye to the 86% of rows
 * that need no attention and buries the handful that do.
 */
export const VerdictCell = React.memo(function VerdictCell({
  blocked,
  reason,
  list,
}: {
  blocked: boolean;
  reason: Row["reason"];
  list: string | null;
}) {
  const label = reasonLabel(reason, list);
  return (
    <span className="flex flex-wrap items-center gap-2">
      {blocked ? (
        <StatusPill label="Blocked" tone="bad" verdict />
      ) : (
        <span className="text-muted-foreground text-sm">Allowed</span>
      )}
      {label ? <span className="text-muted-foreground text-xs">{label}</span> : null}
    </span>
  );
});

export const RowActions = React.memo(function RowActions({
  row,
  deviceName,
  onAction,
}: {
  row: Row;
  deviceName?: string;
  onAction: RowAction;
}) {
  return (
    // The scroll margins keep a row the arrow keys moved to clear of the
    // table's sticky header and of the bottom edge.
    <span className="inline-flex scroll-mt-12 scroll-mb-2" data-row-actions>
      <RowMenu
        // By scope: the household's two verbs, the device's two (or naming
        // it), then the question. Five items at one level read as a list to
        // be searched; three groups read as three decisions.
        actions={[
          { value: "allow", label: "Allow for everyone", group: "For everyone" },
          { value: "block", label: "Block for everyone", group: "For everyone" },
          ...(deviceName
            ? [
                { value: "allow-device", label: `Allow on ${deviceName}`, group: `On ${deviceName}` },
                { value: "block-device", label: `Block on ${deviceName}`, group: `On ${deviceName}` },
              ]
            : [{ value: "name", label: "Name this device…", group: row.client }]),
          { value: "why", label: "Why?" },
        ]}
        label={`Actions for ${row.domain}`}
        onSelect={(value) => onAction(row, value)}
      />
    </span>
  );
});

/**
 * A log row is a domain and a verdict; everything else is context. The
 * domain gets the whole first line — it is what people scan the list for —
 * and the time moves down, where it used to keep its full width while the
 * domain truncated to "analytics.twit…" beside it.
 *
 * The verdict is a word, not a bare dot, and the reason travels with it:
 * "Blocked · HaGeZi Pro" is the sentence the whole page is for. Where the
 * row is wide enough (320px of text) verdict, device and time share one line;
 * on a phone that line cannot hold all three without cutting the reason, so
 * the device and the time take a third line and the verdict keeps its own.
 */
export const NarrowQueryRow = React.memo(function NarrowQueryRow({
  row,
  deviceName,
  onAction,
}: {
  row: Row;
  deviceName?: string;
  onAction: RowAction;
}) {
  const reason = reasonLabel(row.reason, row.list);
  const device = row.device_name ?? `${row.client} (unnamed)`;
  return (
    <NarrowRow
      actions={<RowActions deviceName={deviceName} onAction={onAction} row={row} />}
      detail={
        <span className="@container block">
          <span className="flex flex-col gap-0.5 @xs:flex-row @xs:items-baseline @xs:gap-3">
            <span className="min-w-0 truncate @xs:flex-1">
              <span className={row.blocked ? "font-medium text-foreground" : undefined}>
                {row.blocked ? "Blocked" : "Allowed"}
              </span>
              {reason ? ` · ${reason}` : ""}
              <span className="@max-xs:hidden"> · {device}</span>
            </span>
            <span className="flex min-w-0 items-baseline gap-3 @xs:shrink-0">
              <span className="min-w-0 flex-1 truncate @xs:hidden">{device}</span>
              <span className="tabular ms-auto shrink-0">{formatClock(row.ts)}</span>
            </span>
          </span>
        </span>
      }
      lead={row.blocked ? <Status size="sm" variant="destructive" /> : null}
      title={row.domain}
      titleClassName="font-mono"
    />
  );
});
