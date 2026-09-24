import React from "react";
import { ListFilterIcon } from "lucide-react";
import type { Device } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { SegmentGroup, SegmentGroupItem, SegmentGroupItemText } from "@/components/ui/segment-group";
import { SelectField } from "@/components/app/select-field";
import { TextField } from "@/components/app/text-field";
import { GroupLabel } from "@/components/app/form-field";
import { VERDICTS, type Verdict } from "./model";

/**
 * The domain field, the device and the verdict.
 *
 * Top-aligned, so the three labels share a baseline. Bottom-aligned, the
 * segment group — 2px taller than a field — lifted its label above the other
 * two. Below sm the device and verdict fold behind "Filters", which counts the
 * active ones: the three were the whole first screen of a phone, and three and
 * a half rows were what was left of it. The domain field never folds; it is
 * the one people use, and `/` has to find it.
 */
export function QueryFilters({
  devices,
  search,
  onSearch,
  device,
  onDevice,
  verdict,
  onVerdict,
  initiallyOpen,
}: {
  devices: Device[];
  search: string;
  onSearch: (value: string) => void;
  device: string;
  onDevice: (value: string) => void;
  verdict: Verdict;
  onVerdict: (value: Verdict) => void;
  /** A link that arrives filtered by device or verdict opens the folded filters on a phone. */
  initiallyOpen: boolean;
}) {
  const [open, setOpen] = React.useState(initiallyOpen);
  const verdictLabelId = React.useId();
  const panelId = React.useId();
  const folded = (device !== "all" ? 1 : 0) + (verdict !== "all" ? 1 : 0);

  const deviceOptions = React.useMemo(
    () => [
      { value: "all", label: "All devices" },
      ...devices.map((entry) => ({ value: entry.ip_address, label: `${entry.name} (${entry.ip_address})` })),
      { value: "unnamed", label: "Unnamed devices" },
    ],
    [devices],
  );

  return (
    <div className="mb-4 flex flex-wrap items-start gap-x-3 gap-y-4 sm:gap-x-gutter">
      <TextField
        className="min-w-0 max-w-md flex-1 basis-40 sm:basis-64"
        label="Domain contains"
        onChange={onSearch}
        placeholder="example.com"
        searchTarget
        value={search}
      />
      <Button
        aria-controls={panelId}
        aria-expanded={open}
        className="shrink-0 self-end sm:hidden"
        onClick={() => setOpen((current) => !current)}
        variant="outline"
      >
        <ListFilterIcon aria-hidden />
        Filters
        {folded > 0 ? (
          <span className="tabular text-muted-foreground">
            {folded}
            <span className="sr-only"> active</span>
          </span>
        ) : null}
      </Button>
      <div className={cn("contents", !open && "max-sm:hidden")} id={panelId}>
        <SelectField
          className="min-w-0 max-w-xs flex-1 basis-56"
          label="Device"
          onChange={onDevice}
          options={deviceOptions}
          value={device}
        />
        <div className="flex flex-col gap-2">
          <GroupLabel id={verdictLabelId}>Verdict</GroupLabel>
          <SegmentGroup
            aria-labelledby={verdictLabelId}
            className="w-fit rounded-lg border p-0.5 pointer-fine:h-8"
            onValueChange={(details) => {
              const next = VERDICTS.find((option) => option === details.value);
              if (next) onVerdict(next);
            }}
            value={verdict}
          >
            {VERDICTS.map((option) => (
              <SegmentGroupItem className="px-3" key={option} value={option}>
                <SegmentGroupItemText className="text-sm capitalize">{option}</SegmentGroupItemText>
              </SegmentGroupItem>
            ))}
          </SegmentGroup>
        </div>
      </div>
    </div>
  );
}
