import React from "react";
import { formatCount, formatShare, pluralize } from "@/lib/format";
import { cn } from "@/lib/utils";

type Bucket = { hour: number; queries: number; blocked: number };

/**
 * Hours in the reader's own convention: "6 PM" where the clock is twelve-hour,
 * "18:00" where it is not. A bare "18" is not a time, and "06:00 PM" is not
 * one anybody writes, so the two conventions get different shapes.
 */
const TWELVE_HOUR = new Intl.DateTimeFormat(undefined, { hour: "numeric" }).resolvedOptions().hour12 === true;
const hourFormat = new Intl.DateTimeFormat(
  undefined,
  TWELVE_HOUR ? { hour: "numeric" } : { hour: "2-digit", minute: "2-digit", hourCycle: "h23" },
);

function hourLabel(unixSeconds: number): string {
  return hourFormat.format(new Date(unixSeconds * 1000));
}

/** "6 – 7 PM" / "18:00–19:00": the hour a bar covers, not the instant it starts. */
function hourRange(unixSeconds: number): string {
  const start = new Date(unixSeconds * 1000);
  const end = new Date((unixSeconds + 3600) * 1000);
  // Across midnight formatRange adds both dates ("9/22/2026, 11 PM – 9/23/2026,
  // 12 AM"); the strip only ever spans a day, so the hours alone are enough.
  if (start.getDate() !== end.getDate()) return `${hourFormat.format(start)} – ${hourFormat.format(end)}`;
  return hourFormat.formatRange(start, end);
}

function hourDetail(bucket: Bucket): string {
  return `${hourRange(bucket.hour)}: ${pluralize(bucket.queries, "query", "queries")}, ${formatCount(bucket.blocked)} blocked`;
}

/**
 * The 24-hour bar strip: twenty-four plain divs, a baseline and an hour axis. A
 * chart library is three hundred kilobytes to draw that.
 *
 * The per-hour numbers used to live only in `title` attributes on divs nothing
 * could focus, so a keyboard, a finger and a screen reader got the shape and
 * none of the values. Now the strip is one slider over the hours: arrow keys,
 * Home and End move it, a finger drags along it, a mouse only has to hover, and
 * the readout above the bars prints the hour in words. The figure's caption is
 * the text alternative for the whole: the busiest hour and the day's share
 * blocked.
 */
export function HourStrip({ buckets, queries, blocked }: { buckets: Bucket[]; queries: number; blocked: number }) {
  const count = buckets.length;
  const [hover, setHover] = React.useState<number | null>(null);
  const [pinned, setPinned] = React.useState<number | null>(null);
  // The one pointer that is dragging, so a second finger landing mid-drag
  // neither steals the drag nor starts another one.
  const dragging = React.useRef<number | null>(null);
  const captionId = React.useId();

  const busiest = buckets.reduce((best, bucket, index) => (bucket.queries > buckets[best].queries ? index : best), 0);
  const peak = Math.max(1, buckets[busiest]?.queries ?? 0);
  // An install younger than a day has one or two hours of traffic and drew a
  // 390px rectangle with a sliver at one edge. The strip grows into its full
  // height once there is a shape worth showing.
  const tall = buckets.filter((bucket) => bucket.queries > 0).length >= 4;

  if (count === 0) return null;

  const shown = hover ?? pinned;
  // What a screen reader is told: the pinned hour, or the latest one before
  // anything is pinned. Hover is for the eye only and never moves the value.
  const current = pinned ?? count - 1;
  const clamp = (index: number) => Math.min(count - 1, Math.max(0, index));

  const indexAt = (event: React.PointerEvent<HTMLDivElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    if (rect.width === 0) return count - 1;
    return clamp(Math.floor(((event.clientX - rect.left) / rect.width) * count));
  };

  const endDrag = (event: React.PointerEvent<HTMLDivElement>) => {
    if (dragging.current === event.pointerId) dragging.current = null;
  };

  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const from = pinned ?? count - 1;
    const steps: Record<string, number> = {
      ArrowLeft: from - 1,
      ArrowDown: from - 1,
      ArrowRight: from + 1,
      ArrowUp: from + 1,
      PageDown: from - 6,
      PageUp: from + 6,
      Home: 0,
      End: count - 1,
    };
    if (!(event.key in steps)) return;
    event.preventDefault();
    setHover(null);
    setPinned(clamp(steps[event.key]));
  };

  const summary = `Busiest hour ${hourRange(buckets[busiest].hour)}, with ${pluralize(buckets[busiest].queries, "query", "queries")}. ${formatShare(blocked, queries)} of the day's ${formatCount(queries)} queries were blocked.`;

  return (
    <figure aria-labelledby={captionId} className="@container m-0">
      <figcaption className="sr-only" id={captionId}>
        {summary}
      </figcaption>

      {/* The readout: the hour under the finger, key or pointer, or the day's
          busiest hour when nothing is. Visual only; the slider's value text and
          the caption say the same to assistive technology. */}
      <div aria-hidden className="mb-3 flex min-h-5 flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <p className="tabular text-muted-foreground text-sm">
          {shown === null ? (
            <>
              Busiest <span className="font-medium text-foreground">{hourRange(buckets[busiest].hour)}</span> ·{" "}
              {pluralize(buckets[busiest].queries, "query", "queries")}
            </>
          ) : (
            <>
              <span className="font-medium text-foreground">{hourRange(buckets[shown].hour)}</span> ·{" "}
              {pluralize(buckets[shown].queries, "query", "queries")} · {formatCount(buckets[shown].blocked)} blocked
            </>
          )}
        </p>
        <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-muted-foreground text-xs">
          <span className="flex items-center gap-2">
            <span className="size-2.5 rounded-sm bg-neutral-900 dark:bg-neutral-100" />
            Blocked
          </span>
          <span className="flex items-center gap-2">
            <span className="size-2.5 rounded-sm bg-neutral-300 dark:bg-neutral-600" />
            Answered
          </span>
        </p>
      </div>

      <div
        aria-label="Hour"
        aria-valuemax={count - 1}
        aria-valuemin={0}
        aria-valuenow={current}
        aria-valuetext={hourDetail(buckets[current])}
        // The gap is in pixels and shrinks with the strip: a rem gap at 200% text
        // was 8px, and twenty-three of them were wider than a phone's strip.
        className={cn(
          "relative flex touch-pan-y select-none items-end gap-[clamp(1px,0.4%,4px)] rounded-sm",
          tall ? "h-32" : "h-16",
        )}
        onBlur={() => {
          setPinned(null);
          dragging.current = null;
        }}
        // Keyboard focus lands on the latest hour; a press has already pinned
        // the hour under it by the time focus arrives, and keeps it.
        onFocus={() => setPinned((pinnedNow) => pinnedNow ?? count - 1)}
        onKeyDown={onKeyDown}
        onLostPointerCapture={endDrag}
        onPointerCancel={endDrag}
        onPointerDown={(event) => {
          if (event.pointerType !== "mouse") {
            if (dragging.current !== null) return;
            dragging.current = event.pointerId;
            event.currentTarget.setPointerCapture(event.pointerId);
          }
          setPinned(indexAt(event));
        }}
        onPointerLeave={(event) => {
          if (event.pointerType === "mouse") setHover(null);
        }}
        onPointerMove={(event) => {
          if (event.pointerType === "mouse") setHover(indexAt(event));
          else if (dragging.current === event.pointerId) setPinned(indexAt(event));
        }}
        onPointerUp={endDrag}
        role="slider"
        tabIndex={0}
      >
        {/* The baseline. Without it an hour with no traffic is
            indistinguishable from a chart that failed to render. */}
        <span aria-hidden className="pointer-events-none absolute inset-x-0 bottom-0 h-px bg-border" />
        {buckets.map((bucket, index) => {
          const total = Math.round((bucket.queries / peak) * 100);
          const share = bucket.queries === 0 ? 0 : Math.round((bucket.blocked / bucket.queries) * 100);

          return (
            <div aria-hidden className="relative flex h-full flex-1 flex-col justify-end" key={bucket.hour}>
              {index === shown ? (
                <span className="-inset-x-0.5 pointer-events-none absolute inset-y-0 rounded-sm bg-muted" />
              ) : null}
              {/* Blocked is stacked at the foot of the hour's own bar, so the
                  dark portion reads as a share of that hour, not of the day. */}
              <div
                className={cn(
                  "relative flex w-full flex-col justify-end overflow-hidden rounded-sm bg-neutral-300 dark:bg-neutral-600",
                  // While one hour is being read, the others step back.
                  "transition-opacity duration-150 motion-reduce:transition-none",
                  shown !== null && index !== shown && "opacity-40",
                )}
                // An hour with no traffic draws nothing but the baseline. A
                // one-percent sliver reads as a little traffic, which is the
                // one thing it is not.
                style={{ height: `${bucket.queries === 0 ? 0 : Math.max(total, 2)}%` }}
              >
                <div className="w-full bg-neutral-900 dark:bg-neutral-100" style={{ height: `${share}%` }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Four labels, one every six hours, each at the start of its hour. A
          label per bar was squeezed into a twenty-fourth of the width; below
          16rem of strip (a 320px phone, or large text) only two remain, and
          the in-between two keep their cells so the others stay in place. */}
      <div aria-hidden className="mt-2 grid grid-cols-4">
        {[0, 6, 12, 18].map((index) =>
          buckets[index] ? (
            <span
              className={cn(
                "tabular whitespace-nowrap text-muted-foreground text-xs",
                index % 12 === 6 && "invisible @min-[16rem]:visible",
              )}
              key={index}
            >
              {hourLabel(buckets[index].hour)}
            </span>
          ) : null,
        )}
      </div>
    </figure>
  );
}
