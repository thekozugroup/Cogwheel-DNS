/** Presentation helpers. Every one is total: bad input renders a dash, never NaN. */

const DASH = "—";

const compact = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
const plain = new Intl.NumberFormat();

export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return plain.format(value);
}

/** For stat tiles, where a six-digit count would otherwise blow the layout. */
export function formatCompact(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return Math.abs(value) >= 10_000 ? compact.format(value) : plain.format(value);
}

export function formatPercent(fraction: number | null | undefined, digits = 1): string {
  if (fraction === null || fraction === undefined || !Number.isFinite(fraction)) return DASH;
  return `${(fraction * 100).toFixed(digits)}%`;
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return DASH;
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return DASH;

  const deltaSeconds = Math.round((date.getTime() - Date.now()) / 1000);
  const absolute = Math.abs(deltaSeconds);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

  if (absolute < 60) return formatter.format(Math.trunc(deltaSeconds), "second");
  if (absolute < 3600) return formatter.format(Math.trunc(deltaSeconds / 60), "minute");
  if (absolute < 86_400) return formatter.format(Math.trunc(deltaSeconds / 3600), "hour");
  return formatter.format(Math.trunc(deltaSeconds / 86_400), "day");
}

/** mm:ss, for the protection snooze countdown. */
export function formatDuration(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds) || totalSeconds <= 0) return "0:00";
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = Math.floor(totalSeconds % 60);
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

/** Domains from the wire are untrusted text; keep rows from stretching the table. */
export function truncateMiddle(value: string, max = 48): string {
  if (value.length <= max) return value;
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(value.length - tail)}`;
}
