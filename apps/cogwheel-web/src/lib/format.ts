/**
 * Presentation helpers. Every one is total: bad input renders a dash, never
 * NaN. All timestamps on the wire are unix seconds, so that is what these take.
 */

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

export function formatShare(part: number, whole: number, digits = 1): string {
  if (!Number.isFinite(part) || !Number.isFinite(whole) || whole <= 0) return "0%";
  return `${((part / whole) * 100).toFixed(digits)}%`;
}

function toDate(seconds: number | null | undefined): Date | null {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds <= 0) return null;
  return new Date(seconds * 1000);
}

export function formatClock(seconds: number | null | undefined): string {
  const date = toDate(seconds);
  if (!date) return DASH;
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function formatRelative(seconds: number | null | undefined): string {
  const date = toDate(seconds);
  if (!date) return DASH;

  const deltaSeconds = Math.round((date.getTime() - Date.now()) / 1000);
  const absolute = Math.abs(deltaSeconds);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

  if (absolute < 60) return formatter.format(Math.trunc(deltaSeconds), "second");
  if (absolute < 3600) return formatter.format(Math.trunc(deltaSeconds / 60), "minute");
  if (absolute < 86_400) return formatter.format(Math.trunc(deltaSeconds / 3600), "hour");
  return formatter.format(Math.trunc(deltaSeconds / 86_400), "day");
}

/** h:mm:ss (or m:ss under an hour), for the pause countdown. */
export function formatDuration(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds) || totalSeconds <= 0) return "0:00";
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = Math.floor(totalSeconds % 60);
  const pad = (value: number) => String(value).padStart(2, "0");
  return hours > 0 ? `${hours}:${pad(minutes)}:${pad(seconds)}` : `${minutes}:${pad(seconds)}`;
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return DASH;
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

export function formatInterval(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return DASH;
  if (seconds % 86_400 === 0) return `${seconds / 86_400}d`;
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/** URLs from the wire are untrusted text; keep rows from stretching the table. */
export function truncateMiddle(value: string, max = 48): string {
  if (value.length <= max) return value;
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(value.length - tail)}`;
}
