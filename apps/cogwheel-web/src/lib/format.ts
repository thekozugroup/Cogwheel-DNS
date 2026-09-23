/**
 * Presentation helpers. Every one is total: bad input renders a dash, never
 * NaN. All timestamps on the wire are unix seconds, so that is what these take.
 */

const DASH = "—";

// One format for a count, everywhere. A tile that abbreviated to "23.3K"
// beside a sidebar and a card subtitle that both spelled out "23,320" printed
// one number three times in two notations, and only ever abbreviated the
// larger of the two -- so the same screen disagreed with itself about whether
// abbreviation was the rule. Six digits fit the tile at 375px; there is
// nothing to buy.
const plain = new Intl.NumberFormat();

export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return plain.format(value);
}

/**
 * `1 list`, `2 lists`, `0 lists`. A household appliance is routinely at one of
 * everything, so "1 enabled lists" is the *most* common reading of these
 * strings, not an edge case.
 */
export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${formatCount(count)} ${count === 1 ? singular : plural}`;
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

/**
 * A cadence in words. `1d` is how a crontab writes it; this page is read by
 * someone deciding whether their lists are fresh enough, and "Once a day"
 * answers that without being decoded first.
 */
export function formatInterval(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return DASH;

  const every = (count: number, unit: string) =>
    count === 1 ? `Once ${unit === "hour" ? "an hour" : `a ${unit}`}` : `Every ${count} ${unit}s`;

  if (seconds % 86_400 === 0) return every(seconds / 86_400, "day");
  if (seconds % 3600 === 0) return every(seconds / 3600, "hour");
  if (seconds % 60 === 0) return every(seconds / 60, "minute");
  return every(seconds, "second");
}

/**
 * A list URL, shortened for a table cell without ever cutting the host.
 *
 * `truncateMiddle` on a URL eats the middle, which is where the host ends:
 * `https://raw.githubusercontent.com/hagezi/…/pro.txt` came out as
 * `https://raw.githubuser…/main/pro.txt`, reading as a user called
 * "githubuser". The host is the part a person recognises and the part that
 * decides whether they trust the subscription, so the host always survives
 * whole and the path gives up its middle.
 *
 * What is left of the path is the longest tail that fits AND starts on a `/`,
 * because the distinguishing part of a list URL is usually near the end:
 * StevenBlack's unified and gambling lists are both `…/hosts`, and keeping
 * only the last segment rendered two different subscriptions identically.
 * The full URL is always in the cell's `title`.
 */
export function truncateUrl(value: string, max = 60): string {
  if (value.length <= max) return value;

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return truncateMiddle(value, max);
  }

  const host = `${url.protocol}//${url.host}`;
  const rest = `${url.pathname}${url.search}`;
  const room = max - host.length - 2; // the "/…" that stands in for what is cut
  if (room <= 1 || rest === "") return host.length > max ? truncateMiddle(host, max) : host;

  // Longest `/`-aligned suffix that fits; failing that, the last `room`
  // characters, so something of the path is always shown.
  for (let i = 0; i < rest.length; i += 1) {
    if (rest[i] === "/" && rest.length - i <= room) return `${host}/…${rest.slice(i)}`;
  }
  return `${host}/…${rest.slice(rest.length - room)}`;
}

/** URLs from the wire are untrusted text; keep rows from stretching the table. */
export function truncateMiddle(value: string, max = 48): string {
  if (value.length <= max) return value;
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(value.length - tail)}`;
}
