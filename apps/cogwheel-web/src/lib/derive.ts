import type { CheckResult, ListKind, Reason } from "@/lib/api";
import type { Tone } from "@/components/app/status-indicator";

export type ProtectionState = { tone: Tone; label: string; detail: string; paused: boolean };

/** Seconds left on the pause window, or 0 when protection is not paused. */
export function pauseSecondsRemaining(pausedUntil: number | null, now = Date.now()): number {
  if (!pausedUntil) return 0;
  return Math.max(0, Math.round(pausedUntil - now / 1000));
}

export function protectionState(pausedUntil: number | null, offline: boolean): ProtectionState {
  if (offline) {
    return {
      tone: "bad",
      label: "Unreachable",
      detail: "The control plane did not answer. Filtering may still be running on the appliance.",
      paused: false,
    };
  }
  if (pauseSecondsRemaining(pausedUntil) > 0) {
    return {
      tone: "warn",
      label: "Paused",
      detail: "Every device resolves unfiltered until the pause expires.",
      paused: true,
    };
  }
  return { tone: "good", label: "Protected", detail: "Filtering is active.", paused: false };
}

/**
 * Plain-language version of the step that decided a query. `list` carries the
 * list name for the three tiers that have one, so the row reads "oisd small"
 * rather than "list".
 *
 * "Nothing matched" is the empty string, and the caller renders nothing at all:
 * it is the verdict for most of an allowed household's traffic, and a column
 * that printed "no match" beside eight rows in ten would be saying only that
 * the product works, in vocabulary borrowed from the evaluator.
 */
export function reasonLabel(reason: Reason, list: string | null): string {
  switch (reason) {
    case "device_rule":
      return "device rule";
    case "household_rule":
      return "household rule";
    case "protected":
      return "protected";
    case "list_allow":
      return list ? `allowed by ${list}` : "list allow";
    case "list":
      return list ?? "list";
    case "cname":
      // The record type is the mechanism, not the reason. A household reads
      // "redirected to a blocked domain"; "CNAME → oisd small" is the same
      // fact written for someone holding a packet capture.
      return list ? `redirected to a domain on ${list}` : "redirected to a blocked domain";
    case "paused":
      return "paused";
    case "unfiltered":
      return "unfiltered";
    default:
      return "";
  }
}

/**
 * One sentence naming the step, for the "Why?" answer.
 *
 * It leads with the domain because the answer outlives the click: it is read
 * beside a ten-row table or a two-hundred-row log, and "Blocked for everyone —
 * oisd small." on its own does not say which of those rows it is about.
 */
export function checkSentence(result: CheckResult): string {
  const verdict = result.verdict === "block" ? "Blocked" : "Allowed";
  const scope =
    result.scope === "device" && result.device_name
      ? ` for ${result.device_name}`
      : result.scope === "household"
        ? " for everyone"
        : "";
  const reason = reasonLabel(result.reason, result.list);
  return `${result.domain} — ${verdict}${scope}${reason ? ` — ${reason}` : ""}.`;
}

/**
 * Named by where the file comes from rather than by its syntax: someone
 * subscribing to oisd knows the publisher, not the grammar. The syntax is the
 * field's hint, for the person who has the file open in another tab.
 */
export const LIST_KINDS: { value: ListKind; label: string }[] = [
  { value: "adblock", label: "Adblock-style (oisd, HaGeZi)" },
  { value: "hosts", label: "Hosts file (StevenBlack)" },
  { value: "domains", label: "Plain domains, one per line" },
];

/** The badge in the Lists table. The wire value is `adblock` / `hosts` / `domains`. */
export function listKindLabel(kind: string): string {
  if (kind === "adblock") return "Adblock";
  if (kind === "hosts") return "Hosts";
  if (kind === "domains") return "Domains";
  return kind;
}

export const LIST_KIND_HINT = "Adblock: ||domain^ · Hosts: 0.0.0.0 domain · Plain: domain";

/**
 * A list's fetch failure, as a sentence rather than as the HTTP client's
 * `Display` output.
 *
 * The raw string is the most developer-tool-looking thing a household owner
 * meets — "HTTP status client error (404 File not found) for url
 * (http://…/does-not-exist.txt)" — and it repeats a URL that is already printed
 * under the list's name two lines above. The raw text stays in the server log,
 * where the person who wants it is looking.
 */
export function listErrorSentence(raw: string): string {
  const text = raw.trim();
  if (text === "") return "The download failed.";

  // Only a 4xx/5xx, and only where the text says it is a status. A bare
  // three-digit match would read the `127` out of a localhost URL as a code.
  const status = /(?:status|code)\D{0,16}([1-5]\d{2})\b/i.exec(text) ?? /\b([45]\d{2})\b/.exec(text);
  const code = status ? Number(status[1]) : null;

  if (/timed?\s*out|timeout|deadline/i.test(text)) return "The download timed out.";
  if (/dns error|resolve|no such host|name or service not known/i.test(text)) {
    return "Could not look up that address.";
  }
  if (/connect|connection (refused|reset)|unreachable|tcp|sending request/i.test(text)) {
    return "Could not reach that address.";
  }
  if (/certificate|tls|ssl/i.test(text)) return "The server's certificate could not be verified.";
  if (code === 404) return "That address returned 404 — the list may have moved.";
  if (code === 403 || code === 401) return "That address refused the download.";
  if (code !== null && code >= 500) return `That address returned ${code} — try again later.`;
  if (code !== null && code >= 400) return `That address returned ${code}.`;
  if (/parse|invalid|malformed|utf-?8/i.test(text)) return "The file downloaded but could not be read.";
  return "The download failed.";
}

/** `null_ip`, `nx_domain` and friends as the thing the device actually gets. */
export function blockModeLabel(mode: string): string {
  switch (mode) {
    case "null_ip":
      return "Unroutable address (0.0.0.0)";
    case "nx_domain":
      return "No such domain (NXDOMAIN)";
    case "no_data":
      return "No records (NODATA)";
    case "refused":
      return "Refused";
    default:
      return mode || "—";
  }
}

/** Lower-cases, trims and drops the `*.` a wildcard-minded user might type. */
export function normalizeDomain(value: string): string {
  return value.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
}

/** The server's rule-domain shape: at least two labels, no scheme, no path. */
export function isRuleDomain(value: string): boolean {
  return /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/.test(normalizeDomain(value));
}

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Mirrors the server's `IpAddr` parse so the form rejects before the round trip. */
export function isIpAddress(value: string): boolean {
  const candidate = value.trim();
  const v4 = IPV4.exec(candidate);
  if (v4) return v4.slice(1).every((part) => Number(part) <= 255 && String(Number(part)) === part);
  // Loose but sufficient: hex groups and at most one `::` elision.
  if (!candidate.includes(":")) return false;
  if ((candidate.match(/::/g) ?? []).length > 1) return false;
  return /^[0-9a-f:.]+$/i.test(candidate) && candidate.split(":").length <= 8;
}

export const looksIpv6 = (target: string) => target.includes(":") && !target.includes(".");
