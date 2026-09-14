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
      return list ? `CNAME → ${list}` : "CNAME";
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

const QTYPES: Record<number, string> = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  43: "DS",
  48: "DNSKEY",
  64: "SVCB",
  65: "HTTPS",
  255: "ANY",
  257: "CAA",
};

export function qtypeLabel(qtype: number): string {
  return QTYPES[qtype] ?? `TYPE${qtype}`;
}

export const LIST_KINDS: { value: ListKind; label: string }[] = [
  { value: "adblock", label: "adblock (||domain^)" },
  { value: "hosts", label: "hosts (0.0.0.0 domain)" },
  { value: "domains", label: "domains (one per line)" },
];

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
