import type { CheckResult, Device, ListKind, Reason } from "@/lib/api";
import type { Tone } from "@/components/app/status-indicator";

export type ProtectionState = { tone: Tone; label: string; detail: string; paused: boolean };

/** Seconds left on the pause window, or 0 when protection is not paused. */
export function pauseSecondsRemaining(pausedUntil: number | null, now = Date.now()): number {
  if (!pausedUntil) return 0;
  return Math.max(0, Math.round(pausedUntil - now / 1000));
}

/** What the protection state is worked out from. */
export type ProtectionFacts = {
  pausedUntil: number | null;
  /** No answer from the control plane, ever: nothing else can be claimed. */
  offline: boolean;
  /**
   * The overview's list totals and 24-hour query count. Absent until the
   * overview has loaded once, and then only the pause and the outage are said.
   */
  day?: { enabled: number; total: number; downloaded: boolean; queries: number };
  upstreamFailing?: boolean;
};

/**
 * The household's state in a word or two, for the sidebar, the icon rail and
 * the top bar's chip. The same checks, in the same order, as the answer on
 * Overview, which says each of them as a sentence.
 *
 * The sidebar used to know only the pause and the outage, so it said
 * "Protected" beside an answer saying no device was using Cogwheel yet, and
 * beside "No blocklists yet".
 */
export function protectionState({ pausedUntil, offline, day, upstreamFailing: failing }: ProtectionFacts): ProtectionState {
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
  if (!day) return { tone: "idle", label: "Checking", detail: "Waiting for the appliance to answer.", paused: false };
  if (failing) {
    return {
      tone: "bad",
      label: "Lookups failing",
      detail: "The upstream server is not answering, so names that are not blocked do not resolve.",
      paused: false,
    };
  }
  if (day.enabled === 0) {
    return {
      tone: "warn",
      label: day.total === 0 ? "No blocklists" : "Blocklists off",
      detail: "Only your own rules are blocking anything.",
      paused: false,
    };
  }
  if (!day.downloaded) {
    return {
      tone: "warn",
      label: "Not downloaded",
      detail: "Until a blocklist downloads, only your own rules are blocking anything.",
      paused: false,
    };
  }
  if (day.queries === 0) {
    return { tone: "idle", label: "Ready", detail: "No device is using Cogwheel yet.", paused: false };
  }
  return { tone: "good", label: "Protected", detail: "Filtering is active.", paused: false };
}

/** One reading of the resolver's counters, taken from a poll of the overview. */
export type RuntimeSample = { at: number; queries: number; hits: number; failures: number };

/** How far back the upstream verdict looks. */
const UPSTREAM_WINDOW_MS = 60_000;

/**
 * Adds a sample and drops the ones older than the window. The counters are
 * since the process started, so a smaller count means a restart, and the
 * window starts again from it.
 */
export function trackRuntime(samples: RuntimeSample[], next: RuntimeSample): RuntimeSample[] {
  const last = samples.at(-1);
  if (last && next.queries < last.queries) return [next];
  return [...samples, next].filter((sample) => sample.at >= next.at - UPSTREAM_WINDOW_MS);
}

/**
 * Whether the upstream has stopped answering: over the last minute, at least
 * three lookups sent to it failed, and they were at least half of every query
 * the cache could not answer. A healthy upstream fails a lookup now and then;
 * a dead one fails every lookup that is not blocked, and blocked names are
 * only a fifth or so of the misses. With the upstream stopped, Overview said
 * "Your household is protected" while every name that was not blocked
 * returned SERVFAIL.
 */
export function upstreamFailing(samples: RuntimeSample[]): boolean {
  const first = samples[0];
  const last = samples.at(-1);
  if (!first || !last || first === last) return false;
  const failures = last.failures - first.failures;
  const misses = last.queries - first.queries - (last.hits - first.hits);
  return failures >= 3 && failures * 2 >= misses;
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

/**
 * The format as a word or two, for the Lists table and the narrow row. The
 * wire value is `adblock` / `hosts` / `domains`; "Adblock" and "Domains" on
 * their own read as a verdict and a count, so each says what kind of file it is.
 */
export function listKindLabel(kind: string): string {
  if (kind === "adblock") return "Adblock-style";
  if (kind === "hosts") return "Hosts file";
  if (kind === "domains") return "Domain list";
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

/**
 * The domain a person meant, from whatever they typed or pasted.
 *
 * Lower-cases and trims, then keeps only the host: a pasted
 * `https://www.youtube.com/watch?v=…` is `www.youtube.com`, and so is
 * `www.youtube.com/watch`. It also drops a port, a `user@`, the `*.` a
 * wildcard-minded person types, the trailing dot of a fully qualified name,
 * and the `||` and `^` of a line copied out of an adblock-style list.
 *
 * It keeps the `www.`. A rule on `www.youtube.com` is narrower than one on
 * `youtube.com`, and choosing between them is the person's call; the field
 * shows the host it took, so the choice is made in view.
 */
export function normalizeDomain(value: string): string {
  let text = value.trim().toLowerCase();
  text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  text = text.replace(/^\|\|/, "");
  text = text.replace(/^[^/?#@]*@/, "");
  text = text.split(/[/?#^]/)[0] ?? "";
  text = text.replace(/:\d*$/, "");
  return text.replace(/^\*\./, "").replace(/\.$/, "");
}

/**
 * The host to put in a domain field in place of pasted text, or null to let
 * the paste through as typed. Only an address — something with a scheme, a
 * path or a query — is rewritten, and only when what is left is a domain.
 */
export function pastedDomain(text: string): string | null {
  const trimmed = text.trim();
  if (!/:\/\/|[/?#^]|^\|\|/.test(trimmed)) return null;
  const host = normalizeDomain(trimmed);
  return isRuleDomain(host) ? host : null;
}

/** What a domain field says when its form is sent with it empty or wrong. */
export function domainProblem(raw: string, valid: boolean): string | undefined {
  if (!raw.trim()) return "Type a domain, like ads.example.com.";
  if (!valid) return "That is not a domain. Use something like ads.example.com, with no spaces.";
  return undefined;
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

/* -------------------------------------------------------------------------- */
/* Which lists a device actually filters with                                  */
/* -------------------------------------------------------------------------- */

type ListChoice = Pick<Device, "all_lists" | "lists">;

/**
 * The chosen lists that are switched on. A device that chose only lists which
 * are now off filters with nothing: the server gives a disabled list no slot,
 * so `lists` naming it does not make it apply.
 */
export function chosenEnabledLists(device: ListChoice, enabled: ReadonlySet<string>): string[] {
  return device.all_lists ? [...enabled] : device.lists.filter((id) => enabled.has(id));
}

/**
 * "Choose lists" with nothing that applies: filtering is on, and no list
 * blocks anything for this device. Only its rules and the household's do.
 * It reads "On" everywhere a device is summarised unless it is called out.
 */
export function usesNoLists(device: ListChoice, enabled: ReadonlySet<string>): boolean {
  return !device.all_lists && chosenEnabledLists(device, enabled).length === 0;
}

/**
 * The filtering devices that would be left with no list at all if `listId`
 * stopped applying — deleted or disabled. A device on "all lists" keeps the
 * others, so it is only ever stranded by the household's last list going, and
 * that is a sentence of its own.
 */
export function devicesOnlyOnList<D extends ListChoice & { filtering: boolean }>(
  listId: string,
  devices: readonly D[],
  enabled: ReadonlySet<string>,
): D[] {
  return devices.filter((device) => {
    if (!device.filtering || device.all_lists) return false;
    const chosen = chosenEnabledLists(device, enabled);
    return chosen.length === 1 && chosen[0] === listId;
  });
}

/** "Sam's iPhone", "Sam's iPhone and Kids' iPad", "A, B and 3 more". */
export function nameList(names: readonly string[]): string {
  if (names.length === 0) return "";
  if (names.length === 1) return names[0];
  if (names.length > 3) return `${names.slice(0, 2).join(", ")} and ${names.length - 2} more`;
  return `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;
}

/** What stops happening when a list some devices depend on goes. */
export function onlyListSentence(names: readonly string[]): string {
  const verb = names.length === 1 ? "uses" : "use";
  return `${nameList(names)} ${verb} only this list and will have no list filtering.`;
}
