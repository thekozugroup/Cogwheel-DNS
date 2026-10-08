import type {
  AiExplanation,
  AiState,
  AiVerdictRow,
  CheckResult,
  Device,
  ListKind,
  Reason,
  Settings,
} from "@/lib/api";
import { formatCount, formatSure } from "@/lib/format";
import type { Tone } from "@/components/app/status-indicator";

/** The Status dot for a tone, wherever a dot stands beside the words. */
export const TONE_VARIANT = {
  good: "success",
  warn: "warning",
  bad: "destructive",
  idle: "default",
} as const satisfies Record<Tone, "success" | "warning" | "destructive" | "default">;

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
  /** What the AI list is doing, from the overview. Only its blocks change a sentence here. */
  ai?: { applying: boolean; applied_block: number };
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
export function protectionState({
  pausedUntil,
  offline,
  day,
  upstreamFailing: failing,
  ai,
}: ProtectionFacts): ProtectionState {
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
  const blockers = aiBlockers(ai);
  if (day.enabled === 0) {
    return {
      tone: "warn",
      label: day.total === 0 ? "No blocklists" : "Blocklists off",
      detail: `Only ${blockers} blocking anything.`,
      paused: false,
    };
  }
  if (!day.downloaded) {
    return {
      tone: "warn",
      label: "Not downloaded",
      detail: `Until a blocklist downloads, only ${blockers} blocking anything.`,
      paused: false,
    };
  }
  if (day.queries === 0) {
    return { tone: "idle", label: "Ready", detail: "No device is using Cogwheel yet.", paused: false };
  }
  return { tone: "good", label: "Protected", detail: "Filtering is active.", paused: false };
}

/**
 * Whether the AI list blocks anything right now. One holding only allows
 * blocks nothing, and one that is not applying blocks nothing either, so
 * neither is named as though it filtered a device.
 */
export function aiBlocking(ai: { applying: boolean; applied_block: number } | undefined): boolean {
  return Boolean(ai?.applying && ai.applied_block > 0);
}

/** Who blocks anything while no list does, after "Only". */
export function aiBlockers(ai: { applying: boolean; applied_block: number } | undefined): string {
  return aiBlocking(ai) ? "your own rules and the AI list are" : "your own rules are";
}

/** The states in which AI review has stopped judging new names on its own. */
export const AI_STOPPED: ReadonlySet<AiState> = new Set<AiState>([
  "key_refused",
  "out_of_credit",
  "model_refused",
  "stopped",
]);

/**
 * AI review's state in a word, for a dot beside it. The four ways it can stop
 * share one word; the Lists page, where it is fixed, says which.
 */
export function aiStateWord(state: AiState): { tone: Tone; word: string } {
  if (AI_STOPPED.has(state)) return { tone: "bad", word: "Stopped" };
  switch (state) {
    case "reviewing":
      return { tone: "good", word: "On" };
    case "paused_budget":
      return { tone: "warn", word: "Daily limit reached" };
    case "retrying":
      return { tone: "warn", word: "Retrying" };
    case "no_key":
      return { tone: "warn", word: "Waiting for a key" };
    case "unavailable":
      return { tone: "idle", word: "Unavailable" };
    default:
      return { tone: "idle", word: "Off" };
  }
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
    case "ai":
      return "AI list";
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
  const ai = result.ai ?? null;
  const reason = reasonLabel(result.reason, result.list);
  const head = `${result.domain} — ${verdict}${scope}`;
  if (result.reason === "ai") {
    const decided = ai ? aiDecided(ai) : null;
    return `${head} — ${reason}${decided ? `: ${decided}` : ""}.`;
  }
  const aside = ai ? aiAside(ai, result.reason) : null;
  return `${head}${reason ? ` — ${reason}` : ""}.${aside ? ` ${aside}` : ""}`;
}

/** "the model was 93% sure": always the model's certainty, never Cogwheel's. */
function modelSure(confidence: number | null): string {
  return confidence === null ? "" : ` (the model was ${formatSure(confidence)} sure)`;
}

/**
 * Why the AI list decided a name, after "AI list: ". Null in the race case —
 * the verdict was forgotten a moment ago and only its action is left — where
 * nothing may be said that the server did not send.
 */
function aiDecided(ai: AiExplanation): string | null {
  if (ai.choice === null && ai.judged_at === null) return null;
  const sure = modelSure(ai.confidence);
  if (ai.verdict === "allow") {
    const needed = ai.site ? `needed by ${ai.site}` : "judged needed";
    // The household's lists, not the device's: an allow compiles only over a household list
    // block, and a device on fewer lists or none reaches the AI list too.
    return `${needed}${sure}; the household's lists block it`;
  }
  if (ai.verdict === "block") return `${ai.site ? `not needed by ${ai.site}` : "judged not needed"}${sure}`;
  return null;
}

/**
 * What the AI list thinks of a name something else decided: outranked by a
 * rule, unsure, held back by today's limit, or handed back to the lists
 * because two websites disagreed. Null when it has nothing to add.
 */
function aiAside(ai: AiExplanation, reason: Reason): string | null {
  if (reason === "paused" || reason === "unfiltered" || ai.choice === null) return null;
  if (ai.verdict !== "ignore") {
    if (reason === "household_rule" || reason === "device_rule") return `Your rule outranks the AI list's ${ai.verdict}.`;
    if (reason === "protected") return ai.verdict === "block" ? "Protected names outrank the AI list's block." : null;
    // An AI allow keeps the redirect check: the model judged this name, not where it points.
    if (reason === "cname" && ai.verdict === "allow" && ai.applied) {
      return "The AI list allows this name itself, but not the names it redirects to.";
    }
    return ai.applied ? null : `The AI list's ${ai.verdict} is not applied right now; the Lists page says why.`;
  }
  const sure = modelSure(ai.confidence);
  if (ai.why === "contested") {
    return ai.site && ai.conflict_site
      ? `The AI list has no opinion: it was core on ${ai.site} and not on ${ai.conflict_site}.`
      : "The AI list has no opinion: two websites disagreed.";
  }
  if (ai.why === "unsure") {
    // Blocking a name no list touches has a lower bar than overriding a list.
    const bar = ai.choice === "block" && ai.lists === "nothing" ? "a block" : "overriding a list";
    return `The AI list leaned ${ai.choice}${sure}, short of what ${bar} needs.`;
  }
  if (ai.why === "limit") {
    return `The AI list leaned ${ai.choice}${sure}, but today's limit on overriding your lists had been reached.`;
  }
  return null;
}

/**
 * "Why?" for a row of the log, which answers with what decided the name
 * *then*, against `/check`, which says what decides it *now*. When the two
 * verdicts differ the row's is said first and today's after it: a name AI
 * review judged has older rows the lists alone decided, and "Allowed for
 * everyone" beside a row that reads "Blocked" told a household the opposite
 * of what happened. A later rule, a list change or a pause does the same.
 *
 * Two more ways a household meets are both about a redirect: a row blocked
 * because the name it redirected to was on a list, which checked on its own
 * is not blocked at all; and an AI allow, which lifts a list's block on the
 * name the model judged but not on the names it redirects to.
 */
export function whySentence(
  row: { domain: string; blocked: boolean; reason: Reason; list: string | null },
  result: CheckResult,
): string {
  if (row.reason !== "cname") {
    if (row.blocked === (result.verdict === "block")) return checkSentence(result);
    const step = reasonLabel(row.reason, row.list);
    const then = `${row.domain} — ${row.blocked ? "Blocked" : "Allowed"} when it was looked up${step ? ` — ${step}` : ""}.`;
    return `${then} Since then: ${checkSentence(result)}`;
  }
  const then = `${row.domain} — Blocked when it was looked up — ${reasonLabel("cname", row.list)}.`;
  if (result.reason === "no_match") {
    return `${then} Checked on its own, nothing blocks it: the block was on the name it redirects to.`;
  }
  if (result.reason === "ai" && result.verdict === "allow") {
    return `${then} The AI list allows ${row.domain} itself, but not the names it redirects to, so the lookup is still blocked.`;
  }
  return checkSentence(result);
}

/** Whether AI review has ever been set up here: a key, a model, or switched on. */
export function aiSetUp(settings: Settings): boolean {
  const { ai } = settings;
  return ai.enabled || ai.key_source !== "none" || ai.model !== null;
}

/**
 * What Clear log does besides deleting the rows, for both of its dialogs, so
 * Activity's cannot leave out what Settings' says. `counters` is the line
 * about the 24-hour counters, worded for the page it is on. The AI line is
 * there only once review has been set up: before that there is no AI list.
 */
export function clearLogConsequences(settings: Settings, counters: string): string[] {
  if (!aiSetUp(settings)) return [counters];
  return [
    counters,
    "The AI list also forgets which websites its verdicts were judged for, and the names it left to your lists, which are judged, and paid for, again when next seen. Its blocks and allows stay, and so do names two websites disagreed about.",
  ];
}

/** The most questions AI review asks in a UTC day: `REQUESTS_PER_DAY` in the server's ai/review.rs. */
export const AI_REQUESTS_PER_DAY = 2_000;

/** Questions still in flight when that cap stops review: `IN_FLIGHT` in ai/review.rs. */
const AI_IN_FLIGHT = 2;

/**
 * About how many names a daily spending limit pays for at a model's price,
 * never more than the day's questions, and what those questions cost. With a
 * cheap model the cap comes first: Jev at a 10¢ limit stops at about 4¢, and
 * "about 4,800 names a day" promised more than twice what review would ask.
 */
export function aiDailyReach(
  limitUsd: number,
  usdPerThousand: number,
): { names: number; capped: boolean; capUsd: number } {
  const paidFor = (limitUsd / usdPerThousand) * 1000;
  return {
    names: Math.min(paidFor, AI_REQUESTS_PER_DAY),
    capped: paidFor > AI_REQUESTS_PER_DAY,
    capUsd: (AI_REQUESTS_PER_DAY * usdPerThousand) / 1000,
  };
}

/**
 * Which daily limit paused review: the question cap or the spending limit.
 * The server stops at the cap counting the questions still in flight, so a
 * count within those of it is the cap.
 */
export function aiPausedBy(requestsToday: number): "requests" | "spend" {
  return requestsToday >= AI_REQUESTS_PER_DAY - AI_IN_FLIGHT ? "requests" : "spend";
}

/**
 * What Forget means for one verdict, from the card's last read of AI review's
 * state. A name a household rule covers is never sent for review while the
 * rule stands, so it is not promised a second judgement.
 */
export function aiForgetSentence(row: Pick<AiVerdictRow, "outranked_by">, state: AiState): string {
  if (row.outranked_by === "household_rule") {
    return "your rule decides for it, and it is not sent for review while the rule stands.";
  }
  if (state === "reviewing") return "judged again the next time a website loads it.";
  if (state === "paused_budget") {
    return "your lists decide for it until today's limit resets; then it is judged again when a website loads it.";
  }
  if (state === "retrying") return "judged again once OpenRouter answers and a website loads it.";
  return "your lists decide for it.";
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

const deviceNames = new Intl.ListFormat(undefined, { style: "long", type: "conjunction" });

/**
 * "Every device using Cogwheel is filtered except Work Laptop (filtering off)."
 * Only a claim the device list backs. A device with filtering on but no list
 * behind it blocks by rules alone, and the Devices page already calls that a
 * warning — so it is an exception here too, named in the Devices page's words.
 * Counting only the filtering-off devices had this line call such a device
 * filtered directly under a headline that promises the household is protected.
 */
export function filteredSentence(
  off: readonly string[],
  noLists: readonly string[],
  ai: { applying: boolean; applied_block: number },
): string {
  const aiBlocks = aiBlocking(ai);
  const total = off.length + noLists.length;
  if (total === 0) return "Every device using Cogwheel is filtered.";
  // The AI list applies to a device on no lists too (ADR 0002 puts it above
  // every list), so while it blocks something "no lists" is not the whole
  // story. An AI list of allows, or an empty one, filters nothing for it.
  const noListsWord = aiBlocks ? "no lists; AI list only" : "no lists";
  if (total <= 3) {
    const named = [
      ...off.map((name) => `${name} (filtering off)`),
      ...noLists.map((name) => `${name} (${noListsWord})`),
    ];
    return `Every device using Cogwheel is filtered except ${deviceNames.format(named)}.`;
  }
  const counts = [
    off.length > 0 ? `${formatCount(off.length)} with filtering off` : null,
    noLists.length > 0
      ? `${formatCount(noLists.length)} with no lists${aiBlocks ? " (AI list only)" : ""}`
      : null,
  ].filter((part): part is string => part !== null);
  return `Every device using Cogwheel is filtered except ${deviceNames.format(counts)}.`;
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
