import { api, type CheckResult, type Device } from "@/lib/api";
import { checkSentence, reasonLabel } from "@/lib/derive";
import { formatRelative } from "@/lib/format";

/** What the "Why?" banner under an Overview row says: one sentence, and sometimes a second. */
export type Explanation = { title: string; detail?: string };

/** A rule covers its own name and every name under it, on a label boundary, as the server matches it. */
function covers(rule: string, name: string): boolean {
  return name === rule || name.endsWith(`.${rule}`);
}

const list = new Intl.ListFormat(undefined, { style: "long", type: "conjunction" });

/**
 * "Why?" for a row in Top blocked or Top queried.
 *
 * The household answer alone contradicted the log beside it: youtube.com,
 * blocked 35 times by a rule on Sam's iPhone, answered "Allowed for everyone".
 * So the household verdict is only the first question. Every filtered device
 * with a rule covering the name is asked too, and so is every device on a
 * narrower set of lists when the household blocks it, because those are the
 * two ways a device's answer can differ from the household's. Where they
 * differ, the sentence says where and by what.
 *
 * A name in Top blocked that every scope now allows is still a name the log
 * saw blocked, so the log is asked for its most recent block rather than the
 * banner printing "Allowed" beside a count that says otherwise.
 */
export async function explain(
  domain: string,
  { devices, blocked, signal }: { devices: Device[]; blocked: boolean; signal: AbortSignal },
): Promise<Explanation> {
  const household = await api.check(domain, undefined, { signal });

  // Paused, every scope answers the pause; there is nothing else to find.
  if (household.scope === "paused") return { title: checkSentence(household) };

  const candidates = devices.filter(
    (device) =>
      device.filtering &&
      (device.rules.some((rule) => covers(rule.domain, domain)) ||
        (household.verdict === "block" && !device.all_lists)),
  );
  const answers = await Promise.all(
    candidates.map(async (device) => ({
      device,
      result: await api.check(domain, device.ip_address, { signal }),
    })),
  );
  const differing = answers.filter(({ result }) => result.verdict !== household.verdict);

  if (differing.length > 0) return { title: splitSentence(domain, household, differing) };

  if (blocked && household.verdict === "allow") {
    const page = await api.queries({ q: domain, blocked: true, limit: 50 }, { signal }).catch(() => null);
    const last = page?.rows.find((row) => row.domain === domain);
    if (last) {
      const reason = reasonLabel(last.reason, last.list);
      return {
        title: `${domain} — Allowed for everyone now.`,
        detail: `Last blocked ${formatRelative(last.ts)} on ${last.device_name ?? last.client}${reason ? ` — ${reason}` : ""}.`,
      };
    }
    return {
      title: `${domain} — Allowed for everyone now.`,
      detail: "Activity shows what decided each of its blocks.",
    };
  }

  return { title: checkSentence(household) };
}

/**
 * "youtube.com — Allowed for the household · blocked on Sam's iPhone by a
 * device rule." The device's own reason is named only when every differing
 * device shares it; otherwise the names alone are the true part.
 */
function splitSentence(
  domain: string,
  household: CheckResult,
  differing: { device: Device; result: CheckResult }[],
): string {
  const verdict = household.verdict === "block" ? "Blocked" : "Allowed";
  const opposite = household.verdict === "block" ? "allowed" : "blocked";
  const householdReason = reasonLabel(household.reason, household.list);
  const names = list.format(differing.map(({ device }) => device.name));
  const byRule = differing.every(({ result }) => result.reason === "device_rule");
  const how = byRule ? (differing.length === 1 ? " by a device rule" : " by device rules") : "";

  return `${domain} — ${verdict} for the household${householdReason ? ` (${householdReason})` : ""} · ${opposite} on ${names}${how}.`;
}
