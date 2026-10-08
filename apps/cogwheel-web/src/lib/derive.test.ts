import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { AiExplanation, AiState, CheckResult, Settings } from "@/lib/api";
import { emptySettings } from "@/lib/constants";
import {
  AI_REQUESTS_PER_DAY,
  AI_STOPPED,
  aiBlockers,
  aiDailyReach,
  aiForgetSentence,
  aiPausedBy,
  aiStateWord,
  checkSentence,
  clearLogConsequences,
  filteredSentence,
  protectionState,
  whySentence,
} from "@/lib/derive";

const judged: AiExplanation = {
  verdict: "allow",
  applied: true,
  why: null,
  choice: "allow",
  confidence: 0.96,
  effect: "breaks",
  effect_confidence: 0.93,
  lists: "block",
  site: "www.bigshop-example.com",
  conflict_site: null,
  model: "typesafe/jev-1.13",
  judged_at: 1_760_000_000,
};

function check(domain: string, verdict: "allow" | "block", ai: AiExplanation): CheckResult {
  return { domain, verdict, reason: "ai", list: null, scope: "household", device_name: null, ai };
}

describe("whySentence", () => {
  const assets = "checkout-assets.bigshop-example.com";
  const allowedNow = check(assets, "allow", judged);

  test("a row the lists blocked, which the AI list has allowed since, says both in order", () => {
    const row = { domain: assets, blocked: true, reason: "list" as const, list: "Overbroad test list" };
    assert.equal(
      whySentence(row, allowedNow),
      `${assets} — Blocked when it was looked up — Overbroad test list. Since then: ${assets} — Allowed for everyone — AI list: needed by www.bigshop-example.com (the model was 96% sure); the household's lists block it.`,
    );
  });

  test("an AI allow read for one device names the household's lists, not the device's", () => {
    // A device on No lists reaches the AI tier too, though none of its own lists block the name.
    const forPhone: CheckResult = { ...allowedNow, scope: "device", device_name: "Phone" };
    const sentence = checkSentence(forPhone);
    assert.match(sentence, /Allowed for Phone — AI list: .*; the household's lists block it\.$/);
    assert.doesNotMatch(sentence, /your lists/);
  });

  test("a first-visit row nothing blocked, which the AI list blocks since, is not answered 'Blocked'", () => {
    const metrics = "metrics.news-site.com";
    const blockedNow = check(metrics, "block", { ...judged, verdict: "block", choice: "block", confidence: 0.93 });
    const row = { domain: metrics, blocked: false, reason: "no_match" as const, list: null };
    assert.equal(
      whySentence(row, blockedNow),
      `${metrics} — Allowed when it was looked up. Since then: ${metrics} — Blocked for everyone — AI list: not needed by www.bigshop-example.com (the model was 93% sure).`,
    );
  });

  test("a row today's answer agrees with is today's answer alone", () => {
    const row = { domain: assets, blocked: false, reason: "ai" as const, list: null };
    assert.equal(whySentence(row, allowedNow), checkSentence(allowedNow));
  });

  test("a redirect row keeps its own explanation", () => {
    const row = { domain: "cdn.example.com", blocked: true, reason: "cname" as const, list: "oisd small" };
    const clean: CheckResult = { ...allowedNow, domain: "cdn.example.com", reason: "no_match", ai: null };
    assert.match(whySentence(row, clean), /Checked on its own, nothing blocks it/);
  });
});

describe("clearLogConsequences", () => {
  const counters = "The 24-hour counters are kept.";
  const setUp: Settings = { ...emptySettings, ai: { ...emptySettings.ai, key_source: "saved" } };

  test("once AI review is set up, both Clear log dialogs say what it does to the AI list", () => {
    const lines = clearLogConsequences(setUp, counters);
    assert.equal(lines.length, 2);
    assert.equal(lines[0], counters);
    assert.match(lines[1], /AI list also forgets which websites/);
    assert.match(lines[1], /paid for, again/);
    // A contested name counts as "left to your lists" on the card, yet Clear log keeps it.
    assert.match(lines[1], /blocks and allows stay, and so do names two websites disagreed about/);
  });

  test("before it is set up there is no AI list to mention", () => {
    assert.deepEqual(clearLogConsequences(emptySettings, counters), [counters]);
  });
});

describe("the daily limits", () => {
  // Jev 1.13's listed price at about 500 tokens a name.
  const jev = 0.021;

  test("a cheap model's estimate never passes the day's questions", () => {
    for (const limit of [0.05, 0.1, 0.25, 1]) {
      const reach = aiDailyReach(limit, jev);
      assert.equal(reach.capped, true, `${limit}`);
      assert.equal(reach.names, AI_REQUESTS_PER_DAY, `${limit}`);
      assert.ok(Math.abs(reach.capUsd - 0.042) < 1e-9, `${reach.capUsd}`);
    }
  });

  test("a dear model's estimate is what the limit pays for", () => {
    const reach = aiDailyReach(0.1, 0.5);
    assert.equal(reach.capped, false);
    assert.ok(Math.abs(reach.names - 200) < 1e-9, `${reach.names}`);
  });

  test("a pause at the question cap is told from one at the spending limit", () => {
    assert.equal(aiPausedBy(AI_REQUESTS_PER_DAY), "requests");
    // The server counts the two questions in flight when it stops.
    assert.equal(aiPausedBy(AI_REQUESTS_PER_DAY - 2), "requests");
    assert.equal(aiPausedBy(AI_REQUESTS_PER_DAY - 3), "spend");
    assert.equal(aiPausedBy(40), "spend");
  });
});

describe("what the AI list is said to block", () => {
  const empty = { applying: true, applied_block: 0 };
  const blocking = { applying: true, applied_block: 3 };
  const off = { applying: false, applied_block: 3 };

  test("a device on no lists is 'AI list only' only while the AI list blocks something", () => {
    const sam = ["Sam's iPhone"];
    assert.equal(
      filteredSentence([], sam, empty),
      "Every device using Cogwheel is filtered except Sam's iPhone (no lists).",
    );
    assert.equal(filteredSentence([], sam, off), "Every device using Cogwheel is filtered except Sam's iPhone (no lists).");
    assert.equal(
      filteredSentence([], sam, blocking),
      "Every device using Cogwheel is filtered except Sam's iPhone (no lists; AI list only).",
    );
    const many = ["A", "B", "C", "D"];
    assert.match(filteredSentence([], many, empty), /4 with no lists\.$/);
    assert.match(filteredSentence([], many, blocking), /4 with no lists \(AI list only\)\.$/);
  });

  test("the 'only your own rules' sentences name the AI list only while it blocks", () => {
    assert.equal(aiBlockers(empty), "your own rules are");
    assert.equal(aiBlockers(off), "your own rules are");
    assert.equal(aiBlockers(blocking), "your own rules and the AI list are");
    const day = { enabled: 0, total: 1, downloaded: true, queries: 10 };
    assert.equal(
      protectionState({ pausedUntil: null, offline: false, day, ai: empty }).detail,
      "Only your own rules are blocking anything.",
    );
  });
});

describe("aiForgetSentence", () => {
  test("a name a household rule covers is not promised a second judgement", () => {
    for (const state of ["reviewing", "paused_budget", "retrying", "off"] as const) {
      const said = aiForgetSentence({ outranked_by: "household_rule" }, state);
      assert.doesNotMatch(said, /judged again/, state);
      assert.match(said, /not sent for review while the rule stands/, state);
    }
  });

  test("any other name is judged again while review is on", () => {
    assert.equal(aiForgetSentence({ outranked_by: null }, "reviewing"), "judged again the next time a website loads it.");
    assert.equal(aiForgetSentence({ outranked_by: "protected" }, "off"), "your lists decide for it.");
  });
});

test("only the four ways review stops on its own read 'Stopped', on Overview and beside the dot alike", () => {
  // Retrying and the daily pause resume by themselves: Overview's "AI review has stopped" is not said of them.
  assert.deepEqual([...AI_STOPPED].sort(), ["key_refused", "model_refused", "out_of_credit", "stopped"]);
  const states: AiState[] = ["unavailable", "off", "no_key", "reviewing", "paused_budget", "retrying", ...AI_STOPPED];
  for (const state of states) {
    assert.equal(aiStateWord(state).word === "Stopped", AI_STOPPED.has(state), state);
  }
});
