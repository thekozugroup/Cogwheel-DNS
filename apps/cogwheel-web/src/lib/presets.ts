import type { ListKind, ListSource } from "@/lib/api";

/**
 * The Add-a-list picker's three choices, by how much they block.
 *
 * The server's catalogue (`GET /api/v1/lists`, eleven presets) is named by
 * publisher, and a household owner does not know what separates "HaGeZi Multi"
 * from "oisd big". What they can decide is how much breakage they will put up
 * with, so the picker asks that, and the publisher's list is the detail. The
 * full catalogue stays one step away, under "More lists".
 *
 * Each tier is filled from what the publisher itself says about the list:
 *
 * - **Light: oisd small.** oisd's stated aim is to block without breaking —
 *   "the whole idea of this blocklist is to have ZERO breakage", "the list to
 *   use at home, at work or at your (grand-)parents place" — and small is the
 *   variant that "focuses mainly on Ads, (Mobile) App Ads". It is also the
 *   list a fresh install is seeded with, so Light is what most people have.
 * - **Balanced: HaGeZi Pro.** HaGeZi publishes five levels with explicit
 *   breakage guidance and labels Pro "Balanced": "Restrictions here are rare",
 *   and it is the maintainer's own "go-to recommendation". It adds tracking,
 *   telemetry, phishing and malware to the ads.
 * - **Strict: HaGeZi Pro++.** The next level up, "Balanced/Aggressive": "It
 *   might block a few legit domains by mistake", recommended for people who
 *   can unblock things. Ultimate is not a tier: HaGeZi says it "contains
 *   domains that can limit app or website functionality", which is breakage
 *   by design, and it stays in the full catalogue for whoever wants it.
 *
 * Tiers are not cumulative and do not need to be: a person picks one. The
 * `name` is how the preset is looked up in the server's catalogue, so a URL
 * change there is picked up here; `url` and `kind` are only the fallback for
 * the moment before that catalogue has loaded.
 */
export type Strength = "light" | "balanced" | "strict";

export type ListPreset = { name: string; url: string; kind: ListKind };

export type StrengthTier = {
  value: Strength;
  label: string;
  /** What it blocks and how likely it is to break something, in one line. */
  tradeoff: string;
  preset: ListPreset;
};

const HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock";

export const STRENGTH_TIERS: readonly StrengthTier[] = [
  {
    value: "light",
    label: "Light",
    tradeoff: "Ads. Made never to break a site.",
    preset: { name: "oisd small", url: "https://small.oisd.nl", kind: "adblock" },
  },
  {
    value: "balanced",
    label: "Balanced",
    tradeoff: "Ads, trackers and malware. Rarely breaks a site.",
    preset: { name: "HaGeZi Pro", url: `${HAGEZI}/pro.txt`, kind: "adblock" },
  },
  {
    value: "strict",
    label: "Strict",
    tradeoff: "Blocks the most. Now and then breaks a site you use.",
    preset: { name: "HaGeZi Pro++", url: `${HAGEZI}/pro.plus.txt`, kind: "adblock" },
  },
];

/** The tier's list as the server currently describes it, or the fallback. */
export function tierPreset(tier: StrengthTier, catalogue: readonly ListPreset[]): ListPreset {
  return catalogue.find((entry) => entry.name === tier.preset.name) ?? tier.preset;
}

/**
 * The subscribed list this preset already is, if any. By address, and by name
 * too: the server refuses a second list with the same name, and a list added
 * by hand from a mirror is the same subscription under another URL.
 */
export function subscribedAs(preset: ListPreset, lists: readonly ListSource[]): ListSource | undefined {
  const name = preset.name.toLocaleLowerCase();
  return lists.find((list) => list.url.trim() === preset.url || list.name.toLocaleLowerCase() === name);
}
