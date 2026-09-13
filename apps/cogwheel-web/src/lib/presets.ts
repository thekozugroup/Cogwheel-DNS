import type { Preset } from "@/lib/api";

/**
 * DNSNet's preset catalogue (spec §2.5). `GET /api/v1/lists` returns the same
 * table, so this copy is only the fallback used before the first response
 * lands — the picker stays populated on a cold start with no network.
 */
export const PRESETS: Preset[] = [
  { name: "oisd small", url: "https://small.oisd.nl", kind: "adblock" },
  { name: "oisd big", url: "https://big.oisd.nl", kind: "adblock" },
  {
    name: "HaGeZi Light",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
    kind: "adblock",
  },
  {
    name: "HaGeZi Multi",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
    kind: "adblock",
  },
  {
    name: "HaGeZi Pro",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    kind: "adblock",
  },
  {
    name: "HaGeZi Pro++",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
    kind: "adblock",
  },
  {
    name: "HaGeZi Ultimate",
    url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
    kind: "adblock",
  },
  {
    name: "StevenBlack unified",
    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    kind: "hosts",
  },
  {
    name: "StevenBlack gambling",
    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
    kind: "hosts",
  },
  {
    name: "StevenBlack porn",
    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    kind: "hosts",
  },
  {
    name: "StevenBlack social",
    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts",
    kind: "hosts",
  },
];
