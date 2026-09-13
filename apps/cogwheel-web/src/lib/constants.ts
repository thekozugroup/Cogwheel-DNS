import type {
  BlockProfileListRecord,
  BlockProfileRecord,
  DashboardSummary,
  DnsRuntimeSnapshot,
  ResolverAccessStatus,
  SettingsSummary,
} from "@/lib/api";

/**
 * Neutral defaults so screens can render structure before the first response
 * lands, instead of null-checking every field at every use site.
 */

export const emptyRuntimeSnapshot: DnsRuntimeSnapshot = {
  queries_total: 0,
  blocked_total: 0,
  cache_hits_total: 0,
  cache_expired_total: 0,
  upstream_failures_total: 0,
  stale_served_total: 0,
  cname_blocks_total: 0,
  dropped_total: 0,
  cache_hit_latency_avg_ns: 0,
  cache_hit_samples: 0,
  cache_miss_latency_avg_ns: 0,
  cache_miss_samples: 0,
};

export const emptyDashboard: DashboardSummary = {
  protection_status: "Loading",
  protection_paused_until: null,
  source_count: 0,
  enabled_source_count: 0,
  device_count: 0,
  runtime: emptyRuntimeSnapshot,
  domain_insights: { top_queried_domains: [], top_blocked_domains: [], observed_queries: 0 },
};

export const emptySettings: SettingsSummary = {
  blocklists: [],
  blocklist_statuses: [],
  block_profiles: [],
  devices: [],
};

export const emptyResolverAccess: ResolverAccessStatus = {
  hostname: null,
  dns_targets: [],
  notes: [],
};

export const emptyBlockProfileDraft: BlockProfileRecord = {
  id: "",
  emoji: "",
  name: "",
  description: "",
  blocklists: [],
  allowlists: [],
  updated_at: new Date(0).toISOString(),
};

/**
 * The four presets the backend canonicalises against
 * (`normalize_block_profile_lists`). Core and NSFW families are mutually
 * exclusive: picking the big list drops the small one and vice versa.
 */
export const oisdProfileOptions: BlockProfileListRecord[] = [
  { id: "oisd-small", name: "OISD Small", url: "https://small.oisd.nl", kind: "preset", family: "core-small" },
  { id: "oisd-big", name: "OISD Big", url: "https://big.oisd.nl", kind: "preset", family: "core-full" },
  {
    id: "oisd-nsfw-small",
    name: "OISD NSFW Small",
    url: "https://nsfw-small.oisd.nl",
    kind: "preset",
    family: "nsfw-small",
  },
  { id: "oisd-nsfw", name: "OISD NSFW", url: "https://nsfw.oisd.nl", kind: "preset", family: "nsfw-full" },
];

export const MUTUALLY_EXCLUSIVE_PRESETS: Record<string, string> = {
  "oisd-big": "oisd-small",
  "oisd-small": "oisd-big",
  "oisd-nsfw": "oisd-nsfw-small",
  "oisd-nsfw-small": "oisd-nsfw",
};

/**
 * localStorage keys for the last-known snapshot. The suffix is bumped whenever
 * a cached shape changes incompatibly (the dashboard lost `runtime_health` and
 * gained `runtime`), so a browser that cached the previous build never renders
 * the old shape and trips the error boundary before the first poll answers.
 */
export const CACHE_KEYS = {
  dashboard: "cogwheel_dashboard_cache_v2",
  settings: "cogwheel_settings_cache_v2",
  resolverAccess: "cogwheel_resolver_access_cache_v2",
} as const;

export const THEME_STORAGE_KEY = "cogwheel-theme";

/** Poll cadence for the shared control-plane snapshot. */
export const REFRESH_INTERVAL_MS = 5_000;

/** Rows kept in the live activity buffer before the oldest are dropped. */
export const ACTIVITY_BUFFER_LIMIT = 500;

export const SNOOZE_OPTIONS = [5, 15, 60] as const;
