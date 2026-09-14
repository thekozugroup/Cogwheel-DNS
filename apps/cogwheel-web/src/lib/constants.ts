import type { DeviceList, ListCatalogue, Overview, Rule, Settings } from "@/lib/api";

/**
 * Neutral defaults so screens can render structure before the first response
 * lands, instead of null-checking every field at every use site.
 */

export const emptyOverview: Overview = {
  protection: { paused_until: null },
  runtime: {
    queries_total: 0,
    blocked_total: 0,
    cache_hits_total: 0,
    cache_expired_total: 0,
    stale_served_total: 0,
    upstream_failures_total: 0,
    cname_blocks_total: 0,
    dropped_total: 0,
    log_dropped_total: 0,
    cache_hit_latency_avg_ns: 0,
    cache_miss_latency_avg_ns: 0,
  },
  last_24h: {
    queries: 0,
    blocked: 0,
    per_hour: [],
    active_clients: 0,
    named_devices: 0,
    unnamed_clients: 0,
  },
  lists: { enabled: 0, total: 0, rules_loaded: 0, last_ok_at: null, downloaded: false },
  top_blocked: [],
  top_queried: [],
  connect: { targets: [], port: 53 },
};

export const emptySettings: Settings = {
  version: "",
  upstreams: [],
  block_mode: "",
  http_bind: "",
  dns_udp_bind: "",
  dns_tcp_bind: "",
  advertised_targets: [],
  advertised_port: 53,
  refresh_interval_secs: 0,
  retention: { history_days: 0, max_rows: 0, prune_interval_secs: 0 },
  db_path: "",
  db_size_bytes: 0,
  lists_dir: "",
  protected_suffixes: [],
  schema_version: 0,
};

export const emptyLists: ListCatalogue = { lists: [], presets: [] };

export const emptyDevices: DeviceList = { devices: [], unnamed_clients: [] };

export const emptyRules: Rule[] = [];

/**
 * localStorage keys for the last-known snapshot. The suffix is bumped whenever
 * a cached shape changes incompatibly, so a browser holding the previous build's
 * cache never renders the old shape and trips the error boundary before the
 * first poll answers.
 */
export const CACHE_KEYS = {
  overview: "cogwheel_overview_cache_v3",
  settings: "cogwheel_settings_cache_v3",
  lists: "cogwheel_lists_cache_v3",
  devices: "cogwheel_devices_cache_v3",
  rules: "cogwheel_rules_cache_v3",
} as const;

export const THEME_STORAGE_KEY = "cogwheel-theme";

/** Poll cadence for the live part of the snapshot. */
export const REFRESH_INTERVAL_MS = 5_000;

/** Rows the Activity screen holds before the oldest are dropped. */
export const ACTIVITY_BUFFER_LIMIT = 500;

/** Rows fetched per page of query-log history. */
export const ACTIVITY_PAGE_SIZE = 200;

/**
 * How often the live stream reports itself to a screen reader. A household
 * resolver answers several queries a second; anything finer than this reads as
 * one uninterrupted sentence and makes the rest of the page unreachable.
 */
export const ACTIVITY_ANNOUNCE_INTERVAL_MS = 20_000;

export const PAUSE_OPTIONS = [5, 15, 60] as const;
