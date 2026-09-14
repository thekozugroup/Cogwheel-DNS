/**
 * The Cogwheel control-plane HTTP contract, as the web app uses it.
 *
 * Twenty-two routes, no more: two health probes, one SSE stream and nineteen
 * JSON calls. Field names mirror the wire exactly (snake_case everywhere
 * except the SSE frame, which is camelCase), so nothing here has to translate
 * between two vocabularies — the UI layer does its own naming at the use site.
 */

const API_BASE =
  import.meta.env.VITE_COGWHEEL_API_BASE ??
  (typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:8080");

/** Thrown for every non-2xx response so callers can branch on status. */
class ApiError extends Error {
  readonly status: number;
  readonly path: string;

  constructor(message: string, status: number, path: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.path = path;
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message) return error.message;
  if (typeof error === "string" && error) return error;
  return "Unknown error";
}

type RequestOptions = { signal?: AbortSignal };

/** Errors are `{ "error": "<plain sentence>" }`; fall back to the status line. */
function describeFailure(body: string, response: Response): string {
  try {
    const parsed = JSON.parse(body) as { error?: unknown };
    if (typeof parsed.error === "string" && parsed.error) return parsed.error;
  } catch {
    /* Not JSON — a proxy or the SPA fallback answered instead of the handler. */
  }
  return `${response.status} ${response.statusText}`;
}

/** Every JSON handler wraps its payload in `{ data: T }`. */
async function json<T>(path: string, init: RequestInit = {}, options?: RequestOptions): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      signal: options?.signal,
      headers: {
        "Content-Type": "application/json",
        // Marks the call as programmatic so the SPA fallback cannot be mistaken
        // for a navigation and answered with index.html.
        "X-Requested-With": "XMLHttpRequest",
        ...(init.headers ?? {}),
      },
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError("The control plane is unreachable.", 0, path);
  }

  if (!response.ok) {
    const body = (await response.text().catch(() => "")).trim();
    throw new ApiError(describeFailure(body, response), response.status, path);
  }

  const payload = (await response.json()) as { data: T };
  return payload.data;
}

const body = (value: unknown): RequestInit["body"] => JSON.stringify(value);

/** Drops undefined entries so an unset filter never becomes the string "undefined". */
function query(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

/* ------------------------------------------------------------------------- */
/* Wire types                                                                 */
/* ------------------------------------------------------------------------- */

/** Which evaluation step decided a query. Mirrors `cogwheel_policy::Reason`. */
export type Reason =
  | "no_match"
  | "device_rule"
  | "household_rule"
  | "protected"
  | "list_allow"
  | "list"
  | "cname"
  | "paused"
  | "unfiltered";

export type ListKind = "hosts" | "domains" | "adblock";
export type RuleAction = "allow" | "block";

export type HealthStatus = { status: string };

export type Readiness = {
  status: string;
  subsystems: { storage: boolean; policy: boolean; dns_listeners: boolean };
};

type RuntimeCounters = {
  queries_total: number;
  blocked_total: number;
  cache_hits_total: number;
  cache_expired_total: number;
  /** Expired answers served because the upstream failed. */
  stale_served_total: number;
  upstream_failures_total: number;
  cname_blocks_total: number;
  /** Misses refused because the runtime was saturated; answered SERVFAIL. */
  dropped_total: number;
  log_dropped_total: number;
  cache_hit_latency_avg_ns: number;
  cache_miss_latency_avg_ns: number;
};

type HourBucket = { hour: number; queries: number; blocked: number };

export type Overview = {
  protection: { paused_until: number | null };
  runtime: RuntimeCounters;
  last_24h: {
    queries: number;
    blocked: number;
    /** Oldest first; always 24 entries, zero-filled. */
    per_hour: HourBucket[];
    active_clients: number;
    named_devices: number;
    unnamed_clients: number;
  };
  lists: {
    enabled: number;
    total: number;
    rules_loaded: number;
    last_ok_at: number | null;
    /** False until at least one list body has been fetched or found in the cache. */
    downloaded: boolean;
  };
  top_blocked: DomainCount[];
  top_queried: DomainCount[];
  connect: { targets: string[]; port: number };
};

export type DomainCount = { domain: string; count: number };

export type PauseState = { paused_until: number | null };

export type QueryRow = {
  id: number;
  ts: number;
  client: string;
  device_id: string | null;
  device_name: string | null;
  domain: string;
  qtype: number;
  blocked: boolean;
  reason: Reason;
  /** The list that decided it, for `list`, `list_allow` and `cname`. */
  list: string | null;
};

export type QueryPage = {
  rows: QueryRow[];
  /** Keyset cursor for the next older page, or null at the end of the log. */
  next_before: number | null;
  /** False when COGWHEEL_RETENTION__HISTORY_DAYS=0: only the live stream exists. */
  logging: boolean;
};

export type QueryFilters = {
  limit?: number;
  before?: number;
  client?: string;
  unnamed?: boolean;
  blocked?: boolean;
  q?: string;
};

/** `GET /api/v1/events/stream`, event `query`. The one camelCase payload. */
export type StreamQueryEvent = {
  ts: number;
  client: string;
  deviceName: string | null;
  domain: string;
  qtype: number;
  blocked: boolean;
  reason: Reason;
  list: string | null;
};

type DeviceRule = { id: number; domain: string; action: RuleAction };

export type Device = {
  id: string;
  name: string;
  ip_address: string;
  /** False = this device resolves everything, and is still logged. */
  filtering: boolean;
  all_lists: boolean;
  /** Source ids, meaningful only when `all_lists` is false. */
  lists: string[];
  rules: DeviceRule[];
  queries_24h: number;
  blocked_24h: number;
  last_seen_at: number | null;
};

type UnnamedClient = {
  ip: string;
  queries_24h: number;
  blocked_24h: number;
  last_seen_at: number;
};

export type DeviceList = { devices: Device[]; unnamed_clients: UnnamedClient[] };

export type DeviceInput = {
  name: string;
  ip_address: string;
  filtering?: boolean;
  all_lists?: boolean;
  lists?: string[];
};

export type Rule = {
  id: number;
  domain: string;
  action: RuleAction;
  /** Null = everyone. */
  device_id: string | null;
  device_name: string | null;
  created_at: number;
};

export type RuleInput = { domain: string; action: RuleAction; device_id?: string };

export type ListSource = {
  id: string;
  name: string;
  url: string;
  kind: ListKind;
  enabled: boolean;
  rule_count: number;
  last_ok_at: number | null;
  last_fetched_at: number | null;
  last_error: string | null;
  /** Advisory, e.g. "contains 2 protected names (ignored)". */
  note: string | null;
  due: boolean;
};

type Preset = { name: string; url: string; kind: ListKind };

export type ListCatalogue = { lists: ListSource[]; presets: Preset[] };

export type ListInput = { name: string; url: string; kind: ListKind; enabled?: boolean };

export type ListPatch = { name?: string; url?: string; kind?: ListKind; enabled?: boolean };

type FetchOutcome = "updated" | "unchanged" | "rejected" | "failed";

export type ListCreated = { list: ListSource; outcome: FetchOutcome; note: string | null };

export type RefreshResult = {
  id: string;
  name: string;
  outcome: FetchOutcome;
  rule_count: number;
  note: string | null;
};

export type CheckResult = {
  domain: string;
  verdict: "allow" | "block";
  reason: Reason;
  list: string | null;
  scope: "household" | "device" | "unfiltered" | "paused";
  device_name: string | null;
};

type Upstream = { spec: string; protocol: string; encrypted: boolean };

export type Settings = {
  version: string;
  upstreams: Upstream[];
  block_mode: string;
  http_bind: string;
  dns_udp_bind: string;
  dns_tcp_bind: string;
  advertised_targets: string[];
  advertised_port: number;
  refresh_interval_secs: number;
  retention: { history_days: number; max_rows: number; prune_interval_secs: number };
  db_path: string;
  db_size_bytes: number;
  lists_dir: string;
  protected_suffixes: string[];
  schema_version: number;
};

/* ------------------------------------------------------------------------- */
/* Client — one method per route in §3, in route order.                       */
/* ------------------------------------------------------------------------- */

export const api = {
  /* 1–2 Health */
  live: (options?: RequestOptions) => json<HealthStatus>("/health/live", {}, options),
  ready: (options?: RequestOptions) => json<Readiness>("/health/ready", {}, options),

  /* 3–5 Overview and pause */
  overview: (options?: RequestOptions) => json<Overview>("/api/v1/overview", {}, options),
  pause: (minutes: number) =>
    json<PauseState>("/api/v1/runtime/pause", { method: "POST", body: body({ minutes }) }),
  resume: () => json<PauseState>("/api/v1/runtime/resume", { method: "POST" }),

  /* 6–8 Query log */
  queries: (filters: QueryFilters = {}, options?: RequestOptions) =>
    json<QueryPage>(`/api/v1/queries${query(filters)}`, {}, options),
  clearQueries: () => json<{ deleted: number }>("/api/v1/queries", { method: "DELETE" }),
  eventsStreamUrl: () => `${API_BASE}/api/v1/events/stream`,

  /* 9–12 Devices */
  devices: (options?: RequestOptions) => json<DeviceList>("/api/v1/devices", {}, options),
  createDevice: (input: DeviceInput) =>
    json<Device>("/api/v1/devices", { method: "POST", body: body(input) }),
  updateDevice: (id: string, input: DeviceInput) =>
    json<Device>(`/api/v1/devices/${id}`, { method: "PUT", body: body(input) }),
  deleteDevice: (id: string) =>
    json<{ deleted: boolean }>(`/api/v1/devices/${id}`, { method: "DELETE" }),

  /* 13–15 Rules */
  rules: (deviceId?: string, options?: RequestOptions) =>
    json<Rule[]>(`/api/v1/rules${query({ device_id: deviceId })}`, {}, options),
  createRule: (input: RuleInput) => json<Rule>("/api/v1/rules", { method: "POST", body: body(input) }),
  deleteRule: (id: number) => json<{ deleted: boolean }>(`/api/v1/rules/${id}`, { method: "DELETE" }),

  /* 16–20 Lists */
  lists: (options?: RequestOptions) => json<ListCatalogue>("/api/v1/lists", {}, options),
  createList: (input: ListInput) =>
    json<ListCreated>("/api/v1/lists", { method: "POST", body: body(input) }),
  updateList: (id: string, patch: ListPatch) =>
    json<ListSource>(`/api/v1/lists/${id}`, { method: "PUT", body: body(patch) }),
  deleteList: (id: string) => json<{ deleted: boolean }>(`/api/v1/lists/${id}`, { method: "DELETE" }),
  refreshLists: (id?: string) =>
    json<RefreshResult[]>("/api/v1/lists/refresh", { method: "POST", body: body({ id }) }),

  /* 21–22 Check and settings */
  check: (domain: string, client?: string, options?: RequestOptions) =>
    json<CheckResult>(`/api/v1/check${query({ domain, client })}`, {}, options),
  settings: (options?: RequestOptions) => json<Settings>("/api/v1/settings", {}, options),
};
