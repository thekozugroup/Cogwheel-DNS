/**
 * The Cogwheel control-plane HTTP contract, as the web app uses it.
 *
 * Field naming mirrors the wire exactly: every `/api/v1` JSON handler
 * serialises Rust structs verbatim (snake_case fields, PascalCase enums),
 * while the SSE query frame is camelCase. Renaming either side here would only
 * hide the seam, so the types match the wire and the UI layer does the
 * translating.
 */

const API_BASE =
  import.meta.env.VITE_COGWHEEL_API_BASE ??
  (typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:8080");

/** Thrown for every non-2xx response so callers can branch on status. */
export class ApiError extends Error {
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

async function request(path: string, init: RequestInit, options?: RequestOptions): Promise<Response> {
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
    // Style-A handlers answer with an empty body, so fall back to the status line.
    const detail = (await response.text().catch(() => "")).trim();
    throw new ApiError(detail || `${response.status} ${response.statusText}`, response.status, path);
  }

  return response;
}

/** Every JSON handler wraps its payload in `{ data: T }`. */
async function fetchJson<T>(path: string, init: RequestInit = {}, options?: RequestOptions): Promise<T> {
  const response = await request(path, init, options);
  const payload = (await response.json()) as { data: T };
  return payload.data;
}

/** `pause`/`resume` return HTTP 200 with an empty body, breaking the envelope. */
async function fetchVoid(path: string, init: RequestInit = {}, options?: RequestOptions): Promise<void> {
  await request(path, init, options);
}

const post = (body?: unknown): RequestInit => ({
  method: "POST",
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});

/* ------------------------------------------------------------------------- */
/* `/api/v1` types — snake_case, matching the Rust serialisation.              */
/* ------------------------------------------------------------------------- */

export type DnsRuntimeSnapshot = {
  queries_total: number;
  blocked_total: number;
  cache_hits_total: number;
  cache_expired_total: number;
  upstream_failures_total: number;
  /** Expired answers served because the upstream failed. */
  stale_served_total: number;
  cname_blocks_total: number;
  /** Queries answered SERVFAIL or left out of the log because the runtime was saturated. */
  dropped_total: number;
  cache_hit_latency_avg_ns: number;
  cache_hit_samples: number;
  cache_miss_latency_avg_ns: number;
  cache_miss_samples: number;
};

export type SourceRecord = {
  id: string;
  name: string;
  url: string;
  kind: string;
  enabled: boolean;
  refresh_interval_minutes: number;
  profile: string;
  verification_strictness: string;
};

export type BlocklistStatus = {
  id: string;
  name: string;
  last_refresh_attempt_at: string | null;
  due_for_refresh: boolean;
};

export type DeviceRecord = {
  id: string;
  name: string;
  ip_address: string;
  policy_mode: "global" | "custom";
  blocklist_profile_override: string | null;
  protection_override: "inherit" | "bypass";
  allowed_domains: string[];
};

export type BlockProfileListRecord = {
  id: string;
  name: string;
  url: string;
  kind: string;
  family: string;
};

export type BlockProfileRecord = {
  id: string;
  emoji: string;
  name: string;
  description: string;
  blocklists: BlockProfileListRecord[];
  allowlists: string[];
  updated_at: string;
};

export type DomainInsightEntry = { domain: string; count: number };

export type DomainInsights = {
  top_queried_domains: DomainInsightEntry[];
  top_blocked_domains: DomainInsightEntry[];
  observed_queries: number;
};

export type DashboardSummary = {
  /** Derived server-side as Paused / Protected. */
  protection_status: string;
  protection_paused_until: string | null;
  source_count: number;
  enabled_source_count: number;
  device_count: number;
  /** The DNS runtime's counters since the process started. */
  runtime: DnsRuntimeSnapshot;
  domain_insights: DomainInsights;
};

export type SettingsSummary = {
  blocklists: SourceRecord[];
  blocklist_statuses: BlocklistStatus[];
  block_profiles: BlockProfileRecord[];
  devices: DeviceRecord[];
};

export type ResolverAccessStatus = {
  hostname: string | null;
  dns_targets: string[];
  notes: string[];
};

export type RefreshResponse = {
  outcome: string;
  notes: string[];
};

/* ------------------------------------------------------------------------- */
/* Server-sent events (`GET /api/v1/events/stream`) — `query` frames only.    */
/* ------------------------------------------------------------------------- */

export type StreamQueryEvent = {
  domain: string;
  client: string;
  deviceName?: string | null;
  blocked: boolean;
  reason?: string | null;
  observedAt: string;
  latencyMs?: number | null;
};

export const eventsStreamUrl = `${API_BASE}/api/v1/events/stream`;

/* ------------------------------------------------------------------------- */
/* Client                                                                     */
/* ------------------------------------------------------------------------- */

export const api = {
  /* --- Read ---------------------------------------------------------------- */
  dashboard: (options?: RequestOptions) => fetchJson<DashboardSummary>("/api/v1/dashboard", {}, options),
  settings: (options?: RequestOptions) => fetchJson<SettingsSummary>("/api/v1/settings", {}, options),
  runtimeSnapshot: (options?: RequestOptions) =>
    fetchJson<DnsRuntimeSnapshot>("/api/v1/runtime", {}, options),
  resolverAccess: (options?: RequestOptions) =>
    fetchJson<ResolverAccessStatus>("/api/v1/resolver-access", {}, options),
  devices: (options?: RequestOptions) => fetchJson<DeviceRecord[]>("/api/v1/devices", {}, options),
  sources: (options?: RequestOptions) => fetchJson<SourceRecord[]>("/api/v1/sources", {}, options),

  /* --- Runtime ------------------------------------------------------------- */
  pauseRuntime: (minutes: number) => fetchVoid("/api/v1/runtime/pause", post({ minutes })),
  resumeRuntime: () => fetchVoid("/api/v1/runtime/resume", post()),

  /* --- Sources / blocklists ------------------------------------------------ */
  refreshSources: () => fetchJson<RefreshResponse>("/api/v1/sources/refresh", post()),
  upsertBlocklist: (input: {
    id?: string;
    name: string;
    url: string;
    kind: string;
    enabled: boolean;
    refresh_interval_minutes?: number;
    profile?: string;
    verification_strictness?: string;
  }) => fetchJson<RefreshResponse>("/api/v1/settings/blocklists", post({ ...input, refresh_now: true })),
  setBlocklistEnabled: (id: string, enabled: boolean) =>
    fetchJson<RefreshResponse>("/api/v1/settings/blocklists/state", post({ id, enabled, refresh_now: true })),
  deleteBlocklist: (id: string) =>
    fetchJson<RefreshResponse>("/api/v1/settings/blocklists/delete", post({ id, refresh_now: true })),

  /* --- Block profiles ------------------------------------------------------ */
  upsertBlockProfile: (input: {
    id?: string;
    emoji: string;
    name: string;
    description?: string;
    blocklists: BlockProfileListRecord[];
    allowlists: string[];
  }) => fetchJson<BlockProfileRecord[]>("/api/v1/settings/block-profiles", post(input)),
  deleteBlockProfile: (id: string) =>
    fetchJson<BlockProfileRecord[]>("/api/v1/settings/block-profiles/delete", post({ id })),

  /* --- Devices ------------------------------------------------------------- */
  upsertDevice: (input: {
    id?: string;
    name: string;
    ip_address: string;
    policy_mode?: DeviceRecord["policy_mode"];
    blocklist_profile_override?: string | null;
    protection_override?: DeviceRecord["protection_override"];
    allowed_domains?: string[];
  }) => fetchJson<DeviceRecord>("/api/v1/devices", post(input)),
};
