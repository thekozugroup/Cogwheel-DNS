export type RuntimeHealth = {
  snapshot: {
    upstream_failures_total: number;
    fallback_served_total: number;
    cache_hits_total: number;
    cname_uncloaks_total: number;
    cname_blocks_total: number;
  };
  degraded: boolean;
  notes: string[];
};

export type RulesetSummary = {
  id: string;
  hash: string;
  status: string;
  created_at: string;
};

export type AuditEvent = {
  id: string;
  event_type: string;
  payload: string;
  created_at: string;
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

export type ServiceToggle = {
  manifest: {
    service_id: string;
    display_name: string;
    category: string;
    risk_notes: string;
    allow_domains: string[];
    block_domains: string[];
    exceptions: string[];
  };
  mode: "Inherit" | "Allow" | "Block";
};

export type DeviceRecord = {
  id: string;
  name: string;
  ip_address: string;
  policy_mode: "global" | "custom";
  blocklist_profile_override: string | null;
  protection_override: "inherit" | "bypass";
  allowed_domains: string[];
  service_overrides: DeviceServiceOverride[];
};

export type DeviceServiceOverride = {
  service_id: string;
  mode: "allow" | "block";
};

export type SecurityEventRecord = {
  id: string;
  device_id: string | null;
  device_name: string | null;
  client_ip: string;
  domain: string;
  classifier_score: number;
  severity: string;
  created_at: string;
};

export type DeviceSecuritySummary = {
  label: string;
  event_count: number;
  highest_severity: string;
};

export type SecuritySummary = {
  medium_count: number;
  high_count: number;
  critical_count: number;
  top_devices: DeviceSecuritySummary[];
};

export type NotificationSettings = {
  enabled: boolean;
  webhook_url: string | null;
  min_severity: "medium" | "high" | "critical";
};

export type NotificationDeliveryEvent = {
  status: string;
  event_type: string;
  severity: string;
  title: string;
  summary: string;
  target: string;
  domain: string;
  device_name: string | null;
  client_ip: string;
  attempts: number;
  created_at: string;
};

export type NotificationHealthSummary = {
  delivered_count: number;
  failed_count: number;
  last_delivery_at: string | null;
  last_failure_at: string | null;
};

export type NotificationFailureDomain = {
  domain: string;
  failure_count: number;
};

export type NotificationFailureAnalytics = {
  success_rate_percent: number;
  top_failed_domains: NotificationFailureDomain[];
};

export type NotificationTestResult = {
  outcome: string;
  target: string;
};

export type NotificationTestRequest = {
  domain?: string;
  severity?: NotificationSettings["min_severity"];
  device_name?: string;
  dry_run?: boolean;
};

export type NotificationTestPreset = {
  name: string;
  domain: string;
  severity: NotificationSettings["min_severity"];
  device_name: string;
  dry_run: boolean;
};

export type DashboardSummary = {
  protection_status: string;
  protection_paused_until: string | null;
  active_ruleset: RulesetSummary | null;
  source_count: number;
  enabled_source_count: number;
  service_toggle_count: number;
  device_count: number;
  runtime_health: RuntimeHealth;
  latest_audit_events: AuditEvent[];
  recent_security_events: SecurityEventRecord[];
  recent_notification_deliveries: NotificationDeliveryEvent[];
  notification_health: NotificationHealthSummary;
  notification_failure_analytics: NotificationFailureAnalytics;
  security_summary: SecuritySummary;
};

export type SyncPeerStatus = {
  node_public_key: string;
  imports: number;
  last_import_at: string;
  last_revision: number;
  profile: string;
};

export type SyncNodeStatus = {
  local_node_public_key: string;
  profile: string;
  revision: number;
  transport_mode: string;
  transport_token_configured: boolean;
  replay_cache_entries: number;
  peers: SyncPeerStatus[];
};

export type TailscaleStatus = {
  installed: boolean;
  daemon_running: boolean;
  backend_state: string | null;
  hostname: string | null;
  tailnet_name: string | null;
  peer_count: number;
  exit_node_active: boolean;
  version: string | null;
  health_warnings: string[];
  last_error: string | null;
};

export type TailscaleExitNodeResult = {
  success: boolean;
  message: string;
};

export type TailscaleRollbackResult = {
  success: boolean;
  message: string;
  previous_state: boolean | null;
};

export type TailscaleDnsCheckResult = {
  configured: boolean;
  message: string;
  local_dns_server: string | null;
  suggestions: string[];
};

export type SyncProfileView = {
  profile: string;
};

export type SyncTransportView = {
  mode: string;
  token_configured: boolean;
};

export type SettingsSummary = {
  blocklists: SourceRecord[];
  blocklist_statuses: BlocklistStatus[];
  devices: DeviceRecord[];
  services: ServiceToggle[];
  classifier: {
    mode: "Off" | "Monitor" | "Protect";
    threshold: number;
  };
  notifications: NotificationSettings;
  notification_test_presets: NotificationTestPreset[];
  runtime_guard: {
    probe_domains: string[];
    max_upstream_failures_delta: number;
    max_fallback_served_delta: number;
  };
};

const API_BASE = import.meta.env.VITE_COGWHEEL_API_BASE ?? "http://127.0.0.1:8080";

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    const detail = (await response.text()).trim();
    throw new Error(detail || `${response.status} ${response.statusText}`);
  }
  const payload = (await response.json()) as { data: T };
  return payload.data;
}

export const api = {
  dashboard: (notificationWindow?: number, notificationHistoryWindow?: number) => {
    const params = new URLSearchParams();
    if (notificationWindow) {
      params.set("notification_window", String(notificationWindow));
    }
    if (notificationHistoryWindow) {
      params.set("notification_history_window", String(notificationHistoryWindow));
    }
    const query = params.toString();
    return fetchJson<DashboardSummary>(query ? `/api/v1/dashboard?${query}` : "/api/v1/dashboard");
  },
  settings: () => fetchJson<SettingsSummary>("/api/v1/settings"),
  syncStatus: () => fetchJson<SyncNodeStatus>("/api/v1/sync/status"),
  syncProfile: () => fetchJson<SyncProfileView>("/api/v1/sync/profile"),
  updateSyncProfile: (profile: string) =>
    fetchJson<SyncProfileView>("/api/v1/sync/profile", {
      method: "POST",
      body: JSON.stringify({ profile }),
    }),
  syncTransport: () => fetchJson<SyncTransportView>("/api/v1/sync/transport"),
  updateSyncTransport: (mode: string, token?: string) =>
    fetchJson<SyncTransportView>("/api/v1/sync/transport", {
      method: "POST",
      body: JSON.stringify({ mode, token }),
    }),
  refreshSources: () =>
    fetchJson<{ outcome: string; notes: string[] }>("/api/v1/sources/refresh", {
      method: "POST",
    }),
  rollbackRuleset: () =>
    fetchJson<{ id: string; hash: string; status: string; created_at: string }>(
      "/api/v1/rulesets/rollback",
      {
        method: "POST",
      },
    ),
  runtimeHealthCheck: () =>
    fetchJson<RuntimeHealth>("/api/v1/runtime/health/check", {
      method: "POST",
    }),
  pauseRuntime: (minutes: number) =>
    fetchJson<void>("/api/v1/runtime/pause", {
      method: "POST",
      body: JSON.stringify({ minutes }),
    }),
  resumeRuntime: () =>
    fetchJson<void>("/api/v1/runtime/resume", {
      method: "POST",
    }),
  updateClassifier: (mode: SettingsSummary["classifier"]["mode"], threshold: number) =>
    fetchJson<SettingsSummary["classifier"]>("/api/v1/settings/classifier", {
      method: "POST",
      body: JSON.stringify({ mode, threshold }),
    }),
  updateNotifications: (input: NotificationSettings) =>
    fetchJson<NotificationSettings>("/api/v1/settings/notifications", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  testNotifications: (input?: NotificationTestRequest) =>
    fetchJson<NotificationTestResult>("/api/v1/settings/notifications/test", {
      method: "POST",
      body: JSON.stringify(input ?? {}),
    }),
  updateNotificationTestPresets: (presets: NotificationTestPreset[]) =>
    fetchJson<NotificationTestPreset[]>("/api/v1/settings/notifications/presets", {
      method: "POST",
      body: JSON.stringify({ presets }),
    }),
  upsertBlocklist: (input: Partial<SourceRecord> & { name: string; url: string; kind: string }) =>
    fetchJson<{ outcome: string; notes: string[] }>("/api/v1/settings/blocklists", {
      method: "POST",
      body: JSON.stringify({ ...input, refresh_now: true }),
    }),
  setBlocklistEnabled: (id: string, enabled: boolean) =>
    fetchJson<{ outcome: string; notes: string[] }>("/api/v1/settings/blocklists/state", {
      method: "POST",
      body: JSON.stringify({ id, enabled, refresh_now: true }),
    }),
  deleteBlocklist: (id: string) =>
    fetchJson<{ outcome: string; notes: string[] }>("/api/v1/settings/blocklists/delete", {
      method: "POST",
      body: JSON.stringify({ id, refresh_now: true }),
    }),
  updateService: (service_id: string, mode: ServiceToggle["mode"]) =>
    fetchJson<{ outcome: string; notes: string[] }>("/api/v1/services/toggles", {
      method: "POST",
      body: JSON.stringify({ service_id, mode }),
    }),
  upsertDevice: (input: {
    id?: string;
    name: string;
    ip_address: string;
    policy_mode?: DeviceRecord["policy_mode"];
    blocklist_profile_override?: string | null;
    protection_override?: DeviceRecord["protection_override"];
    allowed_domains?: string[];
    service_overrides?: DeviceServiceOverride[];
  }) =>
    fetchJson<DeviceRecord>("/api/v1/devices", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  securityEvents: () => fetchJson<SecurityEventRecord[]>("/api/v1/security-events"),
  tailscaleStatus: () => fetchJson<TailscaleStatus>("/api/v1/tailscale/status"),
  tailscaleExitNode: (enabled: boolean) =>
    fetchJson<TailscaleExitNodeResult>("/api/v1/tailscale/exit-node", {
      method: "POST",
      body: JSON.stringify({ enabled }),
    }),
  tailscaleRollback: () =>
    fetchJson<TailscaleRollbackResult>("/api/v1/tailscale/rollback", {
      method: "POST",
    }),
  tailscaleDnsCheck: () => fetchJson<TailscaleDnsCheckResult>("/api/v1/tailscale/dns-check"),
  falsePositiveBudget: () => fetchJson<{
    release_ready: boolean;
    blocking_rate: number;
    blocked_total: number;
    queries_total: number;
    false_positive_estimate: number;
    budget_remaining: number;
    budget_limit: number;
    recommendations: string[];
  }>("/api/v1/false-positive-budget"),
};
