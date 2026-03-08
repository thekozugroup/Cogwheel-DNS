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
  severity: string;
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

export type DashboardSummary = {
  protection_status: string;
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
    throw new Error(`${response.status} ${response.statusText}`);
  }
  const payload = (await response.json()) as { data: T };
  return payload.data;
}

export const api = {
  dashboard: () => fetchJson<DashboardSummary>("/api/v1/dashboard"),
  settings: () => fetchJson<SettingsSummary>("/api/v1/settings"),
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
  testNotifications: () =>
    fetchJson<NotificationTestResult>("/api/v1/settings/notifications/test", {
      method: "POST",
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
};
