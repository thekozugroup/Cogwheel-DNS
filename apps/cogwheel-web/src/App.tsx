import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type AuditEvent, type BlockProfileListRecord, type BlockProfileRecord, type DashboardSummary, type FederatedLearningSettings, type LatencyBudgetStatus, type ResolverAccessStatus, type SettingsSummary, type SyncNodeStatus, type TailscaleDnsCheckResult, type TailscaleStatus, type ThreatIntelSettings } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";

type LoadState = "idle" | "loading" | "ready" | "error";
type Toast = { id: number; title: string; detail?: string; tone: "success" | "error" | "info" };
type NavPage = "overview" | "profiles" | "devices" | "grease-ai" | "settings";

const emptyDashboard: DashboardSummary = {
  protection_status: "Loading",
  protection_paused_until: null,
  active_ruleset: null,
  source_count: 0,
  enabled_source_count: 0,
  service_toggle_count: 0,
  device_count: 0,
  runtime_health: {
    snapshot: {
      upstream_failures_total: 0,
      fallback_served_total: 0,
      cache_hits_total: 0,
      cname_uncloaks_total: 0,
      cname_blocks_total: 0,
      queries_total: 0,
      blocked_total: 0,
    },
    degraded: false,
    notes: [],
  },
  latest_audit_events: [],
  recent_security_events: [],
  recent_notification_deliveries: [],
  notification_health: {
    delivered_count: 0,
    failed_count: 0,
    last_delivery_at: null,
    last_failure_at: null,
  },
  notification_failure_analytics: {
    success_rate_percent: 100,
    top_failed_domains: [],
  },
  security_summary: {
    medium_count: 0,
    high_count: 0,
    critical_count: 0,
    top_devices: [],
  },
  domain_insights: {
    top_queried_domains: [],
    top_blocked_domains: [],
    observed_queries: 0,
  },
};

const emptySettings: SettingsSummary = {
  blocklists: [],
  blocklist_statuses: [],
  block_profiles: [],
  devices: [],
  services: [],
  classifier: { mode: "Monitor", threshold: 0.92 },
  notifications: { enabled: false, webhook_url: null, min_severity: "high" },
  notification_test_presets: [],
  runtime_guard: { probe_domains: [], max_upstream_failures_delta: 0, max_fallback_served_delta: 0 },
};

const emptySyncStatus: SyncNodeStatus = {
  local_node_public_key: "",
  profile: "full",
  revision: 0,
  transport_mode: "opportunistic",
  transport_token_configured: false,
  replay_cache_entries: 0,
  peers: [],
};

const emptyTailscaleStatus: TailscaleStatus = {
  installed: false,
  daemon_running: false,
  backend_state: null,
  hostname: null,
  tailnet_name: null,
  peer_count: 0,
  exit_node_active: false,
  version: null,
  health_warnings: [],
  last_error: null,
};

const emptyTailscaleDnsCheck: TailscaleDnsCheckResult = {
  configured: false,
  message: "",
  local_dns_server: null,
  suggestions: [],
};

const emptyThreatIntelSettings: ThreatIntelSettings = {
  providers: [],
  recommendations: [],
};

const emptyFederatedLearningSettings: FederatedLearningSettings = {
  enabled: false,
  coordinator_url: null,
  node_id: "",
  round_interval_hours: 24,
  last_round_at: null,
  last_model_version: null,
  privacy_mode: "model-updates-only",
  raw_log_export_enabled: false,
  recommendations: [],
};

const emptyLatencyBudget: LatencyBudgetStatus = {
  within_budget: true,
  cache_hit_rate: 0,
  checks: [],
  recommendations: [],
};

const emptyResolverAccess: ResolverAccessStatus = {
  hostname: null,
  dns_targets: [],
  tailscale_ip: null,
  notes: [],
};

const emptyBlockProfileDraft: BlockProfileRecord = {
  id: "",
  emoji: "",
  name: "",
  description: "",
  blocklists: [],
  allowlists: [],
  updated_at: new Date(0).toISOString(),
};

const oisdProfileOptions: BlockProfileListRecord[] = [
  { id: "oisd-small", name: "OISD Small", url: "https://small.oisd.nl", kind: "preset", family: "core-small" },
  { id: "oisd-big", name: "OISD Big", url: "https://big.oisd.nl", kind: "preset", family: "core-full" },
  { id: "oisd-nsfw-small", name: "OISD NSFW Small", url: "https://nsfw-small.oisd.nl", kind: "preset", family: "nsfw-small" },
  { id: "oisd-nsfw", name: "OISD NSFW", url: "https://nsfw.oisd.nl", kind: "preset", family: "nsfw-full" },
];

export default function App() {
  const [dashboard, setDashboard] = useState<DashboardSummary>(emptyDashboard);
  const [settings, setSettings] = useState<SettingsSummary>(emptySettings);
  const [syncStatus, setSyncStatus] = useState<SyncNodeStatus>(emptySyncStatus);
  const [tailscaleStatus, setTailscaleStatus] = useState<TailscaleStatus>(emptyTailscaleStatus);
  const [tailscaleDnsCheck, setTailscaleDnsCheck] = useState<TailscaleDnsCheckResult>(emptyTailscaleDnsCheck);
  const [threatIntelSettings, setThreatIntelSettings] = useState<ThreatIntelSettings>(emptyThreatIntelSettings);
  const [federatedLearningSettings, setFederatedLearningSettings] = useState<FederatedLearningSettings>(emptyFederatedLearningSettings);
  const [latencyBudget, setLatencyBudget] = useState<LatencyBudgetStatus>(emptyLatencyBudget);
  const [resolverAccess, setResolverAccess] = useState<ResolverAccessStatus>(emptyResolverAccess);
  const [state, setState] = useState<LoadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [activePage, setActivePage] = useState<NavPage>("overview");

  const [blocklistName, setBlocklistName] = useState("");
  const [blocklistUrl, setBlocklistUrl] = useState("");
  const [blocklistProfile, setBlocklistProfile] = useState("custom");
  const [blocklistStrictness, setBlocklistStrictness] = useState<"strict" | "balanced" | "relaxed">("balanced");
  const [blocklistInterval, setBlocklistInterval] = useState("60");

  const [classifierThreshold, setClassifierThreshold] = useState("0.92");
  const [notificationEnabled, setNotificationEnabled] = useState(false);
  const [notificationWebhookUrl, setNotificationWebhookUrl] = useState("");
  const [notificationMinSeverity, setNotificationMinSeverity] = useState<"medium" | "high" | "critical">("high");
  const [notificationTestDomain] = useState("notification-test.cogwheel.local");
  const [notificationTestSeverity, setNotificationTestSeverity] = useState<"medium" | "high" | "critical">("high");
  const [notificationTestDeviceName] = useState("Control Plane Test");
  const [notificationDryRun] = useState(false);
  const [notificationAnalyticsWindow] = useState<10 | 30 | 50 | 100>(30);
  const [notificationHistoryWindow] = useState<10 | 30 | 50 | 100>(10);
  const [serviceSearch] = useState("");
  const [auditEventFilter, setAuditEventFilter] = useState<"all" | "runtime" | "notifications" | "devices" | "rulesets">("all");
  const [showServicesView, setShowServicesView] = useState(false);
  const [syncProfileDraft, setSyncProfileDraft] = useState("full");
  const [syncTransportModeDraft, setSyncTransportModeDraft] = useState("opportunistic");
  const [syncTransportTokenDraft, setSyncTransportTokenDraft] = useState("");

  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [deviceName, setDeviceName] = useState("");
  const [deviceIpAddress, setDeviceIpAddress] = useState("");
  const [devicePolicyMode, setDevicePolicyMode] = useState<"global" | "custom">("global");
  const [deviceProfileOverride, setDeviceProfileOverride] = useState("");
  const [deviceProtectionOverride, setDeviceProtectionOverride] = useState<"inherit" | "bypass">("inherit");
  const [deviceAllowedDomains, setDeviceAllowedDomains] = useState("");
  const [deviceServiceOverrides, setDeviceServiceOverrides] = useState<Array<{ service_id: string; mode: "allow" | "block" }>>([]);
  const [deviceServiceOverrideId, setDeviceServiceOverrideId] = useState("");
  const [deviceServiceOverrideMode, setDeviceServiceOverrideMode] = useState<"allow" | "block">("allow");
  const [selectedBlockProfileId, setSelectedBlockProfileId] = useState<string | null>(null);
  const [blockProfileDraft, setBlockProfileDraft] = useState<BlockProfileRecord>(emptyBlockProfileDraft);
  const [blockProfileAllowlistDraft, setBlockProfileAllowlistDraft] = useState("");
  const [customProfileListName, setCustomProfileListName] = useState("");
  const [customProfileListUrl, setCustomProfileListUrl] = useState("");

  const load = useCallback(async () => {
    setState("loading");
    setError(null);
    try {
      const [dashboardData, settingsData, syncStatusData, tailscaleData, tailscaleDns, threatIntelData, federatedLearningData, latencyBudgetData, resolverAccessData] = await Promise.all([
        api.dashboard(notificationAnalyticsWindow, notificationHistoryWindow),
        api.settings(),
        api.syncStatus(),
        api.tailscaleStatus(),
        api.tailscaleDnsCheck(),
        api.threatIntelProviders(),
        api.federatedLearningStatus(),
        api.latencyBudget(),
        api.resolverAccess(),
      ]);
      localStorage.setItem("cogwheel_dashboard_cache", JSON.stringify(dashboardData));
      localStorage.setItem("cogwheel_settings_cache", JSON.stringify(settingsData));
      localStorage.setItem("cogwheel_sync_status_cache", JSON.stringify(syncStatusData));
      localStorage.setItem("cogwheel_tailscale_cache", JSON.stringify(tailscaleData));
      localStorage.setItem("cogwheel_tailscale_dns_cache", JSON.stringify(tailscaleDns));
      localStorage.setItem("cogwheel_threat_intel_cache", JSON.stringify(threatIntelData));
      localStorage.setItem("cogwheel_federated_learning_cache", JSON.stringify(federatedLearningData));
      localStorage.setItem("cogwheel_latency_budget_cache", JSON.stringify(latencyBudgetData));
      localStorage.setItem("cogwheel_resolver_access_cache", JSON.stringify(resolverAccessData));
      setDashboard(dashboardData);
      setSettings(settingsData);
      setSyncStatus(syncStatusData);
      setTailscaleStatus(tailscaleData);
      setTailscaleDnsCheck(tailscaleDns);
      setThreatIntelSettings(threatIntelData);
      setFederatedLearningSettings(federatedLearningData);
      setLatencyBudget(latencyBudgetData);
      setResolverAccess(resolverAccessData);
      setState("ready");
    } catch (loadError) {
      const cachedDashboard = localStorage.getItem("cogwheel_dashboard_cache");
      const cachedSettings = localStorage.getItem("cogwheel_settings_cache");
      const cachedSyncStatus = localStorage.getItem("cogwheel_sync_status_cache");
      const cachedTailscale = localStorage.getItem("cogwheel_tailscale_cache");
      const cachedTailscaleDns = localStorage.getItem("cogwheel_tailscale_dns_cache");
      const cachedThreatIntel = localStorage.getItem("cogwheel_threat_intel_cache");
      const cachedFederatedLearning = localStorage.getItem("cogwheel_federated_learning_cache");
      const cachedLatencyBudget = localStorage.getItem("cogwheel_latency_budget_cache");
      const cachedResolverAccess = localStorage.getItem("cogwheel_resolver_access_cache");

      if (cachedDashboard && cachedSettings && cachedSyncStatus && cachedTailscale && cachedTailscaleDns && cachedThreatIntel && cachedFederatedLearning && cachedLatencyBudget && cachedResolverAccess) {
        try {
          setDashboard(JSON.parse(cachedDashboard) as DashboardSummary);
          setSettings(JSON.parse(cachedSettings) as SettingsSummary);
          setSyncStatus(JSON.parse(cachedSyncStatus) as SyncNodeStatus);
          setTailscaleStatus(JSON.parse(cachedTailscale) as TailscaleStatus);
          setTailscaleDnsCheck(JSON.parse(cachedTailscaleDns) as TailscaleDnsCheckResult);
          setThreatIntelSettings(JSON.parse(cachedThreatIntel) as ThreatIntelSettings);
          setFederatedLearningSettings(JSON.parse(cachedFederatedLearning) as FederatedLearningSettings);
          setLatencyBudget(JSON.parse(cachedLatencyBudget) as LatencyBudgetStatus);
          setResolverAccess(JSON.parse(cachedResolverAccess) as ResolverAccessStatus);
          setState("ready");
          pushToast("Working offline", "Showing cached data while the server is unreachable.", "info");
          return;
        } catch {
          // Fall through if parse fails
        }
      }

      setError(loadError instanceof Error ? loadError.message : "Unknown error");
      setState("error");
    }
  }, [notificationAnalyticsWindow, notificationHistoryWindow]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    setClassifierThreshold(settings.classifier.threshold.toFixed(2));
  }, [settings.classifier.threshold]);

  useEffect(() => {
    setNotificationEnabled(settings.notifications.enabled);
    setNotificationWebhookUrl(settings.notifications.webhook_url ?? "");
    setNotificationMinSeverity(settings.notifications.min_severity);
    setNotificationTestSeverity(settings.notifications.min_severity);
  }, [settings.notifications]);

  useEffect(() => {
    setSyncProfileDraft(syncStatus.profile);
    setSyncTransportModeDraft(syncStatus.transport_mode);
    setSyncTransportTokenDraft("");
  }, [syncStatus.profile, syncStatus.transport_mode]);

  useEffect(() => {
    const selectedProfile = settings.block_profiles.find((profile) => profile.id === selectedBlockProfileId);
    if (selectedProfile) {
      setBlockProfileDraft(selectedProfile);
      setBlockProfileAllowlistDraft(selectedProfile.allowlists.join(", "));
      return;
    }

    if (settings.block_profiles.length > 0 && selectedBlockProfileId === null) {
      const firstProfile = settings.block_profiles[0];
      setSelectedBlockProfileId(firstProfile.id);
      setBlockProfileDraft(firstProfile);
      setBlockProfileAllowlistDraft(firstProfile.allowlists.join(", "));
      return;
    }

    if (settings.block_profiles.length === 0) {
      setBlockProfileDraft(emptyBlockProfileDraft);
      setBlockProfileAllowlistDraft("");
    }
  }, [selectedBlockProfileId, settings.block_profiles]);

  function pushToast(title: string, detail: string | undefined, tone: Toast["tone"]) {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((current) => [...current, { id, title, detail, tone }]);
    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id));
    }, 3200);
  }

  function resetDeviceForm() {
    setDeviceId(null);
    setDeviceName("");
    setDeviceIpAddress("");
    setDevicePolicyMode("global");
    setDeviceProfileOverride("");
    setDeviceProtectionOverride("inherit");
    setDeviceAllowedDomains("");
    setDeviceServiceOverrides([]);
    setDeviceServiceOverrideId("");
    setDeviceServiceOverrideMode("allow");
  }

  const enabledBlocklists = useMemo(
    () => settings.blocklists.filter((source) => source.enabled),
    [settings.blocklists],
  );

  const filteredServices = useMemo(
    () => settings.services.filter((service) => {
      const query = serviceSearch.trim().toLowerCase();
      if (!query) return true;
      return `${service.manifest.display_name} ${service.manifest.category} ${service.manifest.risk_notes}`
        .toLowerCase()
        .includes(query);
    }),
    [serviceSearch, settings.services],
  );

  const filteredAuditEvents = useMemo(
    () => dashboard.latest_audit_events.filter((event) => {
      if (auditEventFilter === "all") return true;
      if (auditEventFilter === "notifications") return event.event_type.startsWith("notification.") || event.event_type.startsWith("security.alert");
      if (auditEventFilter === "runtime") return event.event_type.startsWith("runtime.");
      if (auditEventFilter === "devices") return event.event_type.startsWith("device.");
      if (auditEventFilter === "rulesets") return event.event_type.startsWith("ruleset.");
      return true;
    }),
    [auditEventFilter, dashboard.latest_audit_events],
  );

  const controlPlaneStatus = useMemo(() => {
    if (state === "loading" || busyAction === "refresh-sources" || busyAction === "rollback-ruleset" || busyAction === "runtime-health-check") {
      return {
        label: "Updating",
        detail: "Cogwheel is applying or checking control-plane changes right now.",
        tone: "secondary" as const,
        action: "wait" as const,
      };
    }

    if (error) {
      return {
        label: "Needs attention",
        detail: error,
        tone: "ghost" as const,
        action: "refresh" as const,
      };
    }

    if (dashboard.protection_status === "Paused") {
      return {
        label: "Paused",
        detail: `Protection is temporarily disabled until ${new Date(dashboard.protection_paused_until!).toLocaleTimeString()}.`,
        tone: "ghost" as const,
        action: "resume" as const,
      };
    }

    if (dashboard.runtime_health.degraded) {
      return {
        label: "Needs attention",
        detail: dashboard.runtime_health.notes[0] ?? "Runtime guard detected a degraded state.",
        tone: "ghost" as const,
        action: "health-check" as const,
      };
    }

    if (dashboard.notification_health.failed_count > 0 && dashboard.notification_health.failed_count >= dashboard.notification_health.delivered_count) {
      return {
        label: "Needs attention",
        detail: "Notification delivery is failing often enough to hide important security and recovery signals.",
        tone: "ghost" as const,
        action: "notifications" as const,
      };
    }

    return {
      label: "Protected",
      detail: "Runtime health, sources, and delivery checks look stable from the control plane.",
      tone: "primary" as const,
      action: "refresh" as const,
    };
  }, [busyAction, dashboard.notification_health.delivered_count, dashboard.notification_health.failed_count, dashboard.protection_paused_until, dashboard.protection_status, dashboard.runtime_health.degraded, dashboard.runtime_health.notes, error, state]);

  const recoveryActions = useMemo(() => {
    const actions: Array<{
      title: string;
      detail: string;
      steps: string[];
      actionLabel: string;
      actionKey: "runtime-health-check" | "notifications" | "refresh-sources" | "rollback-ruleset";
      disabled?: boolean;
    }> = [];

    if (dashboard.runtime_health.degraded) {
      actions.push({
        title: "Check runtime health again",
        detail: dashboard.runtime_health.notes[0] ?? "Probe the runtime again to confirm whether the issue is still active.",
        steps: [
          "Run an active health check to refresh probe results.",
          "If probes still fail, compare the runtime notes with the most recent ruleset change.",
          "Roll back if the degraded state appeared after a fresh source update.",
        ],
        actionLabel: busyAction === "runtime-health-check" ? "Checking..." : "Run health check",
        actionKey: "runtime-health-check",
        disabled: busyAction === "runtime-health-check",
      });
    }

    if (dashboard.notification_health.failed_count > 0) {
      actions.push({
        title: "Review notification delivery",
        detail: "Open recent notification events and look for repeated delivery failures before the next alert is missed.",
        steps: [
          "Filter recent delivery history down to failed events.",
          "Check whether the failures are security alerts or control-plane recovery events.",
          "Fix the webhook target before relying on the next health or risky-domain alert.",
        ],
        actionLabel: "Show notifications",
        actionKey: "notifications",
      });
    }

    if (!dashboard.active_ruleset) {
      actions.push({
        title: "Refresh sources now",
        detail: "The resolver does not have an active ruleset yet, so request a fresh source refresh from the control plane.",
        steps: [
          "Refresh sources to build a fresh candidate ruleset.",
          "Confirm the active ruleset hash appears in the dashboard summary.",
          "Re-run a runtime health check once the new ruleset is active.",
        ],
        actionLabel: busyAction === "refresh-sources" ? "Refreshing..." : "Refresh sources",
        actionKey: "refresh-sources",
        disabled: busyAction === "refresh-sources",
      });
    }

    if (dashboard.active_ruleset && dashboard.runtime_health.degraded) {
      actions.push({
        title: "Roll back to the previous ruleset",
        detail: "If the degraded state appeared after a recent change, roll back to the last known-good policy set.",
        steps: [
          "Roll back to the previous verified ruleset.",
          "Watch the notification history for rollback delivery events.",
          "Run the health check again to confirm the runtime recovered.",
        ],
        actionLabel: busyAction === "rollback-ruleset" ? "Rolling back..." : "Roll back",
        actionKey: "rollback-ruleset",
        disabled: busyAction === "rollback-ruleset",
      });
    }

    if (actions.length === 0) {
      actions.push({
        title: "System looks steady",
        detail: "No immediate recovery flow is needed right now. Use refresh or device editing when you are ready to make the next change.",
        steps: [
          "Keep sources fresh before the next policy edit.",
          "Use the checklist to finish any incomplete setup items.",
          "Review recent audit events after each meaningful control-plane change.",
        ],
        actionLabel: busyAction === "refresh-sources" ? "Refreshing..." : "Refresh sources",
        actionKey: "refresh-sources",
        disabled: busyAction === "refresh-sources",
      });
    }

    return actions.slice(0, 3);
  }, [busyAction, dashboard.active_ruleset, dashboard.notification_health.failed_count, dashboard.runtime_health.degraded, dashboard.runtime_health.notes]);

  const navItems: Array<{ id: NavPage; label: string }> = [
    { id: "overview", label: "Overview" },
    { id: "profiles", label: "Block Profiles" },
    { id: "devices", label: "Devices" },
    { id: "grease-ai", label: "Grease-AI" },
    { id: "settings", label: "Settings" },
  ];

  const overviewStats = useMemo(() => {
    const allowlistCount = settings.block_profiles.reduce((total, profile) => total + profile.allowlists.length, 0);
    return [
      {
        label: "Sources",
        value: dashboard.enabled_source_count.toLocaleString(),
        accent: "border-sky-200 bg-sky-50/70",
        detail: `${settings.blocklists.length} blocklist source${settings.blocklists.length === 1 ? "" : "s"} and ${allowlistCount} saved allowlist entr${allowlistCount === 1 ? "y" : "ies"}`,
      },
      {
        label: "Blocked DNS Queries",
        value: dashboard.runtime_health.snapshot.blocked_total.toLocaleString(),
        accent: "border-rose-200 bg-rose-50/70",
        detail: `${dashboard.runtime_health.snapshot.queries_total.toLocaleString()} total queries observed by this node`,
      },
      {
        label: "Devices",
        value: dashboard.device_count.toLocaleString(),
        accent: "border-emerald-200 bg-emerald-50/70",
        detail: "Recognized unique devices currently visible to the control plane",
      },
    ];
  }, [dashboard.device_count, dashboard.enabled_source_count, dashboard.runtime_health.snapshot.blocked_total, dashboard.runtime_health.snapshot.queries_total, settings.block_profiles, settings.blocklists.length]);

  const greaseAiSignals = useMemo(() => {
    const totalQueries = Math.max(dashboard.runtime_health.snapshot.queries_total, 1);
    const blockedRatio = dashboard.runtime_health.snapshot.blocked_total / totalQueries;
    const riskyEventRatio = Math.min(dashboard.recent_security_events.length / 6, 1);
    const latencyHeadroom = latencyBudget.within_budget ? 0.78 : 0.46;
    return [
      {
        label: "Classifier confidence",
        value: Math.min(0.35 + blockedRatio * 1.8, 0.96),
        tint: "from-sky-400/80 to-cyan-300/80",
      },
      {
        label: "Risk memory",
        value: Math.min(0.22 + riskyEventRatio * 0.7, 0.92),
        tint: "from-amber-400/85 to-orange-300/80",
      },
      {
        label: "Latency headroom",
        value: latencyHeadroom,
        tint: "from-emerald-400/85 to-lime-300/80",
      },
    ];
  }, [dashboard.recent_security_events.length, dashboard.runtime_health.snapshot.blocked_total, dashboard.runtime_health.snapshot.queries_total, latencyBudget.within_budget]);

  const serviceLabelMap = useMemo(
    () =>
      new Map(
        settings.services.map((service) => [
          service.manifest.service_id,
          service.manifest.display_name,
        ]),
      ),
    [settings.services],
  );

  const serviceInfoMap = useMemo(
    () =>
      new Map(
        settings.services.map((service) => [service.manifest.service_id, service.manifest]),
      ),
    [settings.services],
  );

  const selectedDeviceServiceManifest = useMemo(
    () => (deviceServiceOverrideId ? serviceInfoMap.get(deviceServiceOverrideId) ?? null : null),
    [deviceServiceOverrideId, serviceInfoMap],
  );

  const pendingDeviceServiceOverride = useMemo(
    () => deviceServiceOverrides.find((item) => item.service_id === deviceServiceOverrideId) ?? null,
    [deviceServiceOverrideId, deviceServiceOverrides],
  );

  const deviceServiceOverrideIsNoop = pendingDeviceServiceOverride?.mode === deviceServiceOverrideMode;

  const deviceServiceOverridePreview = useMemo(() => {
    if (!selectedDeviceServiceManifest) return null;

    const domains = deviceServiceOverrideMode === "allow"
      ? Array.from(new Set([
          ...selectedDeviceServiceManifest.allow_domains,
          ...selectedDeviceServiceManifest.block_domains,
          ...selectedDeviceServiceManifest.exceptions,
        ]))
      : selectedDeviceServiceManifest.block_domains;

    return {
      serviceId: selectedDeviceServiceManifest.service_id,
      displayName: selectedDeviceServiceManifest.display_name,
      category: selectedDeviceServiceManifest.category,
      riskNotes: selectedDeviceServiceManifest.risk_notes,
      domains,
      exceptions: selectedDeviceServiceManifest.exceptions,
      sampleDomains: domains.slice(0, 4),
    };
  }, [deviceServiceOverrideMode, selectedDeviceServiceManifest]);

  async function handlePauseRuntime(minutes: number) {
    setBusyAction("pause-runtime");
    try {
      await api.pauseRuntime(minutes);
      pushToast("Protection paused", `Adblocking and classification paused for ${minutes} minutes.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Pause failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleResumeRuntime() {
    setBusyAction("resume-runtime");
    try {
      await api.resumeRuntime();
      pushToast("Protection resumed", "Adblocking and classification are active again.", "success");
      await load();
    } catch (mutationError) {
      pushToast("Resume failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleSyncProfileSave() {
    setBusyAction("sync-profile-save");
    try {
      await api.updateSyncProfile(syncProfileDraft);
      pushToast("Sync profile updated", `Node sync profile is now ${syncProfileDraft}.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Sync profile update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleSyncTransportSave() {
    setBusyAction("sync-transport-save");
    try {
      await api.updateSyncTransport(syncTransportModeDraft, syncTransportTokenDraft);
      pushToast("Sync transport updated", `Transport mode is now ${syncTransportModeDraft}.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Sync transport update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleClassifierUpdate(mode: SettingsSummary["classifier"]["mode"]) {
    setBusyAction(`classifier-mode-${mode}`);
    try {
      await api.updateClassifier(mode, Number.parseFloat(classifierThreshold) || settings.classifier.threshold);
      pushToast("Classifier updated", `Mode switched to ${mode}.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Classifier update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleClassifierThresholdSave() {
    setBusyAction("classifier-threshold");
    try {
      const threshold = Number.parseFloat(classifierThreshold) || settings.classifier.threshold;
      await api.updateClassifier(settings.classifier.mode, threshold);
      pushToast("Threshold saved", `Classifier threshold is now ${threshold.toFixed(2)}.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Threshold update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleNotificationSave() {
    setBusyAction("notifications-save");
    try {
      await api.updateNotifications({
        enabled: notificationEnabled,
        webhook_url: notificationWebhookUrl || null,
        min_severity: notificationMinSeverity,
      });
      pushToast("Notifications updated", notificationEnabled ? "Webhook delivery is configured." : "Webhook delivery is disabled.", "success");
      await load();
    } catch (mutationError) {
      pushToast("Notification update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleNotificationTest() {
    setBusyAction("notifications-test");
    try {
      const result = await api.testNotifications({
        domain: notificationTestDomain,
        severity: notificationTestSeverity,
        device_name: notificationTestDeviceName,
        dry_run: notificationDryRun,
      });
      pushToast(
        notificationDryRun ? "Webhook validated" : "Test notification sent",
        notificationDryRun
          ? `Validated ${result.target} without sending a live request.`
          : `Delivered to ${result.target} and added to recent history.`,
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast("Test notification failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleTailscaleExitNodeToggle() {
    const newState = !tailscaleStatus.exit_node_active;
    setBusyAction("tailscale-exit-node");
    try {
      const result = await api.tailscaleExitNode(newState);
      pushToast(
        newState ? "Exit node enabled" : "Exit node disabled",
        result.message,
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast(
        "Exit node toggle failed",
        mutationError instanceof Error ? mutationError.message : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleTailscaleRollback() {
    setBusyAction("tailscale-rollback");
    try {
      const result = await api.tailscaleRollback();
      pushToast("Exit node rolled back", result.message, "success");
      await load();
    } catch (mutationError) {
      pushToast(
        "Rollback failed",
        mutationError instanceof Error ? mutationError.message : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleThreatIntelProviderSave(providerId: string) {
    const provider = threatIntelSettings.providers.find((item) => item.id === providerId);
    if (!provider) {
      pushToast("Provider missing", "The selected provider could not be found.", "error");
      return;
    }

    setBusyAction(`threat-intel-${providerId}`);
    try {
      const next = await api.updateThreatIntelProvider(
        provider.id,
        provider.enabled,
        provider.feed_url,
        provider.update_interval_minutes,
      );
      setThreatIntelSettings(next);
      pushToast("Threat intel updated", `${provider.display_name} settings saved.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Threat intel update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleFederatedLearningSave() {
    setBusyAction("federated-learning-save");
    try {
      const next = await api.updateFederatedLearningStatus(
        federatedLearningSettings.enabled,
        federatedLearningSettings.coordinator_url,
        federatedLearningSettings.round_interval_hours,
      );
      setFederatedLearningSettings(next);
      pushToast("Federated learning updated", next.enabled ? "Coordinator settings are active with model-updates-only privacy." : "Federated learning is disabled.", "success");
      await load();
    } catch (mutationError) {
      pushToast("Federated learning update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleBlockProfileSave() {
    if (!blockProfileDraft.name.trim()) {
      pushToast("Name required", "Give the block profile a friendly name before saving.", "error");
      return;
    }

    setBusyAction("block-profile-save");
    try {
      const updatedProfiles = await api.upsertBlockProfile({
        id: blockProfileDraft.id || undefined,
        emoji: blockProfileDraft.emoji,
        name: blockProfileDraft.name,
        description: blockProfileDraft.description,
        blocklists: blockProfileDraft.blocklists,
        allowlists: blockProfileAllowlistDraft
          .split(",")
          .map((entry) => entry.trim())
          .filter(Boolean),
      });
      const nextSelectedId = (updatedProfiles.find((profile) => profile.name === blockProfileDraft.name)?.id) ?? blockProfileDraft.id;
      setSettings((current) => ({ ...current, block_profiles: updatedProfiles }));
      setSelectedBlockProfileId(nextSelectedId || null);
      pushToast("Block profile saved", `${blockProfileDraft.name} is ready for device assignment.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Block profile save failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  function startNewBlockProfile() {
    setSelectedBlockProfileId(null);
    setBlockProfileDraft({ ...emptyBlockProfileDraft, updated_at: new Date().toISOString() });
    setBlockProfileAllowlistDraft("");
    setCustomProfileListName("");
    setCustomProfileListUrl("");
  }

  function selectBlockProfile(profile: BlockProfileRecord) {
    setSelectedBlockProfileId(profile.id);
    setBlockProfileDraft(profile);
    setBlockProfileAllowlistDraft(profile.allowlists.join(", "));
    setCustomProfileListName("");
    setCustomProfileListUrl("");
  }

  function togglePresetBlocklist(option: BlockProfileListRecord) {
    setBlockProfileDraft((current) => {
      const exists = current.blocklists.some((entry) => entry.id === option.id);
      if (exists) {
        return {
          ...current,
          blocklists: current.blocklists.filter((entry) => entry.id !== option.id),
        };
      }

      let nextLists = current.blocklists.filter((entry) => {
        if (option.id === "oisd-big") return entry.id !== "oisd-small";
        if (option.id === "oisd-small") return entry.id !== "oisd-big";
        if (option.id === "oisd-nsfw") return entry.id !== "oisd-nsfw-small";
        if (option.id === "oisd-nsfw-small") return entry.id !== "oisd-nsfw";
        return true;
      });

      nextLists = [...nextLists, option].sort((left, right) => left.name.localeCompare(right.name));
      return { ...current, blocklists: nextLists };
    });
  }

  function addCustomBlocklistToProfile() {
    const name = customProfileListName.trim();
    const url = customProfileListUrl.trim();
    if (!name || !url) {
      pushToast("List details required", "Enter both a list name and a GitHub URL before adding it.", "error");
      return;
    }

    if (!(url.includes("github.com") || url.includes("raw.githubusercontent.com"))) {
      pushToast("GitHub URL required", "Manual lists should point at a GitHub or raw GitHub blocklist URL.", "error");
      return;
    }

    const nextList: BlockProfileListRecord = {
      id: name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || `custom-${Date.now()}`,
      name,
      url,
      kind: "custom",
      family: "custom",
    };

    setBlockProfileDraft((current) => ({
      ...current,
      blocklists: [...current.blocklists.filter((entry) => entry.url !== url), nextList].sort((left, right) => left.name.localeCompare(right.name)),
    }));
    setCustomProfileListName("");
    setCustomProfileListUrl("");
  }

  function removeBlocklistFromProfile(id: string) {
    setBlockProfileDraft((current) => ({
      ...current,
      blocklists: current.blocklists.filter((entry) => entry.id !== id),
    }));
  }

  async function handleRefreshSources() {
    setBusyAction("refresh-sources");
    try {
      const result = await api.refreshSources();
      pushToast("Sources refreshed", result.notes[0], "success");
      await load();
    } catch (mutationError) {
      pushToast("Refresh failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRollbackRuleset() {
    setBusyAction("rollback-ruleset");
    try {
      const ruleset = await api.rollbackRuleset();
      pushToast("Rollback completed", `Restored ruleset ${ruleset.hash.slice(0, 12)}.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Rollback failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRuntimeHealthCheck() {
    setBusyAction("runtime-health-check");
    try {
      const report = await api.runtimeHealthCheck();
      pushToast(
        report.degraded ? "Runtime degraded" : "Runtime healthy",
        report.notes[0] ?? "Runtime guard probes completed without regressions.",
        report.degraded ? "error" : "success",
      );
      await load();
    } catch (mutationError) {
      pushToast("Runtime health check failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleServiceUpdate(serviceId: string, mode: "Inherit" | "Allow" | "Block") {
    setBusyAction(`service-${serviceId}`);
    try {
      await api.updateService(serviceId, mode);
      pushToast("Service updated", `Service mode set to ${mode}.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Service update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleBlocklistCreate() {
    setBusyAction("create-blocklist");
    try {
      await api.upsertBlocklist({
        name: blocklistName,
        url: blocklistUrl,
        kind: "domains",
        enabled: true,
        refresh_interval_minutes: Number.parseInt(blocklistInterval, 10) || 60,
        profile: blocklistProfile,
        verification_strictness: blocklistStrictness,
      });
      setBlocklistName("");
      setBlocklistUrl("");
      setBlocklistProfile("custom");
      setBlocklistStrictness("balanced");
      setBlocklistInterval("60");
      pushToast("Blocklist added", "The source was saved and refreshed.", "success");
      await load();
    } catch (mutationError) {
      pushToast("Blocklist add failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleBlocklistToggle(id: string, enabled: boolean) {
    setBusyAction(`blocklist-toggle-${id}`);
    try {
      await api.setBlocklistEnabled(id, enabled);
      pushToast(enabled ? "Blocklist enabled" : "Blocklist disabled", "Ruleset refresh requested.", "success");
      await load();
    } catch (mutationError) {
      pushToast("Blocklist update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleDeviceSubmit() {
    setBusyAction("device-submit");
    try {
      await api.upsertDevice({
        id: deviceId ?? undefined,
        name: deviceName,
        ip_address: deviceIpAddress,
        policy_mode: devicePolicyMode,
        blocklist_profile_override: devicePolicyMode === "custom" ? deviceProfileOverride || null : null,
        protection_override: devicePolicyMode === "custom" ? deviceProtectionOverride : "inherit",
        allowed_domains: devicePolicyMode === "custom"
          ? deviceAllowedDomains
              .split(",")
              .map((domain) => domain.trim())
              .filter(Boolean)
          : [],
        service_overrides: devicePolicyMode === "custom" ? deviceServiceOverrides : [],
      });
      pushToast(deviceId ? "Device updated" : "Device added", `${deviceName} is now tracked in the control plane.`, "success");
      resetDeviceForm();
      await load();
    } catch (mutationError) {
      pushToast("Device save failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  function startDeviceEdit(device: SettingsSummary["devices"][number]) {
    setDeviceId(device.id);
    setDeviceName(device.name);
    setDeviceIpAddress(device.ip_address);
    setDevicePolicyMode(device.policy_mode);
    setDeviceProfileOverride(device.blocklist_profile_override ?? "");
    setDeviceProtectionOverride(device.protection_override);
    setDeviceAllowedDomains(device.allowed_domains.join(", "));
    setDeviceServiceOverrides(device.service_overrides);
    setDeviceServiceOverrideId("");
    setDeviceServiceOverrideMode("allow");
  }

  function addDeviceServiceOverride() {
    if (devicePolicyMode !== "custom") {
      pushToast("Custom mode required", "Switch the device to custom policy mode before adding service rules.", "error");
      return;
    }
    if (!deviceServiceOverrideId) {
      pushToast("Service required", "Choose a built-in service before adding a device rule.", "error");
      return;
    }
    if (!selectedDeviceServiceManifest) {
      pushToast("Unknown service", "Reload settings and pick the service again before saving the device rule.", "error");
      return;
    }
    if (!deviceServiceOverridePreview || deviceServiceOverridePreview.domains.length === 0) {
      pushToast("Service rule unavailable", "This service does not currently expand into any device-specific domains for the selected mode.", "error");
      return;
    }
    if (deviceServiceOverrideIsNoop) {
      pushToast("Service rule already queued", `${selectedDeviceServiceManifest.display_name} is already using ${deviceServiceOverrideMode} mode for this device.`, "error");
      return;
    }

    setDeviceServiceOverrides((current) => {
      const next = current.filter((item) => item.service_id !== deviceServiceOverrideId);
      next.push({ service_id: deviceServiceOverrideId, mode: deviceServiceOverrideMode });
      next.sort((left, right) => left.service_id.localeCompare(right.service_id));
      return next;
    });
    pushToast(
      "Service rule added",
      pendingDeviceServiceOverride
        ? `${selectedDeviceServiceManifest.display_name} now uses ${deviceServiceOverrideMode} mode for this device.`
        : `${selectedDeviceServiceManifest.display_name} expands into ${deviceServiceOverridePreview.domains.length} device-specific domain rule${deviceServiceOverridePreview.domains.length === 1 ? "" : "s"}.`,
      "success",
    );
  }

  function removeDeviceServiceOverride(serviceId: string) {
    setDeviceServiceOverrides((current) => current.filter((item) => item.service_id !== serviceId));
  }

  function formatDeviceServiceOverride(serviceId: string, mode: "allow" | "block") {
    const label = serviceLabelMap.get(serviceId) ?? serviceId;
    return `${label} - ${mode}`;
  }

  function describeDeviceServiceOverride(serviceId: string) {
    const info = serviceInfoMap.get(serviceId);
    if (!info) return "Custom device service rule";
    return `${info.category} - ${info.risk_notes}`;
  }

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-[1540px] flex-col gap-4 px-3 py-3 sm:px-4 sm:py-4 lg:px-5 lg:py-5">
      <div className="pointer-events-none fixed right-4 top-4 z-50 flex w-full max-w-sm flex-col gap-3">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto rounded-[22px] border px-4 py-3 shadow-lg backdrop-blur ${toast.tone === "error" ? "border-accent/30 bg-white text-foreground" : "border-border/70 bg-white/95 text-foreground"}`}
          >
            <div className="font-medium">{toast.title}</div>
            {toast.detail ? <div className="mt-1 text-sm text-muted-foreground">{toast.detail}</div> : null}
          </div>
        ))}
      </div>

      <div className="flex flex-1 flex-col gap-5 rounded-[34px] border border-border/60 bg-[linear-gradient(180deg,rgba(255,255,255,0.96),rgba(246,244,240,0.94))] p-3 shadow-sm sm:p-4 lg:p-5">

      <header className="sticky top-4 z-40 rounded-[28px] border border-border/60 bg-white/90 px-4 py-4 shadow-sm backdrop-blur">
        <div className="flex flex-col gap-4 lg:grid lg:grid-cols-[auto_1fr_auto] lg:items-center">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-2xl border border-border/70 bg-muted/60 text-lg">⚙️</div>
            <div className="font-display text-2xl font-semibold tracking-tight">Cogwheel</div>
          </div>
          <nav className="grid gap-2 sm:grid-cols-2 lg:mx-auto lg:flex lg:justify-center">
            {navItems.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setActivePage(item.id)}
                className={`rounded-full px-5 py-2.5 text-center text-sm font-medium transition ${activePage === item.id ? "bg-foreground text-background shadow-sm" : "border border-border/70 bg-white text-foreground hover:bg-muted/60"}`}
              >
                {item.label}
              </button>
            ))}
          </nav>
          <div className="flex items-center justify-end">
            <Badge className={controlPlaneStatus.tone === "primary" ? "bg-primary text-primary-foreground" : controlPlaneStatus.tone === "secondary" ? "bg-secondary text-secondary-foreground" : "bg-muted text-foreground"}>
              {controlPlaneStatus.label}
            </Badge>
          </div>
        </div>
      </header>

      {activePage === "overview" ? (
        <>

      <section className="grid gap-4">
        <div className="flex flex-col gap-4 rounded-[28px] border border-border/60 bg-white px-5 py-5 shadow-sm md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="font-display text-3xl font-semibold tracking-tight">Dashboard</h1>
            <div className="mt-1 text-sm text-muted-foreground">A clean snapshot of household filtering, blocked traffic, and active devices.</div>
          </div>
          <div className="flex flex-wrap gap-2">
            {dashboard.protection_status === "Paused" ? (
              <Button variant="secondary" onClick={() => void handleResumeRuntime()} disabled={busyAction === "resume-runtime"}>Resume protection</Button>
            ) : (
              <Button variant="ghost" onClick={() => void handlePauseRuntime(10)} disabled={busyAction === "pause-runtime"}>Pause 10m</Button>
            )}
          </div>
        </div>

        <section id="quick-health" className="grid gap-4 lg:grid-cols-3">
          {overviewStats.map((item) => (
            <Card key={item.label} className={`border ${item.accent}`}>
              <div className="text-sm text-muted-foreground">{item.label}</div>
              <div className="mt-3 font-display text-5xl font-semibold tracking-tight">{item.value}</div>
              <div className="mt-2 text-sm text-muted-foreground">{item.detail}</div>
            </Card>
          ))}
        </section>
      </section>

        <section className="grid gap-6 lg:grid-cols-[1fr_1fr]">

          <Card>
            <CardTitle>Top queried domains</CardTitle>
            <CardDescription>Recent destinations seen by the resolver over the last day.</CardDescription>
            <div className="mt-5 grid gap-3">
              {dashboard.domain_insights.top_queried_domains.length === 0 ? (
                <div className="rounded-[24px] border border-dashed border-border/70 bg-muted/30 p-5 text-sm text-muted-foreground">
                  Query activity will appear here once devices begin sending traffic through Cogwheel.
                </div>
              ) : (
                dashboard.domain_insights.top_queried_domains.map((entry, index) => (
                  <div key={entry.domain} className="rounded-[24px] border border-border/70 bg-white/85 p-4">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <div className="text-xs uppercase tracking-[0.24em] text-muted-foreground">{String(index + 1).padStart(2, "0")}</div>
                        <div className="mt-1 font-medium text-foreground">{entry.domain}</div>
                      </div>
                      <div className="text-right">
                        <div className="font-display text-2xl font-semibold">{entry.count}</div>
                        <div className="text-xs text-muted-foreground">queries</div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>

          <Card>
            <CardTitle>Top blocked domains</CardTitle>
            <CardDescription>Where protection is actively stepping in right now.</CardDescription>
            <div className="mt-5 grid gap-3">
              {dashboard.domain_insights.top_blocked_domains.length === 0 ? (
                <div className="rounded-[24px] border border-dashed border-border/70 bg-muted/30 p-5 text-sm text-muted-foreground">
                  No blocked domains yet. When filtering engages, the busiest blocked destinations will appear here.
                </div>
              ) : (
                dashboard.domain_insights.top_blocked_domains.map((entry) => (
                  <div key={entry.domain} className="rounded-[24px] border border-border/70 bg-[linear-gradient(135deg,rgba(250,245,239,0.9),rgba(255,255,255,0.96))] p-4">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <div className="font-medium text-foreground">{entry.domain}</div>
                        <div className="mt-1 text-xs text-muted-foreground">Blocked before the query could complete.</div>
                      </div>
                      <Badge className="bg-foreground text-background">{entry.count} blocked</Badge>
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>
        </section>

      {error ? <Card className="border-accent/30 bg-accent/10 text-accent-foreground">{error}</Card> : null}

      <section className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <Card id="resolver-access">
          <CardTitle>How to connect devices</CardTitle>
          <CardDescription>Use one of these DNS targets on phones, laptops, TVs, or routers that should use this Cogwheel instance.</CardDescription>
          <div className="mt-5 grid gap-3">
            {resolverAccess.dns_targets.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                Resolver targets will appear here once the control plane reports reachable DNS addresses.
              </div>
            ) : (
              resolverAccess.dns_targets.map((target) => (
                <div key={target} className="rounded-2xl border border-border/70 bg-white/80 p-4 text-sm">
                  <div className="text-muted-foreground">DNS server</div>
                  <div className="mt-1 font-mono text-base font-semibold text-foreground">{target}</div>
                </div>
              ))
            )}
            <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
              <div className="text-muted-foreground">Tailscale</div>
              <div className="mt-1 font-medium text-foreground">{resolverAccess.tailscale_ip ?? "Not available on this node"}</div>
            </div>
            {resolverAccess.notes.length > 0 ? (
              <div className="rounded-2xl border border-dashed border-border/70 bg-background/80 p-4 text-sm text-muted-foreground">
                {resolverAccess.notes.join(" ")}
              </div>
            ) : null}
            <div className="grid gap-3 md:grid-cols-2">
              {[
                {
                  title: "Android",
                  detail: "Network & internet -> Private DNS or the current Wi-Fi network -> DNS server.",
                  target: resolverAccess.dns_targets[0] ?? "fractal.local",
                },
                {
                  title: "iPhone / iPad",
                  detail: "Wi-Fi -> tap the info icon -> Configure DNS -> Manual.",
                  target: resolverAccess.dns_targets[0] ?? "fractal.local",
                },
                {
                  title: "Mac",
                  detail: "System Settings -> Wi-Fi -> Details -> DNS, then add this resolver.",
                  target: resolverAccess.dns_targets[0] ?? "fractal.local",
                },
                {
                  title: "Windows",
                  detail: "Network & Internet -> Hardware properties -> DNS server assignment -> Edit.",
                  target: resolverAccess.dns_targets[0] ?? "fractal.local",
                },
              ].map((platform) => (
                <div key={platform.title} className="rounded-2xl border border-border/70 bg-white/80 p-4 text-sm">
                  <div className="font-medium text-foreground">{platform.title}</div>
                  <div className="mt-1 text-muted-foreground">{platform.detail}</div>
                  <div className="mt-3 font-mono text-sm font-semibold text-foreground">{platform.target}</div>
                </div>
              ))}
            </div>
          </div>
        </Card>

        <Card>
          <CardTitle>Resolver summary</CardTitle>
          <CardDescription>Small operational details that are still useful on the main dashboard.</CardDescription>
          <div className="mt-5 grid gap-3 text-sm">
            <Row label="Protection" value={dashboard.protection_status} />
            <Row label="Active ruleset" value={dashboard.active_ruleset?.hash.slice(0, 12) ?? "None"} />
            <Row label="Cache hits" value={String(dashboard.runtime_health.snapshot.cache_hits_total)} />
            <Row label="Fallback served" value={String(dashboard.runtime_health.snapshot.fallback_served_total)} />
            <Row label="Runtime notes" value={String(dashboard.runtime_health.notes.length)} />
          </div>
        </Card>
      </section>

      <section className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <Card>
          <CardTitle>Recent risky events</CardTitle>
          <CardDescription>Newest high-signal security events without pulling in device management controls.</CardDescription>
          <div className="mt-5 grid gap-3">
            {dashboard.recent_security_events.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                No risky DNS events recorded yet.
              </div>
            ) : (
              dashboard.recent_security_events.slice(0, 4).map((event) => (
                <div key={event.id} className="rounded-2xl border border-border/70 bg-muted/60 p-3 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-medium">{event.domain}</div>
                    <Badge>{event.severity}</Badge>
                  </div>
                  <div className="mt-1 text-muted-foreground">
                    {(event.device_name ?? "Unassigned device")} on {event.client_ip}
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>

      </section>

      {state === "loading" ? <div className="text-sm text-muted-foreground">Loading control plane data...</div> : null}
      {state === "ready" ? (
        <div className="text-sm text-muted-foreground">
          {enabledBlocklists.length} enabled blocklists and {settings.devices.length} named devices.
        </div>
      ) : null}
        </>
      ) : activePage === "profiles" ? (
        <section className="grid gap-6 xl:grid-cols-[0.88fr_1.12fr]">
          <Card>
            <CardTitle>Block profiles</CardTitle>
            <CardDescription>Build named household profiles from OISD defaults, allowlists, and any extra GitHub-hosted list you trust.</CardDescription>
            <div className="mt-5 flex items-center justify-between gap-3">
              <div className="text-sm text-muted-foreground">Saved profiles can be assigned to devices without reopening the full settings wall.</div>
              <Button variant="secondary" size="sm" className="min-w-11 px-0" onClick={startNewBlockProfile} aria-label="Create profile">+</Button>
            </div>
            <div className="mt-5 grid gap-3">
              {settings.block_profiles.length === 0 ? (
                <div className="rounded-[24px] border border-dashed border-border/70 bg-muted/30 p-5 text-sm text-muted-foreground">
                  No saved profiles yet. Start with a family-safe or focus profile and then assign it to devices.
                </div>
              ) : (
                settings.block_profiles.map((profile) => (
                  <button
                    key={profile.id}
                    type="button"
                    onClick={() => selectBlockProfile(profile)}
                    className={`rounded-[24px] border p-4 text-left transition ${selectedBlockProfileId === profile.id ? "border-foreground bg-foreground text-background" : "border-border/70 bg-white/80 hover:bg-muted/30"}`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-2xl">{profile.emoji || "◌"}</div>
                        <div className="mt-2 font-medium">{profile.name}</div>
                        <div className={`mt-1 text-sm ${selectedBlockProfileId === profile.id ? "text-background/70" : "text-muted-foreground"}`}>{profile.description || "No summary yet."}</div>
                      </div>
                      <Badge className={selectedBlockProfileId === profile.id ? "bg-background text-foreground" : "bg-muted text-muted-foreground"}>{profile.blocklists.length} sources</Badge>
                    </div>
                    <div className={`mt-3 text-xs ${selectedBlockProfileId === profile.id ? "text-background/70" : "text-muted-foreground"}`}>
                      Updated {new Date(profile.updated_at).toLocaleString()} • {profile.allowlists.length} allowlist entr{profile.allowlists.length === 1 ? "y" : "ies"}
                    </div>
                  </button>
                ))
              )}
            </div>
          </Card>

          <Card>
            <CardTitle>{selectedBlockProfileId ? "Edit profile" : "Create profile"}</CardTitle>
            <CardDescription>Pick the OISD lists this profile should use, add any custom GitHub list, and save a clear set of exceptions.</CardDescription>
            <div className="mt-5 grid gap-4">
              <div className="grid gap-3 sm:grid-cols-[120px_1fr]">
                <Input value={blockProfileDraft.emoji} onChange={(event) => setBlockProfileDraft((current) => ({ ...current, emoji: event.target.value }))} placeholder="Optional emoji" />
                <Input value={blockProfileDraft.name} onChange={(event) => setBlockProfileDraft((current) => ({ ...current, name: event.target.value }))} placeholder="Homework time" />
              </div>
              <Input value={blockProfileDraft.description} onChange={(event) => setBlockProfileDraft((current) => ({ ...current, description: event.target.value }))} placeholder="Short summary shown when assigning this profile to devices" />
              <div className="rounded-[26px] border border-border/70 bg-muted/30 p-4">
                <div className="font-medium text-foreground">Blocklist sources</div>
                <div className="mt-1 text-sm text-muted-foreground">These upstream lists define what the profile blocks before device-specific exceptions are applied.</div>
                <div className="mt-4 rounded-2xl border border-border/70 bg-white/85 p-4">
                  <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
                    <div>
                      <div className="font-medium text-foreground">OISD presets</div>
                      <div className="text-sm text-muted-foreground">Pick any combination except the overlapping small/full pair in the same family.</div>
                    </div>
                    <div className="text-xs text-muted-foreground">Core and NSFW families are kept mutually exclusive automatically.</div>
                  </div>
                  <div className="mt-4 grid gap-3 lg:grid-cols-2">
                    {oisdProfileOptions.map((option) => {
                      const enabled = blockProfileDraft.blocklists.some((entry) => entry.id === option.id);
                      return (
                        <label key={option.id} className={`rounded-[24px] border px-4 py-4 text-sm transition ${enabled ? "border-foreground bg-foreground text-background shadow-sm" : "border-border/70 bg-white/80 hover:bg-muted/30"}`}>
                          <input type="checkbox" className="sr-only" checked={enabled} onChange={() => togglePresetBlocklist(option)} />
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <div className="font-medium">{option.name}</div>
                              <div className={`mt-1 text-xs ${enabled ? "text-background/70" : "text-muted-foreground"}`}>{option.id.includes("nsfw") ? "Adult-content focused OISD feed." : "General-purpose OISD protection feed."}</div>
                            </div>
                            <Badge className={enabled ? "bg-background text-foreground" : "bg-muted text-muted-foreground"}>{option.id.includes("small") ? "small" : "full"}</Badge>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </div>
                <div className="mt-4 rounded-2xl border border-border/70 bg-white/85 p-4">
                  <div className="font-medium text-foreground">Manual GitHub list</div>
                  <div className="mt-1 text-sm text-muted-foreground">Add a named list from GitHub or raw GitHub and bundle it into this profile.</div>
                  <div className="mt-4 grid gap-3 lg:grid-cols-[0.85fr_1.15fr_auto]">
                    <Input value={customProfileListName} onChange={(event) => setCustomProfileListName(event.target.value)} placeholder="My family blocklist companion" />
                    <Input value={customProfileListUrl} onChange={(event) => setCustomProfileListUrl(event.target.value)} placeholder="https://raw.githubusercontent.com/.../domains.txt" />
                    <Button variant="secondary" onClick={addCustomBlocklistToProfile}>Add list</Button>
                  </div>
                </div>
                <div className="mt-4 grid gap-3">
                  {blockProfileDraft.blocklists.length === 0 ? (
                    <div className="rounded-2xl border border-dashed border-border/70 bg-white/70 p-4 text-sm text-muted-foreground">Choose at least one OISD preset or add a custom GitHub list here.</div>
                  ) : (
                    blockProfileDraft.blocklists.map((list) => (
                      <div key={list.id} className="flex flex-col gap-3 rounded-2xl border border-border/70 bg-white/85 p-4 sm:flex-row sm:items-center sm:justify-between">
                        <div>
                          <div className="font-medium text-foreground">{list.name}</div>
                          <div className="mt-1 break-all text-xs text-muted-foreground">{list.url}</div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge>{list.kind}</Badge>
                          <Button variant="ghost" size="sm" onClick={() => removeBlocklistFromProfile(list.id)}>Remove</Button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="rounded-[26px] border border-border/70 bg-white/85 p-4">
                <div className="font-medium text-foreground">Allowlist exceptions</div>
                <div className="mt-1 text-sm text-muted-foreground">Add domains that should stay reachable even when one of the selected blocklists would normally catch them.</div>
                <Input className="mt-4" value={blockProfileAllowlistDraft} onChange={(event) => setBlockProfileAllowlistDraft(event.target.value)} placeholder="school.example, video.example" />
              </div>
              <div className="rounded-[24px] border border-border/70 bg-muted/30 p-4 text-sm text-muted-foreground">
                Device assignment uses the profile name as the runtime override today, so keeping names short and obvious still makes the household UI easier to scan.
              </div>
              <div className="flex flex-wrap gap-3">
                <Button onClick={() => void handleBlockProfileSave()} disabled={busyAction === "block-profile-save"}>
                  {busyAction === "block-profile-save" ? "Saving..." : "Save profile"}
                </Button>
                <Button variant="ghost" onClick={startNewBlockProfile}>Clear editor</Button>
              </div>
            </div>
          </Card>
        </section>
      ) : activePage === "devices" ? (
        <section className="grid gap-6 lg:grid-cols-[1.05fr_0.95fr]">
          <Card id="devices-page">
            <CardTitle>Devices</CardTitle>
            <CardDescription>Give each device a clear name, then decide whether it keeps the household default or receives a saved profile.</CardDescription>
            <div className="mt-5 grid gap-4">
              <div className="grid gap-3 md:grid-cols-2">
                <Input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} placeholder="Kitchen iPad" />
                <Input value={deviceIpAddress} onChange={(event) => setDeviceIpAddress(event.target.value)} placeholder="192.168.1.42" />
              </div>
              <div className="grid gap-3 md:grid-cols-4">
                <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={devicePolicyMode} onChange={(event) => setDevicePolicyMode(event.target.value as "global" | "custom")}>
                  <option value="global">Household default</option>
                  <option value="custom">Custom assignment</option>
                </select>
                <select
                  className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm"
                  value={deviceProfileOverride}
                  onChange={(event) => setDeviceProfileOverride(event.target.value)}
                  disabled={devicePolicyMode !== "custom"}
                >
                  <option value="">Choose a saved profile</option>
                  {settings.block_profiles.map((profile) => (
                    <option key={profile.id} value={profile.name}>{profile.emoji} {profile.name}</option>
                  ))}
                </select>
                <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={deviceProtectionOverride} onChange={(event) => setDeviceProtectionOverride(event.target.value as "inherit" | "bypass")} disabled={devicePolicyMode !== "custom"}>
                  <option value="inherit">Keep blocking on</option>
                  <option value="bypass">Bypass blocking</option>
                </select>
                <Input
                  value={deviceAllowedDomains}
                  onChange={(event) => setDeviceAllowedDomains(event.target.value)}
                  placeholder="school.site, printer.local"
                  disabled={devicePolicyMode !== "custom"}
                />
              </div>
              <div className="grid gap-3 md:grid-cols-[1fr_160px_auto]">
                <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={deviceServiceOverrideId} onChange={(event) => setDeviceServiceOverrideId(event.target.value)} disabled={devicePolicyMode !== "custom"}>
                  <option value="">Select service override</option>
                  {settings.services.map((service) => (
                    <option key={service.manifest.service_id} value={service.manifest.service_id}>
                      {service.manifest.display_name}
                    </option>
                  ))}
                </select>
                <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={deviceServiceOverrideMode} onChange={(event) => setDeviceServiceOverrideMode(event.target.value as "allow" | "block")} disabled={devicePolicyMode !== "custom"}>
                  <option value="allow">Allow service</option>
                  <option value="block">Block service</option>
                </select>
                <Button variant="ghost" onClick={addDeviceServiceOverride} disabled={devicePolicyMode !== "custom" || !deviceServiceOverrideId || deviceServiceOverrideIsNoop}>
                  Add service rule
                </Button>
              </div>
              <div className="flex flex-wrap gap-3">
                <Button onClick={() => void handleDeviceSubmit()} disabled={!deviceName || !deviceIpAddress || busyAction === "device-submit"}>
                  {busyAction === "device-submit" ? "Saving..." : deviceId ? "Save device" : "Add device"}
                </Button>
                {deviceId ? <Button variant="ghost" onClick={resetDeviceForm}>Cancel</Button> : null}
              </div>
              {devicePolicyMode !== "custom" ? (
                <div className="rounded-[24px] border border-dashed border-border/70 bg-muted/30 p-4 text-sm text-muted-foreground">
                  This device will follow the household default until you switch it to a custom assignment.
                </div>
              ) : null}
              {deviceServiceOverrideId && deviceServiceOverridePreview ? (
                <div className="rounded-[24px] border border-border/70 bg-white/80 p-4 text-sm">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="font-medium">{deviceServiceOverridePreview.displayName}</div>
                      <div className="mt-1 text-muted-foreground">{deviceServiceOverridePreview.riskNotes}</div>
                    </div>
                    <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                      <Badge>{deviceServiceOverrideMode}</Badge>
                      <Badge>{deviceServiceOverridePreview.category}</Badge>
                      <Badge>{deviceServiceOverridePreview.domains.length} domains</Badge>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    {deviceServiceOverridePreview.sampleDomains.map((domain) => (
                      <Badge key={domain}>{domain}</Badge>
                    ))}
                  </div>
                </div>
              ) : null}
              {deviceServiceOverrides.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {deviceServiceOverrides.map((override) => (
                    <button key={`${override.service_id}-${override.mode}`} type="button" title={describeDeviceServiceOverride(override.service_id)} className="rounded-full border border-border/70 bg-muted/40 px-3 py-1 text-xs text-muted-foreground" onClick={() => removeDeviceServiceOverride(override.service_id)}>
                      {formatDeviceServiceOverride(override.service_id, override.mode)} x
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          </Card>

          <div className="grid gap-6">
            <Card>
              <CardTitle>Saved devices</CardTitle>
              <CardDescription>Detected and named devices stay easy to scan, edit, and reassign.</CardDescription>
              <div className="mt-5 grid gap-3">
                {settings.devices.length === 0 ? (
                  <div className="rounded-[24px] border border-dashed border-border/70 bg-muted/30 p-5 text-sm text-muted-foreground">
                    No devices have been named yet. Start with the devices the household will recognize fastest.
                  </div>
                ) : (
                  settings.devices.map((device) => (
                    <div key={device.id} className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="font-medium">{device.name}</div>
                          <div className="text-sm text-muted-foreground">{device.ip_address}</div>
                        </div>
                        <Badge>{device.policy_mode === "custom" ? "Custom" : "Default"}</Badge>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                        <Badge>{device.blocklist_profile_override ?? "Household default"}</Badge>
                        <Badge>{device.protection_override === "bypass" ? "Bypass enabled" : "Blocking on"}</Badge>
                        <Badge>{device.allowed_domains.length} allowlisted</Badge>
                        <Badge>{device.service_overrides.length} service rules</Badge>
                      </div>
                      <div className="mt-4">
                        <Button variant="ghost" size="sm" onClick={() => startDeviceEdit(device)}>
                          Edit device
                        </Button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </Card>

            <Card>
              <CardTitle>Assignment help</CardTitle>
              <CardDescription>Use friendly names from saved block profiles so the household can tell what each device is using at a glance.</CardDescription>
              <div className="mt-5 grid gap-3 text-sm text-muted-foreground">
                {settings.block_profiles.length === 0 ? (
                  <div className="rounded-[24px] border border-dashed border-border/70 bg-muted/30 p-4">
                    Create a block profile first, then come back here to assign it to a device.
                  </div>
                ) : (
                  settings.block_profiles.map((profile) => (
                    <div key={profile.id} className="rounded-[24px] border border-border/70 bg-muted/40 p-4">
                      <div className="font-medium text-foreground">{profile.emoji} {profile.name}</div>
                      <div className="mt-1">{profile.description}</div>
                    </div>
                  ))
                )}
              </div>
            </Card>
          </div>
        </section>
      ) : activePage === "grease-ai" ? (
        <section className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
          <Card>
            <CardTitle>Grease-AI</CardTitle>
            <CardDescription>A placeholder home for the AI classifier while we shape how the learning loop should feel in the household control plane.</CardDescription>
            <div className="mt-5 rounded-[28px] border border-border/70 bg-[radial-gradient(circle_at_top_left,rgba(115,196,255,0.2),transparent_35%),radial-gradient(circle_at_bottom_right,rgba(129,224,170,0.22),transparent_38%),linear-gradient(180deg,rgba(255,255,255,0.96),rgba(246,244,240,0.94))] p-5">
              <div className="grid gap-4 lg:grid-cols-[0.9fr_1.1fr]">
                <div className="space-y-3">
                  <div className="text-sm font-medium text-foreground">Learning pulse</div>
                  <div className="space-y-3">
                    {greaseAiSignals.map((signal) => (
                      <div key={signal.label} className="rounded-2xl border border-border/60 bg-white/75 p-4">
                        <div className="flex items-center justify-between gap-3 text-sm">
                          <span className="font-medium text-foreground">{signal.label}</span>
                          <span className="text-muted-foreground">{Math.round(signal.value * 100)}%</span>
                        </div>
                        <div className="mt-3 h-3 overflow-hidden rounded-full bg-muted/60">
                          <div className={`h-full rounded-full bg-gradient-to-r ${signal.tint}`} style={{ width: `${Math.max(signal.value * 100, 6)}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="rounded-[26px] border border-border/70 bg-slate-950 p-5 text-slate-100 shadow-inner">
                  <div className="text-xs uppercase tracking-[0.24em] text-slate-400">Classifier animation</div>
                  <div className="mt-4 grid gap-3">
                    {[0, 1, 2, 3, 4].map((row) => (
                      <div key={row} className="grid grid-cols-8 gap-2">
                        {greaseAiSignals.map((signal, index) => (
                          <div
                            key={`${row}-${signal.label}-${index}`}
                            className="h-5 rounded-full bg-gradient-to-r from-sky-400/20 via-cyan-300/80 to-emerald-300/30"
                            style={{ opacity: Math.max(0.2, signal.value - row * 0.12 + index * 0.04) }}
                          />
                        ))}
                        <div className="h-5 rounded-full bg-white/10" />
                        <div className="h-5 rounded-full bg-white/5" />
                        <div className="h-5 rounded-full bg-white/10" />
                        <div className="h-5 rounded-full bg-white/5" />
                        <div className="h-5 rounded-full bg-white/10" />
                      </div>
                    ))}
                  </div>
                  <div className="mt-4 text-sm text-slate-300">The bars brighten as more DNS activity arrives, blocked decisions climb, and the runtime stays inside latency budget.</div>
                </div>
              </div>
            </div>
          </Card>

          <div className="grid gap-6">
            <Card>
              <CardTitle>Classifier stats</CardTitle>
              <CardDescription>Operational numbers behind the current learning pulse.</CardDescription>
              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Mode</div>
                  <div className="mt-1 text-xl font-semibold text-foreground">{settings.classifier.mode}</div>
                </div>
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Threshold</div>
                  <div className="mt-1 text-xl font-semibold text-foreground">{settings.classifier.threshold.toFixed(2)}</div>
                </div>
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Queries observed</div>
                  <div className="mt-1 text-xl font-semibold text-foreground">{dashboard.runtime_health.snapshot.queries_total.toLocaleString()}</div>
                </div>
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Blocked queries</div>
                  <div className="mt-1 text-xl font-semibold text-foreground">{dashboard.runtime_health.snapshot.blocked_total.toLocaleString()}</div>
                </div>
              </div>
            </Card>

            <Card>
              <CardTitle>Latency budgets</CardTitle>
              <CardDescription>Live hot-path budget checks after the latest traffic observed by this resolver.</CardDescription>
              <div className="mt-5 grid gap-3 sm:grid-cols-3">
                {latencyBudget.checks.map((check) => (
                  <div key={check.label} className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-medium text-foreground">{check.label}</div>
                      <Badge>{check.status}</Badge>
                    </div>
                    <div className="mt-2 text-xl font-semibold text-foreground">{check.observed_ms.toFixed(3)} ms</div>
                    <div className="mt-1 text-xs text-muted-foreground">Target {check.target_p50_ms.toFixed(1)} ms • {check.sample_count} samples</div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </section>
      ) : (
        <section className="grid gap-6">
          <Card>
            <CardTitle>Settings</CardTitle>
            <CardDescription>Technical controls live here: syncing, Tailscale, alerts, blocklists, recovery, and operator visibility.</CardDescription>
            <div className="mt-5 grid gap-4 lg:grid-cols-2">
              <div className="rounded-[24px] border border-border/70 bg-muted/40 p-4 text-sm">
                <div className="font-medium">Sync and replication</div>
                <div className="mt-2 grid gap-2 text-muted-foreground">
                  <div>Profile: <span className="font-medium text-foreground">{syncStatus.profile}</span></div>
                  <div>Revision: <span className="font-medium text-foreground">{syncStatus.revision}</span></div>
                  <div>Peers: <span className="font-medium text-foreground">{syncStatus.peers.length}</span></div>
                </div>
                <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_auto]">
                  <select className="h-10 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={syncProfileDraft} onChange={(event) => setSyncProfileDraft(event.target.value)}>
                    <option value="full">Full replication</option>
                    <option value="settings-only">Settings only</option>
                    <option value="read-only-follower">Read-only follower</option>
                  </select>
                  <Button variant="secondary" size="sm" onClick={() => void handleSyncProfileSave()} disabled={busyAction === "sync-profile-save"}>Save profile</Button>
                </div>
                <div className="mt-3 grid gap-3 sm:grid-cols-[180px_1fr_auto]">
                  <select className="h-10 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={syncTransportModeDraft} onChange={(event) => setSyncTransportModeDraft(event.target.value)}>
                    <option value="opportunistic">Opportunistic</option>
                    <option value="https-required">HTTPS required</option>
                  </select>
                  <Input value={syncTransportTokenDraft} onChange={(event) => setSyncTransportTokenDraft(event.target.value)} placeholder={syncStatus.transport_token_configured ? "Set new token or leave blank to clear" : "Optional bearer token"} />
                  <Button variant="secondary" size="sm" onClick={() => void handleSyncTransportSave()} disabled={busyAction === "sync-transport-save"}>Save transport</Button>
                </div>
              </div>
              <div className="rounded-[24px] border border-border/70 bg-muted/40 p-4 text-sm">
                <div className="flex items-center justify-between gap-3">
                  <div className="font-medium">Tailscale</div>
                  <Badge>{tailscaleStatus.exit_node_active ? "Exit node advertised" : tailscaleStatus.installed ? "Installed" : "Not installed"}</Badge>
                </div>
                <div className="mt-2 grid gap-2 text-muted-foreground">
                  <div>Host: <span className="font-medium text-foreground">{tailscaleStatus.hostname ?? "-"}</span></div>
                  <div>Tailnet: <span className="font-medium text-foreground">{tailscaleStatus.tailnet_name ?? "-"}</span></div>
                  <div>Peers: <span className="font-medium text-foreground">{tailscaleStatus.peer_count}</span></div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button variant={tailscaleStatus.exit_node_active ? "ghost" : "secondary"} size="sm" onClick={() => void handleTailscaleExitNodeToggle()} disabled={busyAction === "tailscale-exit-node"}>
                    {busyAction === "tailscale-exit-node" ? "Updating..." : tailscaleStatus.exit_node_active ? "Disable exit-node filtering" : "Enable exit-node filtering"}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => void handleTailscaleRollback()} disabled={busyAction === "tailscale-rollback"}>
                    {busyAction === "tailscale-rollback" ? "Rolling back..." : "Roll back"}
                  </Button>
                </div>
                {tailscaleDnsCheck.suggestions.length > 0 ? (
                  <div className="mt-3 rounded-lg bg-blue-50 px-3 py-2 text-xs text-blue-800">{tailscaleDnsCheck.message}</div>
                ) : null}
                <div className="mt-3 text-xs text-muted-foreground">When enabled, Cogwheel advertises this machine as a Tailscale exit node and keeps DNS on the local filter path for exit-node traffic only.</div>
              </div>
            </div>
            <div className="mt-4 rounded-[24px] border border-border/70 bg-muted/30 p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-medium">Latency budgets</div>
                  <div className="text-sm text-muted-foreground">Tracks the DNS hot path against the documented p50 budgets for cache hits, cache misses, and classifier work.</div>
                </div>
                <Badge>{latencyBudget.within_budget ? "Within budget" : "Needs attention"}</Badge>
              </div>
              <div className="mt-4 grid gap-3 lg:grid-cols-[0.9fr_1.1fr]">
                <div className="rounded-2xl border border-border/70 bg-white/70 p-4 text-sm">
                  <div className="text-muted-foreground">Current cache hit rate</div>
                  <div className="mt-1 text-2xl font-semibold text-foreground">{(latencyBudget.cache_hit_rate * 100).toFixed(1)}%</div>
                  <div className="mt-2 text-xs text-muted-foreground">Higher cache hit rates usually keep household traffic under the fastest path budget.</div>
                </div>
                <div className="grid gap-3 sm:grid-cols-3">
                  {latencyBudget.checks.map((check) => (
                    <div key={check.label} className="rounded-2xl border border-border/70 bg-white/70 p-4 text-sm">
                      <div className="flex items-center justify-between gap-2">
                        <div className="font-medium text-foreground">{check.label}</div>
                        <Badge>{check.status}</Badge>
                      </div>
                      <div className="mt-3 text-lg font-semibold text-foreground">{check.observed_ms.toFixed(3)} ms</div>
                      <div className="mt-1 text-xs text-muted-foreground">Target p50 {check.target_p50_ms.toFixed(1)} ms</div>
                      <div className="mt-1 text-xs text-muted-foreground">Samples: {check.sample_count}</div>
                    </div>
                  ))}
                </div>
              </div>
              {latencyBudget.recommendations.length > 0 ? (
                <div className="mt-4 rounded-2xl border border-dashed border-border/70 bg-background/80 p-4 text-sm text-muted-foreground">
                  {latencyBudget.recommendations.join(" ")}
                </div>
              ) : null}
            </div>
          </Card>

          <section className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
            <Card id="settings-page-core">
              <CardTitle>Policy and notifications</CardTitle>
              <CardDescription>Core controls for classifier behavior, alerts, feeds, and imported lists.</CardDescription>
              <div className="mt-6 space-y-5">
                <section className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">Classifier mode</div>
                      <div className="text-sm text-muted-foreground">Persisted directly in the backend control plane.</div>
                    </div>
                    <Badge>{settings.classifier.mode}</Badge>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {(["Off", "Monitor", "Protect"] as const).map((mode) => (
                      <Button key={mode} variant={settings.classifier.mode === mode ? "primary" : "secondary"} size="sm" onClick={() => void handleClassifierUpdate(mode)} disabled={busyAction === `classifier-mode-${mode}`}>
                        {mode}
                      </Button>
                    ))}
                  </div>
                  <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                    <Input value={classifierThreshold} onChange={(event) => setClassifierThreshold(event.target.value)} placeholder="0.92" />
                    <Button variant="secondary" onClick={() => void handleClassifierThresholdSave()} disabled={busyAction === "classifier-threshold"}>Save threshold</Button>
                  </div>
                </section>

                <Separator />

                <section className="space-y-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="font-medium">Alert delivery</div>
                      <div className="text-sm text-muted-foreground">Send high-severity security alerts to an external webhook.</div>
                    </div>
                    <Badge>{notificationEnabled ? `Webhook ${notificationMinSeverity}+` : "Disabled"}</Badge>
                  </div>
                  <label className="flex items-center gap-3 rounded-2xl border border-border/70 bg-muted/40 px-4 py-3 text-sm">
                    <input type="checkbox" checked={notificationEnabled} onChange={(event) => setNotificationEnabled(event.target.checked)} />
                    Enable outbound alert notifications
                  </label>
                  <div className="grid gap-3 sm:grid-cols-[1fr_170px_auto]">
                    <Input value={notificationWebhookUrl} onChange={(event) => setNotificationWebhookUrl(event.target.value)} placeholder="https://hooks.example.com/cogwheel" />
                    <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={notificationMinSeverity} onChange={(event) => setNotificationMinSeverity(event.target.value as "medium" | "high" | "critical")}>
                      <option value="medium">Medium+</option>
                      <option value="high">High+</option>
                      <option value="critical">Critical only</option>
                    </select>
                    <div className="flex gap-2">
                      <Button variant="secondary" onClick={() => void handleNotificationSave()} disabled={busyAction === "notifications-save"}>Save alerts</Button>
                      <Button variant="ghost" onClick={() => void handleNotificationTest()} disabled={busyAction === "notifications-test" || !notificationWebhookUrl}>Send test</Button>
                    </div>
                  </div>
                </section>

                <Separator />

                <section className="space-y-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="font-medium">Optional intelligence feeds</div>
                      <div className="text-sm text-muted-foreground">Keep enrichment providers off the DNS hot path and enable them only when needed.</div>
                    </div>
                    <Badge>{threatIntelSettings.providers.filter((provider) => provider.enabled).length} enabled</Badge>
                  </div>
                  <div className="grid gap-3">
                    {threatIntelSettings.providers.map((provider) => (
                      <div key={provider.id} className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="font-medium">{provider.display_name}</div>
                            <div className="mt-1 text-xs text-muted-foreground">{provider.capabilities.join(" • ")}</div>
                          </div>
                          <Badge className={provider.enabled ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"}>{provider.enabled ? "Enabled" : "Disabled"}</Badge>
                        </div>
                        <div className="mt-3 grid gap-3 sm:grid-cols-[1fr_180px_auto]">
                          <Input value={provider.feed_url ?? ""} onChange={(event) => setThreatIntelSettings((current) => ({ ...current, providers: current.providers.map((item) => item.id === provider.id ? { ...item, feed_url: event.target.value || null } : item) }))} placeholder="https://feed.example.invalid/dns" />
                          <Input value={String(provider.update_interval_minutes)} onChange={(event) => {
                            const nextValue = Number.parseInt(event.target.value, 10);
                            setThreatIntelSettings((current) => ({
                              ...current,
                              providers: current.providers.map((item) => item.id === provider.id ? { ...item, update_interval_minutes: Number.isNaN(nextValue) ? item.update_interval_minutes : nextValue } : item),
                            }));
                          }} placeholder="60" />
                          <Button variant="secondary" size="sm" onClick={() => void handleThreatIntelProviderSave(provider.id)} disabled={busyAction === `threat-intel-${provider.id}`}>{busyAction === `threat-intel-${provider.id}` ? "Saving..." : "Save"}</Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>

                <Separator />

                <section className="space-y-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="font-medium">Federated learning</div>
                      <div className="text-sm text-muted-foreground">Share model updates only. Raw logs stay local.</div>
                    </div>
                    <Badge>{federatedLearningSettings.enabled ? federatedLearningSettings.privacy_mode : "Disabled"}</Badge>
                  </div>
                  <label className="flex items-center gap-3 rounded-2xl border border-border/70 bg-muted/40 px-4 py-3 text-sm">
                    <input type="checkbox" checked={federatedLearningSettings.enabled} onChange={(event) => setFederatedLearningSettings((current) => ({ ...current, enabled: event.target.checked }))} />
                    Enable federated learning coordinator sync
                  </label>
                  <div className="grid gap-3 sm:grid-cols-[1fr_180px_auto]">
                    <Input value={federatedLearningSettings.coordinator_url ?? ""} onChange={(event) => setFederatedLearningSettings((current) => ({ ...current, coordinator_url: event.target.value || null }))} placeholder="https://coordinator.example.invalid" />
                    <Input value={String(federatedLearningSettings.round_interval_hours)} onChange={(event) => {
                      const nextValue = Number.parseInt(event.target.value, 10);
                      setFederatedLearningSettings((current) => ({ ...current, round_interval_hours: Number.isNaN(nextValue) ? current.round_interval_hours : nextValue }));
                    }} placeholder="24" />
                    <Button variant="secondary" onClick={() => void handleFederatedLearningSave()} disabled={busyAction === "federated-learning-save"}>{busyAction === "federated-learning-save" ? "Saving..." : "Save"}</Button>
                  </div>
                </section>
              </div>
            </Card>

            <div className="grid gap-6">
              <Card id="settings-page-blocklists">
                <CardTitle>Sources and services</CardTitle>
                <CardDescription>Manage imported blocklists and common-service toggles without crowding the overview.</CardDescription>
                <div className="mt-5 grid gap-3">
                  <div className="rounded-[24px] border border-border/70 bg-muted/40 p-4 text-sm">
                    <div className="font-medium">Add blocklist</div>
                    <div className="mt-3 grid gap-3">
                      <Input value={blocklistName} onChange={(event) => setBlocklistName(event.target.value)} placeholder="Human-readable name" />
                      <Input value={blocklistUrl} onChange={(event) => setBlocklistUrl(event.target.value)} placeholder="Source URL or data: URL" />
                      <div className="grid gap-3 sm:grid-cols-3">
                        <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={blocklistProfile} onChange={(event) => setBlocklistProfile(event.target.value)}>
                          <option value="custom">Custom</option>
                          <option value="essential">Essential</option>
                          <option value="balanced">Balanced</option>
                          <option value="aggressive">Aggressive</option>
                        </select>
                        <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={blocklistStrictness} onChange={(event) => setBlocklistStrictness(event.target.value as "strict" | "balanced" | "relaxed")}>
                          <option value="strict">Strict</option>
                          <option value="balanced">Balanced</option>
                          <option value="relaxed">Relaxed</option>
                        </select>
                        <Input value={blocklistInterval} onChange={(event) => setBlocklistInterval(event.target.value)} placeholder="Refresh minutes" />
                      </div>
                      <Button onClick={() => void handleBlocklistCreate()} disabled={!blocklistName || !blocklistUrl || busyAction === "create-blocklist"}>Add blocklist</Button>
                    </div>
                  </div>
                  {settings.blocklists.map((source) => (
                    <div key={source.id} className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="font-medium">{source.name}</div>
                          <div className="text-sm text-muted-foreground">{source.profile} • {source.refresh_interval_minutes}m</div>
                        </div>
                        <div className="flex gap-2">
                          <Button variant="secondary" size="sm" onClick={() => void handleBlocklistToggle(source.id, !source.enabled)} disabled={busyAction === `blocklist-toggle-${source.id}`}>{source.enabled ? "Disable" : "Enable"}</Button>
                        </div>
                      </div>
                    </div>
                  ))}
                  <Card id="services" className="p-5">
                    <CardTitle>Services</CardTitle>
                    <CardDescription className="mt-1">Optional curated allow/block toggles for common apps.</CardDescription>
                    <div className="mt-4 grid gap-3">
                      {filteredServices.slice(0, showServicesView ? filteredServices.length : 3).map((service) => (
                        <div key={service.manifest.service_id} className="rounded-[24px] border border-border/70 bg-muted/40 p-4">
                          <div className="flex items-center justify-between gap-3">
                            <div>
                              <div className="font-medium">{service.manifest.display_name}</div>
                              <div className="text-sm text-muted-foreground">{service.manifest.risk_notes}</div>
                            </div>
                            <Badge>{service.mode}</Badge>
                          </div>
                          <div className="mt-3 flex gap-2">
                            {(["Inherit", "Allow", "Block"] as const).map((mode) => (
                              <Button key={mode} variant={service.mode === mode ? "primary" : "secondary"} size="sm" onClick={() => void handleServiceUpdate(service.manifest.service_id, mode)} disabled={busyAction === `service-${service.manifest.service_id}`}>
                                {mode}
                              </Button>
                            ))}
                          </div>
                        </div>
                      ))}
                      {!showServicesView ? <Button variant="ghost" onClick={() => setShowServicesView(true)}>Show all services</Button> : null}
                    </div>
                  </Card>
                </div>
              </Card>

              <Card>
                <CardTitle>Recovery and operator feed</CardTitle>
                <CardDescription>Use guided recovery, audit history, and runtime notes without cluttering the household overview.</CardDescription>
                <div className="mt-5 space-y-5">
                  <section className="space-y-3">
                    <div className="font-medium">Guided recovery</div>
                    <div className="grid gap-3">
                      {recoveryActions.map((item) => (
                        <div key={item.title} className="rounded-[24px] border border-border/70 bg-muted/40 p-4 text-sm">
                          <div className="font-medium">{item.title}</div>
                          <div className="mt-1 text-muted-foreground">{item.detail}</div>
                          <div className="mt-3">
                            <Button variant="secondary" size="sm" onClick={() => {
                              if (item.actionKey === "runtime-health-check") {
                                void handleRuntimeHealthCheck();
                                return;
                              }
                              if (item.actionKey === "notifications") {
                                setAuditEventFilter("notifications");
                                return;
                              }
                              if (item.actionKey === "rollback-ruleset") {
                                void handleRollbackRuleset();
                                return;
                              }
                              void handleRefreshSources();
                            }} disabled={item.disabled}>
                              {item.actionLabel}
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>
                  <Separator />
                  <section className="space-y-3">
                    <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                      <div>
                        <div className="font-medium">Recent audit events</div>
                        <div className="text-sm text-muted-foreground">Filter the operator feed to focus on the control-plane changes you are investigating.</div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {[["all", "All events"], ["runtime", "Runtime"], ["notifications", "Notifications"], ["devices", "Devices"], ["rulesets", "Rulesets"]].map(([value, label]) => (
                          <Button key={value} variant={auditEventFilter === value ? "primary" : "ghost"} size="sm" onClick={() => setAuditEventFilter(value as "all" | "runtime" | "notifications" | "devices" | "rulesets")}>{label}</Button>
                        ))}
                      </div>
                    </div>
                    <div className="grid gap-3">
                      {filteredAuditEvents.slice(0, 8).map((event) => {
                        const summary = summarizeAuditEvent(event);
                        return (
                          <div key={event.id} className="rounded-2xl border border-border/70 bg-muted/60 p-3 text-sm">
                            <div className="flex items-start justify-between gap-3">
                              <div>
                                <div className="font-medium">{summary.title}</div>
                                <div className="mt-1 text-xs text-muted-foreground">{event.event_type}</div>
                              </div>
                              <Badge>{summary.category}</Badge>
                            </div>
                            <div className="mt-2 text-muted-foreground">{summary.detail}</div>
                          </div>
                        );
                      })}
                    </div>
                  </section>
                </div>
              </Card>
            </div>
          </section>
        </section>
      )}
      </div>
    </main>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}

function summarizeAuditEvent(event: AuditEvent) {
  const payload = parseAuditPayload(event.payload);
  const category = event.event_type.split(".")[0] ?? "system";

  if (event.event_type === "ruleset.rollback") {
    return {
      category,
      title: "Ruleset rollback completed",
      detail: `Recovered ruleset ${String(payload.hash ?? "unknown").slice(0, 12)} after an operator-triggered rollback.`,
    };
  }

  if (event.event_type === "ruleset.auto_rollback") {
    return {
      category,
      title: "Automatic rollback triggered",
      detail: String(firstPayloadItem(payload.notes) ?? "Runtime guard restored the previous verified ruleset."),
    };
  }

  if (event.event_type === "ruleset.refresh_rejected") {
    return {
      category,
      title: "Ruleset refresh rejected",
      detail: String(firstPayloadItem(payload.notes) ?? "Verification blocked the candidate ruleset before activation."),
    };
  }

  if (event.event_type.startsWith("notification.delivery_") || event.event_type.startsWith("security.alert_delivery_")) {
    return {
      category,
      title: String(payload.title ?? payload.domain ?? "Notification delivery"),
      detail: String(payload.summary ?? `${payload.severity ?? "unknown"} delivery to ${payload.client_ip ?? payload.device_name ?? "control-plane"}.`),
    };
  }

  if (event.event_type.startsWith("runtime.health_check_")) {
    return {
      category,
      title: event.event_type.endsWith("degraded") ? "Runtime health degraded" : "Runtime health check passed",
      detail: String(firstPayloadItem(payload.notes) ?? "Manual runtime health check completed."),
    };
  }

  if (event.event_type === "device.upserted") {
    return {
      category,
      title: `Updated device ${String(payload.name ?? "unnamed device")}`,
      detail: `Policy mode ${String(payload.policy_mode ?? "unknown")} for ${String(payload.ip_address ?? "unknown IP")}.`,
    };
  }

  const [firstKey, firstValue] = Object.entries(payload)[0] ?? [];
  return {
    category,
    title: event.event_type,
    detail: firstKey ? `${firstKey}: ${stringifyAuditValue(firstValue)}` : "No structured payload details recorded.",
  };
}

function parseAuditPayload(payload: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(payload) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function firstPayloadItem(value: unknown) {
  return Array.isArray(value) && value.length > 0 ? value[0] : undefined;
}

function stringifyAuditValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value) && value.length > 0) return stringifyAuditValue(value[0]);
  if (value && typeof value === "object") {
    const [firstKey, firstValue] = Object.entries(value)[0] ?? [];
    return firstKey ? `${firstKey}: ${stringifyAuditValue(firstValue)}` : "details available";
  }
  return "details available";
}
