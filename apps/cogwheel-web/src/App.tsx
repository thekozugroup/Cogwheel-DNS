import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Activity, ListFilter, RefreshCw, ShieldCheck, Sparkles, Undo2 } from "lucide-react";
import { api, type AuditEvent, type DashboardSummary, type SettingsSummary } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";

type LoadState = "idle" | "loading" | "ready" | "error";
type Toast = { id: number; title: string; detail?: string; tone: "success" | "error" | "info" };

const emptyDashboard: DashboardSummary = {
  protection_status: "Loading",
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
};

const emptySettings: SettingsSummary = {
  blocklists: [],
  blocklist_statuses: [],
  devices: [],
  services: [],
  classifier: { mode: "Monitor", threshold: 0.92 },
  notifications: { enabled: false, webhook_url: null, min_severity: "high" },
  notification_test_presets: [],
  runtime_guard: { probe_domains: [], max_upstream_failures_delta: 0, max_fallback_served_delta: 0 },
};

export default function App() {
  const [dashboard, setDashboard] = useState<DashboardSummary>(emptyDashboard);
  const [settings, setSettings] = useState<SettingsSummary>(emptySettings);
  const [state, setState] = useState<LoadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const [blocklistName, setBlocklistName] = useState("");
  const [blocklistUrl, setBlocklistUrl] = useState("");
  const [blocklistProfile, setBlocklistProfile] = useState("custom");
  const [blocklistStrictness, setBlocklistStrictness] = useState<"strict" | "balanced" | "relaxed">("balanced");
  const [blocklistInterval, setBlocklistInterval] = useState("60");
  const [editingBlocklistId, setEditingBlocklistId] = useState<string | null>(null);

  const [classifierThreshold, setClassifierThreshold] = useState("0.92");
  const [notificationEnabled, setNotificationEnabled] = useState(false);
  const [notificationWebhookUrl, setNotificationWebhookUrl] = useState("");
  const [notificationMinSeverity, setNotificationMinSeverity] = useState<"medium" | "high" | "critical">("high");
  const [notificationTestDomain, setNotificationTestDomain] = useState("notification-test.cogwheel.local");
  const [notificationTestSeverity, setNotificationTestSeverity] = useState<"medium" | "high" | "critical">("high");
  const [notificationTestDeviceName, setNotificationTestDeviceName] = useState("Control Plane Test");
  const [notificationDryRun, setNotificationDryRun] = useState(false);
  const [notificationPresetName, setNotificationPresetName] = useState("");
  const [selectedNotificationPreset, setSelectedNotificationPreset] = useState("");
  const [notificationAnalyticsWindow, setNotificationAnalyticsWindow] = useState<10 | 30 | 50 | 100>(30);
  const [notificationHistoryWindow, setNotificationHistoryWindow] = useState<10 | 30 | 50 | 100>(10);
  const [serviceSearch, setServiceSearch] = useState("");
  const [auditEventFilter, setAuditEventFilter] = useState<"all" | "runtime" | "notifications" | "devices" | "rulesets">("all");
  const [notificationDeliveryFilter, setNotificationDeliveryFilter] = useState<"all" | "failed" | "security" | "control-plane">("all");

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

  const load = useCallback(async () => {
    setState("loading");
    setError(null);
    try {
      const [dashboardData, settingsData] = await Promise.all([
        api.dashboard(notificationAnalyticsWindow, notificationHistoryWindow),
        api.settings(),
      ]);
      setDashboard(dashboardData);
      setSettings(settingsData);
      setState("ready");
    } catch (loadError) {
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
    if (!selectedNotificationPreset) return;
    const preset = settings.notification_test_presets.find((item) => item.name === selectedNotificationPreset);
    if (!preset) return;
    setNotificationPresetName(preset.name);
    setNotificationTestDomain(preset.domain);
    setNotificationTestSeverity(preset.severity);
    setNotificationTestDeviceName(preset.device_name);
    setNotificationDryRun(preset.dry_run);
  }, [selectedNotificationPreset, settings.notification_test_presets]);

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

  const filteredNotificationDeliveries = useMemo(
    () => dashboard.recent_notification_deliveries.filter((delivery) => {
      if (notificationDeliveryFilter === "all") return true;
      if (notificationDeliveryFilter === "failed") return delivery.status === "failed";
      if (notificationDeliveryFilter === "security") return delivery.event_type.startsWith("security.");
      if (notificationDeliveryFilter === "control-plane") return !delivery.event_type.startsWith("security.");
      return true;
    }),
    [dashboard.recent_notification_deliveries, notificationDeliveryFilter],
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
  }, [busyAction, dashboard.notification_health.delivered_count, dashboard.notification_health.failed_count, dashboard.runtime_health.degraded, dashboard.runtime_health.notes, error, state]);

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

  const onboardingChecklist = useMemo(() => {
    const enabledBlocklistsCount = settings.blocklists.filter((source) => source.enabled).length;
    const items = [
      {
        title: "Add a blocklist",
        done: enabledBlocklistsCount > 0,
        detail: enabledBlocklistsCount > 0 ? `${enabledBlocklistsCount} blocklist source${enabledBlocklistsCount === 1 ? " is" : "s are"} enabled.` : "Turn on at least one source so Cogwheel can build an active ruleset.",
        actionLabel: "Open blocklists",
        actionKey: "blocklists" as const,
      },
      {
        title: "Enable the classifier",
        done: settings.classifier.mode !== "Off",
        detail: settings.classifier.mode !== "Off" ? `Classifier is in ${settings.classifier.mode} mode.` : "Switch the classifier out of Off mode for risky-domain detection.",
        actionLabel: "Open settings",
        actionKey: "settings" as const,
      },
      {
        title: "Name a device",
        done: settings.devices.length > 0,
        detail: settings.devices.length > 0 ? `${settings.devices.length} named device${settings.devices.length === 1 ? "" : "s"} tracked.` : "Name at least one device so per-device policy and alerts are easier to interpret.",
        actionLabel: "Open devices",
        actionKey: "devices" as const,
      },
      {
        title: "Configure alert delivery",
        done: settings.notifications.enabled && Boolean(settings.notifications.webhook_url),
        detail: settings.notifications.enabled && settings.notifications.webhook_url
          ? `Webhook notifications are enabled at ${settings.notifications.min_severity} severity and above.`
          : "Add a webhook destination so operators hear about degraded health and risky alerts quickly.",
        actionLabel: "Open settings",
        actionKey: "settings" as const,
      },
    ];

    return {
      completed: items.filter((item) => item.done).length,
      total: items.length,
      items,
    };
  }, [settings.blocklists, settings.classifier.mode, settings.devices.length, settings.notifications.enabled, settings.notifications.min_severity, settings.notifications.webhook_url]);

  function scrollToSection(sectionId: string) {
    document.getElementById(sectionId)?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

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

  async function handleNotificationPresetSave() {
    if (!notificationPresetName.trim()) {
      pushToast("Preset name required", "Name the preset before saving it.", "error");
      return;
    }

    setBusyAction("notifications-preset-save");
    try {
      const nextPresets = settings.notification_test_presets.filter(
        (preset) => preset.name !== notificationPresetName.trim(),
      );
      nextPresets.push({
        name: notificationPresetName.trim(),
        domain: notificationTestDomain,
        severity: notificationTestSeverity,
        device_name: notificationTestDeviceName,
        dry_run: notificationDryRun,
      });
      nextPresets.sort((left, right) => left.name.localeCompare(right.name));
      await api.updateNotificationTestPresets(nextPresets);
      setSelectedNotificationPreset(notificationPresetName.trim());
      pushToast("Preset saved", `Stored ${notificationPresetName.trim()} for future tests.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Preset save failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
  }

  async function handleNotificationPresetDelete() {
    if (!selectedNotificationPreset) {
      pushToast("Preset required", "Select a saved preset before deleting it.", "error");
      return;
    }

    setBusyAction("notifications-preset-delete");
    try {
      const nextPresets = settings.notification_test_presets.filter(
        (preset) => preset.name !== selectedNotificationPreset,
      );
      await api.updateNotificationTestPresets(nextPresets);
      pushToast("Preset deleted", `${selectedNotificationPreset} was removed.`, "success");
      setSelectedNotificationPreset("");
      setNotificationPresetName("");
      await load();
    } catch (mutationError) {
      pushToast("Preset delete failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
    } finally {
      setBusyAction(null);
    }
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

  async function handleBlocklistEdit(source: SettingsSummary["blocklists"][number]) {
    setBusyAction(`blocklist-save-${source.id}`);
    try {
      await api.upsertBlocklist({
        id: source.id,
        name: source.name,
        url: source.url,
        kind: source.kind,
        enabled: source.enabled,
        refresh_interval_minutes: source.refresh_interval_minutes,
        profile: source.profile,
        verification_strictness: source.verification_strictness,
      });
      setEditingBlocklistId(null);
      pushToast("Blocklist updated", `${source.name} metadata was saved.`, "success");
      await load();
    } catch (mutationError) {
      pushToast("Blocklist update failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
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

  async function handleBlocklistDelete(id: string) {
    setBusyAction(`blocklist-delete-${id}`);
    try {
      await api.deleteBlocklist(id);
      pushToast("Blocklist deleted", "The source was removed and refresh requested.", "success");
      await load();
    } catch (mutationError) {
      pushToast("Blocklist delete failed", mutationError instanceof Error ? mutationError.message : "Unknown error", "error");
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
    <main className="mx-auto flex min-h-screen max-w-7xl flex-col gap-6 px-6 py-8 md:px-10">
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

      <section className="grid gap-4 md:grid-cols-[1.4fr_0.9fr]">
        <Card className="overflow-hidden bg-gradient-to-br from-card via-white to-secondary/70">
          <div className="flex flex-col gap-6">
            <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
              <div className="space-y-4">
                <Badge className={controlPlaneStatus.tone === "primary" ? "bg-primary text-primary-foreground" : controlPlaneStatus.tone === "secondary" ? "bg-secondary text-secondary-foreground" : "bg-muted text-foreground"}>
                  {controlPlaneStatus.label}
                </Badge>
                <div className="space-y-2">
                  <h1 className="font-display text-4xl font-semibold tracking-tight md:text-5xl">Quiet control, visible protection.</h1>
                  <p className="max-w-2xl text-sm text-muted-foreground md:text-base">
                    The control plane now surfaces sources, device naming, and recent risky-query signals while the Rust backend keeps policy and rollback logic centralized.
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button variant="secondary" onClick={() => void handleRefreshSources()} disabled={busyAction === "refresh-sources"}>
                  <RefreshCw className="mr-2 size-4" />
                  Refresh sources
                </Button>
                <Button variant="ghost" onClick={() => void handleRollbackRuleset()} disabled={busyAction === "rollback-ruleset"}>
                  <Undo2 className="mr-2 size-4" />
                  Roll back
                </Button>
              </div>
            </div>
            <div className="rounded-[28px] border border-border/70 bg-white/75 p-5">
              <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                <div className="space-y-2">
                  <div className="text-sm font-medium text-foreground">Control-plane status</div>
                  <div className="max-w-2xl text-sm text-muted-foreground">{controlPlaneStatus.detail}</div>
                </div>
                <div className="flex flex-wrap gap-2">
                  {controlPlaneStatus.action === "health-check" ? (
                    <Button variant="secondary" size="sm" onClick={handleRuntimeHealthCheck} disabled={busyAction === "runtime-health-check"}>
                      {busyAction === "runtime-health-check" ? "Checking..." : "Run health check"}
                    </Button>
                  ) : null}
                  {controlPlaneStatus.action === "notifications" ? (
                    <Button variant="secondary" size="sm" onClick={() => setAuditEventFilter("notifications")}>
                      Review notifications
                    </Button>
                  ) : null}
                  {controlPlaneStatus.action === "refresh" ? (
                    <Button variant="secondary" size="sm" onClick={() => void handleRefreshSources()} disabled={busyAction === "refresh-sources"}>
                      Refresh now
                    </Button>
                  ) : null}
                </div>
              </div>
              <div className="mt-4 grid gap-3 sm:grid-cols-3">
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Protection state</div>
                  <div className="mt-1 font-medium">{dashboard.protection_status}</div>
                </div>
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Runtime notes</div>
                  <div className="mt-1 font-medium">{dashboard.runtime_health.notes.length}</div>
                </div>
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Delivery failures</div>
                  <div className="mt-1 font-medium">{dashboard.notification_health.failed_count}</div>
                </div>
              </div>
            </div>
          </div>
        </Card>

        <Card id="quick-health">
          <CardTitle>Quick health</CardTitle>
          <CardDescription>Backend-facing summary for dashboard, recovery, and operator workflows.</CardDescription>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <Metric label="Sources" value={String(dashboard.source_count)} icon={<ListFilter className="size-4" />} />
            <Metric label="Enabled" value={String(dashboard.enabled_source_count)} icon={<ShieldCheck className="size-4" />} />
            <Metric label="Services" value={String(dashboard.service_toggle_count)} icon={<Sparkles className="size-4" />} />
            <Metric label="Devices" value={String(dashboard.device_count)} icon={<Activity className="size-4" />} />
          </div>
          <div className="mt-5 flex flex-wrap gap-2">
            {[
              ["dashboard-summary", "Overview"],
              ["guided-recovery", "Recovery"],
              ["settings", "Alerts & settings"],
              ["blocklists", "Blocklists"],
              ["devices", "Devices"],
            ].map(([target, label]) => (
              <Button key={target} variant="ghost" size="sm" onClick={() => scrollToSection(target)}>
                {label}
              </Button>
            ))}
          </div>
        </Card>
      </section>

      <section className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <Card id="guided-recovery">
          <CardTitle>Guided recovery</CardTitle>
          <CardDescription>Plain-language next steps for the issues most likely to block protection or visibility.</CardDescription>
          <div className="mt-5 grid gap-3">
            {recoveryActions.map((item) => (
              <div key={item.title} className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                <div className="font-medium">{item.title}</div>
                <div className="mt-1 text-sm text-muted-foreground">{item.detail}</div>
                <div className="mt-3 grid gap-2 text-sm text-muted-foreground">
                  {item.steps.map((step, index) => (
                    <div key={step} className="flex gap-3 rounded-2xl bg-muted/40 px-3 py-2">
                      <span className="font-medium text-foreground">{index + 1}</span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
                <div className="mt-3">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
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
                    }}
                    disabled={item.disabled}
                  >
                    {item.actionLabel}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card id="setup-checklist">
          <CardTitle>Setup checklist</CardTitle>
          <CardDescription>Track the core steps that turn the current control plane into a ready-to-run deployment.</CardDescription>
          <div className="mt-5 rounded-[24px] border border-border/70 bg-muted/40 p-4">
            <div className="text-sm text-muted-foreground">Completed</div>
            <div className="mt-1 font-display text-3xl font-semibold">{onboardingChecklist.completed}/{onboardingChecklist.total}</div>
          </div>
          <div className="mt-4 grid gap-3">
            {onboardingChecklist.items.map((item) => (
              <div key={item.title} className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div className="font-medium">{item.title}</div>
                  <Badge>{item.done ? "Done" : "Next"}</Badge>
                </div>
                <div className="mt-1 text-sm text-muted-foreground">{item.detail}</div>
                {!item.done ? (
                  <div className="mt-3">
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        if (item.actionKey === "blocklists") {
                          scrollToSection("blocklists");
                          return;
                        }
                        if (item.actionKey === "devices") {
                          scrollToSection("devices");
                          return;
                        }
                        scrollToSection("settings");
                      }}
                    >
                      {item.actionLabel}
                    </Button>
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </Card>
      </section>

      {error ? <Card className="border-accent/30 bg-accent/10 text-accent-foreground">{error}</Card> : null}

      <section className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
        <Card id="dashboard-summary">
          <CardTitle>Dashboard</CardTitle>
          <CardDescription>Current backend summary surfaced in a UI-first shape.</CardDescription>
          <div className="mt-6 space-y-4">
            <Row label="Protection" value={dashboard.protection_status} />
            <Row label="Active ruleset" value={dashboard.active_ruleset?.hash.slice(0, 12) ?? "None"} />
            <Row label="Fallback served" value={String(dashboard.runtime_health.snapshot.fallback_served_total)} />
            <Row label="Cache hits" value={String(dashboard.runtime_health.snapshot.cache_hits_total)} />
            <Row label="Probe domains" value={settings.runtime_guard.probe_domains.join(", ") || "None"} />
          </div>
          <Separator className="my-6" />
          <div className="space-y-3">
            <div className="font-medium">Alert posture</div>
            <div className="grid gap-3 sm:grid-cols-3">
              <Metric label="Critical" value={String(dashboard.security_summary.critical_count)} icon={<ShieldCheck className="size-4" />} />
              <Metric label="High" value={String(dashboard.security_summary.high_count)} icon={<Activity className="size-4" />} />
              <Metric label="Medium" value={String(dashboard.security_summary.medium_count)} icon={<Sparkles className="size-4" />} />
            </div>
            <div className="grid gap-3">
              {dashboard.security_summary.top_devices.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                  No devices are currently trending for risky activity.
                </div>
              ) : (
                dashboard.security_summary.top_devices.map((device) => (
                  <div key={device.label} className="rounded-2xl border border-border/70 bg-muted/60 p-3 text-sm">
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium">{device.label}</div>
                      <Badge>{device.highest_severity}</Badge>
                    </div>
                    <div className="mt-1 text-muted-foreground">{device.event_count} recent risky requests in the current alert window.</div>
                  </div>
                ))
              )}
            </div>
          </div>
          <Separator className="my-6" />
          <div className="space-y-3">
            <div className="font-medium">Recent risky events</div>
            <div className="grid gap-3">
              {dashboard.recent_security_events.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                  No risky DNS events recorded yet.
                </div>
              ) : (
                dashboard.recent_security_events.map((event) => (
                  <div key={event.id} className="rounded-2xl border border-border/70 bg-muted/60 p-3 text-sm">
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium">{event.domain}</div>
                      <Badge>{event.severity}</Badge>
                    </div>
                    <div className="mt-1 text-muted-foreground">
                      {(event.device_name ?? "Unassigned device")} on {event.client_ip} - classifier {event.classifier_score.toFixed(2)}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </Card>

        <Card id="settings">
          <CardTitle>Settings</CardTitle>
          <CardDescription>Classifier and blocklist controls map directly to the backend endpoints.</CardDescription>
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
                  <Button
                    key={mode}
                    variant={settings.classifier.mode === mode ? "primary" : "secondary"}
                    size="sm"
                    onClick={() => void handleClassifierUpdate(mode)}
                    disabled={busyAction === `classifier-mode-${mode}`}
                  >
                    {mode}
                  </Button>
                ))}
              </div>
              <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                <Input value={classifierThreshold} onChange={(event) => setClassifierThreshold(event.target.value)} placeholder="0.92" />
                <Button variant="secondary" onClick={() => void handleClassifierThresholdSave()} disabled={busyAction === "classifier-threshold"}>
                  Save threshold
                </Button>
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
                  <Button variant="secondary" onClick={() => void handleNotificationSave()} disabled={busyAction === "notifications-save"}>
                    Save alerts
                  </Button>
                  <Button variant="ghost" onClick={() => void handleNotificationTest()} disabled={busyAction === "notifications-test" || !notificationWebhookUrl}>
                    Send test
                  </Button>
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="grid gap-2 text-sm text-muted-foreground">
                  <span>Notification analytics window</span>
                  <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm text-foreground" value={notificationAnalyticsWindow} onChange={(event) => setNotificationAnalyticsWindow(Number.parseInt(event.target.value, 10) as 10 | 30 | 50 | 100)}>
                    <option value="10">Last 10 events</option>
                    <option value="30">Last 30 events</option>
                    <option value="50">Last 50 events</option>
                    <option value="100">Last 100 events</option>
                  </select>
                </label>
                <label className="grid gap-2 text-sm text-muted-foreground">
                  <span>Delivery history window</span>
                  <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm text-foreground" value={notificationHistoryWindow} onChange={(event) => setNotificationHistoryWindow(Number.parseInt(event.target.value, 10) as 10 | 30 | 50 | 100)}>
                    <option value="10">Last 10 events</option>
                    <option value="30">Last 30 events</option>
                    <option value="50">Last 50 events</option>
                    <option value="100">Last 100 events</option>
                  </select>
                </label>
              </div>
              <div className="grid gap-3 sm:grid-cols-[1fr_170px]">
                <Input value={notificationTestDomain} onChange={(event) => setNotificationTestDomain(event.target.value)} placeholder="notification-test.cogwheel.local" />
                <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={notificationTestSeverity} onChange={(event) => setNotificationTestSeverity(event.target.value as "medium" | "high" | "critical") }>
                  <option value="medium">Medium test</option>
                  <option value="high">High test</option>
                  <option value="critical">Critical test</option>
                </select>
              </div>
              <div className="grid gap-3 sm:grid-cols-[1fr_180px_auto_auto]">
                <Input value={notificationPresetName} onChange={(event) => setNotificationPresetName(event.target.value)} placeholder="weekday-health-check" />
                <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={selectedNotificationPreset} onChange={(event) => setSelectedNotificationPreset(event.target.value)}>
                  <option value="">Load saved preset</option>
                  {settings.notification_test_presets.map((preset) => (
                    <option key={preset.name} value={preset.name}>{preset.name}</option>
                  ))}
                </select>
                <Button variant="ghost" onClick={() => void handleNotificationPresetSave()} disabled={busyAction === "notifications-preset-save"}>
                  Save preset
                </Button>
                <Button variant="ghost" onClick={() => void handleNotificationPresetDelete()} disabled={busyAction === "notifications-preset-delete" || !selectedNotificationPreset}>
                  Delete preset
                </Button>
              </div>
              <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                <Input value={notificationTestDeviceName} onChange={(event) => setNotificationTestDeviceName(event.target.value)} placeholder="Control Plane Test" />
                <label className="flex items-center gap-3 rounded-2xl border border-border/70 bg-muted/40 px-4 py-3 text-sm">
                  <input type="checkbox" checked={notificationDryRun} onChange={(event) => setNotificationDryRun(event.target.checked)} />
                  Validate only
                </label>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Delivered</div>
                  <div className="mt-1 font-medium">{dashboard.notification_health.delivered_count}</div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    Last success: {dashboard.notification_health.last_delivery_at ? new Date(dashboard.notification_health.last_delivery_at).toLocaleString() : "none yet"}
                  </div>
                </div>
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Failed</div>
                  <div className="mt-1 font-medium">{dashboard.notification_health.failed_count}</div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    Last failure: {dashboard.notification_health.last_failure_at ? new Date(dashboard.notification_health.last_failure_at).toLocaleString() : "none yet"}
                  </div>
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Success rate</div>
                  <div className="mt-1 font-medium">{dashboard.notification_failure_analytics.success_rate_percent.toFixed(1)}%</div>
                  <div className="mt-1 text-xs text-muted-foreground">Based on the last {notificationAnalyticsWindow} delivery audit events.</div>
                </div>
                <div className="rounded-2xl border border-border/70 bg-muted/40 p-4 text-sm">
                  <div className="text-muted-foreground">Top failed domains</div>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {dashboard.notification_failure_analytics.top_failed_domains.length === 0 ? (
                      <span className="text-xs text-muted-foreground">No failed domains in the recent window.</span>
                    ) : (
                      dashboard.notification_failure_analytics.top_failed_domains.map((domain) => (
                        <Badge key={domain.domain}>{domain.domain} x{domain.failure_count}</Badge>
                      ))
                    )}
                  </div>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="text-sm text-muted-foreground">Recent delivery history from the last {notificationHistoryWindow} delivery audit events.</div>
                  <div className="flex flex-wrap gap-2">
                    {[
                      ["all", "All"],
                      ["failed", "Failed"],
                      ["security", "Security"],
                      ["control-plane", "Control plane"],
                    ].map(([value, label]) => (
                      <Button key={value} variant={notificationDeliveryFilter === value ? "primary" : "ghost"} size="sm" onClick={() => setNotificationDeliveryFilter(value as "all" | "failed" | "security" | "control-plane")}>
                        {label}
                      </Button>
                    ))}
                  </div>
                </div>
              </div>
              <div className="grid gap-3">
                {filteredNotificationDeliveries.length === 0 ? (
                  <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                    No recent notification deliveries match the selected history filter.
                  </div>
                ) : (
                  filteredNotificationDeliveries.map((delivery) => (
                    <div key={`${delivery.created_at}-${delivery.title}-${delivery.status}`} className="rounded-2xl border border-border/70 bg-muted/60 p-3 text-sm">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <div className="font-medium">{delivery.title}</div>
                          <div className="mt-1 text-xs text-muted-foreground">{delivery.target}</div>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Badge>{delivery.status}</Badge>
                          <Badge>{delivery.event_type}</Badge>
                        </div>
                      </div>
                      <div className="mt-1 text-muted-foreground">{delivery.summary}</div>
                    </div>
                  ))
                )}
              </div>
            </section>

            <Separator />

            <section className="space-y-3">
              <div className="font-medium">Add blocklist</div>
              <div className="grid gap-3">
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
                <Button onClick={() => void handleBlocklistCreate()} disabled={!blocklistName || !blocklistUrl || busyAction === "create-blocklist"}>
                  Add blocklist
                </Button>
              </div>
            </section>
          </div>
        </Card>
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <Card id="blocklists">
          <CardTitle>Blocklists</CardTitle>
          <CardDescription>Schedule, profile, strictness, and refresh status are backend-driven.</CardDescription>
          <div className="mt-5 grid gap-3">
            {settings.blocklists.map((source) => {
              const status = settings.blocklist_statuses.find((entry) => entry.id === source.id);
              return (
                <div key={source.id} className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-medium">{source.name}</div>
                      <div className="text-sm text-muted-foreground">{source.url}</div>
                    </div>
                    <Badge className={source.enabled ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"}>{source.enabled ? "Enabled" : "Disabled"}</Badge>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                    <Badge>{source.profile}</Badge>
                    <Badge>{source.verification_strictness}</Badge>
                    <Badge>{source.refresh_interval_minutes}m</Badge>
                    <Badge>{status?.due_for_refresh ? "Due" : "Fresh"}</Badge>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    <Button variant="ghost" size="sm" onClick={() => setEditingBlocklistId(editingBlocklistId === source.id ? null : source.id)}>
                      {editingBlocklistId === source.id ? "Close" : "Edit"}
                    </Button>
                    <Button variant="secondary" size="sm" onClick={() => void handleBlocklistToggle(source.id, !source.enabled)} disabled={busyAction === `blocklist-toggle-${source.id}`}>
                      {source.enabled ? "Disable" : "Enable"}
                    </Button>
                    {source.name !== "baseline" ? (
                      <Button variant="ghost" size="sm" onClick={() => void handleBlocklistDelete(source.id)} disabled={busyAction === `blocklist-delete-${source.id}`}>
                        Delete
                      </Button>
                    ) : null}
                  </div>
                  {editingBlocklistId === source.id ? (
                    <div className="mt-4 grid gap-3 rounded-[20px] border border-border/70 bg-muted/40 p-4">
                      <Input value={source.name} readOnly />
                      <Input value={source.url} readOnly />
                      <div className="grid gap-3 text-sm text-muted-foreground sm:grid-cols-3">
                        <label className="grid gap-1">
                          <span>Profile</span>
                          <select
                            className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm"
                            value={source.profile}
                            onChange={(event) => {
                              setSettings((current) => ({
                                ...current,
                                blocklists: current.blocklists.map((item) => item.id === source.id ? { ...item, profile: event.target.value } : item),
                              }));
                            }}
                          >
                            <option value="essential">Essential</option>
                            <option value="balanced">Balanced</option>
                            <option value="aggressive">Aggressive</option>
                            <option value="custom">Custom</option>
                          </select>
                        </label>
                        <label className="grid gap-1">
                          <span>Strictness</span>
                          <select
                            className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm"
                            value={source.verification_strictness}
                            onChange={(event) => {
                              setSettings((current) => ({
                                ...current,
                                blocklists: current.blocklists.map((item) => item.id === source.id ? { ...item, verification_strictness: event.target.value } : item),
                              }));
                            }}
                          >
                            <option value="strict">Strict</option>
                            <option value="balanced">Balanced</option>
                            <option value="relaxed">Relaxed</option>
                          </select>
                        </label>
                        <label className="grid gap-1">
                          <span>Refresh (minutes)</span>
                          <Input
                            value={String(source.refresh_interval_minutes)}
                            onChange={(event) => {
                              setSettings((current) => ({
                                ...current,
                                blocklists: current.blocklists.map((item) => item.id === source.id ? { ...item, refresh_interval_minutes: Number.parseInt(event.target.value, 10) || item.refresh_interval_minutes } : item),
                              }));
                            }}
                          />
                        </label>
                      </div>
                      <Button size="sm" onClick={() => void handleBlocklistEdit(source)} disabled={busyAction === `blocklist-save-${source.id}`}>
                        Save metadata
                      </Button>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </Card>

        <Card id="services">
          <CardTitle>Services</CardTitle>
          <CardDescription>Optional common-service toggles powered by the layered rules built in Rust.</CardDescription>
          <div className="mt-5 space-y-4">
            <Input value={serviceSearch} onChange={(event) => setServiceSearch(event.target.value)} placeholder="Search services or categories" />
            <div className="grid gap-3">
              {filteredServices.map((service) => (
                <div key={service.manifest.service_id} className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="font-medium">{service.manifest.display_name}</div>
                      <div className="text-sm text-muted-foreground">{service.manifest.risk_notes}</div>
                    </div>
                    <Badge>{service.mode}</Badge>
                  </div>
                  <div className="mt-3 flex gap-2">
                    {(["Inherit", "Allow", "Block"] as const).map((mode) => (
                      <Button
                        key={mode}
                        variant={service.mode === mode ? "primary" : "secondary"}
                        size="sm"
                        onClick={() => void handleServiceUpdate(service.manifest.service_id, mode)}
                        disabled={busyAction === `service-${service.manifest.service_id}`}
                      >
                        {mode}
                      </Button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </section>

      <section className="grid gap-6 lg:grid-cols-[1.05fr_0.95fr]">
        <Card id="devices">
          <CardTitle>Devices</CardTitle>
          <CardDescription>Name devices and choose whether they inherit the global policy or carry a custom profile override with validated service-rule previews.</CardDescription>
          <div className="mt-5 grid gap-3">
            <div className="grid gap-3 md:grid-cols-2">
              <Input value={deviceName} onChange={(event) => setDeviceName(event.target.value)} placeholder="MacBook Pro" />
              <Input value={deviceIpAddress} onChange={(event) => setDeviceIpAddress(event.target.value)} placeholder="192.168.1.42" />
            </div>
            <div className="grid gap-3 md:grid-cols-4">
              <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={devicePolicyMode} onChange={(event) => setDevicePolicyMode(event.target.value as "global" | "custom")}>
                <option value="global">Global</option>
                <option value="custom">Custom</option>
              </select>
              <Input
                value={deviceProfileOverride}
                onChange={(event) => setDeviceProfileOverride(event.target.value)}
                placeholder="balanced"
                disabled={devicePolicyMode !== "custom"}
              />
              <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={deviceProtectionOverride} onChange={(event) => setDeviceProtectionOverride(event.target.value as "inherit" | "bypass")} disabled={devicePolicyMode !== "custom"}>
                <option value="inherit">Inherit blocking</option>
                <option value="bypass">Bypass blocking</option>
              </select>
              <Input
                value={deviceAllowedDomains}
                onChange={(event) => setDeviceAllowedDomains(event.target.value)}
                placeholder="example.com, cdn.example.com"
                disabled={devicePolicyMode !== "custom"}
              />
              <div className="flex gap-2">
                <Button onClick={() => void handleDeviceSubmit()} disabled={!deviceName || !deviceIpAddress || busyAction === "device-submit"}>
                  {deviceId ? "Save device" : "Add device"}
                </Button>
                {deviceId ? <Button variant="ghost" onClick={resetDeviceForm}>Cancel</Button> : null}
              </div>
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
            {devicePolicyMode !== "custom" ? (
              <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                Switch to custom policy mode to preview and add per-device service overrides.
              </div>
            ) : deviceServiceOverrideId && deviceServiceOverridePreview ? (
              <div className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="font-medium">{deviceServiceOverridePreview.displayName}</div>
                    <div className="mt-1 text-sm text-muted-foreground">{deviceServiceOverridePreview.riskNotes}</div>
                  </div>
                  <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                    <Badge>{deviceServiceOverrideMode}</Badge>
                    <Badge>{deviceServiceOverridePreview.category}</Badge>
                    <Badge>
                      {deviceServiceOverridePreview.domains.length} expanded domain{deviceServiceOverridePreview.domains.length === 1 ? "" : "s"}
                    </Badge>
                    {deviceServiceOverridePreview.exceptions.length > 0 ? (
                      <Badge>{deviceServiceOverridePreview.exceptions.length} exception{deviceServiceOverridePreview.exceptions.length === 1 ? "" : "s"}</Badge>
                    ) : null}
                    {deviceServiceOverrideIsNoop ? <Badge>already queued</Badge> : null}
                    {pendingDeviceServiceOverride && !deviceServiceOverrideIsNoop ? <Badge>replaces pending {pendingDeviceServiceOverride.mode}</Badge> : null}
                  </div>
                </div>
                <div className="mt-3 text-sm text-muted-foreground">
                  {deviceServiceOverrideMode === "allow"
                    ? "Allow mode expands allow, block, and exception domains so the service keeps working for this device."
                    : "Block mode expands blocked domains and preserves manifest exceptions so essential endpoints can still resolve."}
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {deviceServiceOverridePreview.sampleDomains.map((domain) => (
                    <Badge key={domain}>{domain}</Badge>
                  ))}
                  {deviceServiceOverridePreview.domains.length > deviceServiceOverridePreview.sampleDomains.length ? (
                    <Badge>
                      +{deviceServiceOverridePreview.domains.length - deviceServiceOverridePreview.sampleDomains.length} more
                    </Badge>
                  ) : null}
                </div>
              </div>
            ) : deviceServiceOverrideId ? (
              <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                The selected service does not currently expose any domains for this override mode.
              </div>
            ) : (
              <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                Select a service to preview the domains and exceptions that will be attached to this device rule.
              </div>
            )}
            {deviceServiceOverrides.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {deviceServiceOverrides.map((override) => (
                  <button key={`${override.service_id}-${override.mode}`} type="button" title={describeDeviceServiceOverride(override.service_id)} className="rounded-full border border-border/70 bg-muted/40 px-3 py-1 text-xs text-muted-foreground" onClick={() => removeDeviceServiceOverride(override.service_id)}>
                    {formatDeviceServiceOverride(override.service_id, override.mode)} x
                  </button>
                ))}
              </div>
            ) : null}
            <Separator className="my-2" />
            <div className="grid gap-3">
              {settings.devices.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                  No devices have been named yet.
                </div>
              ) : (
                settings.devices.map((device) => (
                  <div key={device.id} className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-medium">{device.name}</div>
                        <div className="text-sm text-muted-foreground">{device.ip_address}</div>
                      </div>
                      <Badge>{device.policy_mode}</Badge>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                      <Badge>{device.blocklist_profile_override ?? "inherits global profile"}</Badge>
                      <Badge>{device.protection_override === "bypass" ? "blocking bypassed" : "inherits blocking"}</Badge>
                      <Badge>
                        {device.allowed_domains.length > 0
                          ? `${device.allowed_domains.length} allowed domain${device.allowed_domains.length === 1 ? "" : "s"}`
                          : "no device allowlist"}
                      </Badge>
                      <Badge>
                        {device.service_overrides.length > 0
                          ? `${device.service_overrides.length} service override${device.service_overrides.length === 1 ? "" : "s"}`
                          : "no service overrides"}
                      </Badge>
                    </div>
                    {device.service_overrides.length > 0 ? (
                      <div className="mt-3 grid gap-2 text-xs text-muted-foreground">
                        {device.service_overrides.map((override) => (
                          <div key={`${device.id}-${override.service_id}-${override.mode}`} className="rounded-2xl border border-border/70 bg-muted/40 px-3 py-2">
                            <div className="font-medium text-foreground">{formatDeviceServiceOverride(override.service_id, override.mode)}</div>
                            <div className="mt-1">{describeDeviceServiceOverride(override.service_id)}</div>
                          </div>
                        ))}
                      </div>
                    ) : null}
                    <div className="mt-4">
                      <Button variant="ghost" size="sm" onClick={() => startDeviceEdit(device)}>
                        Edit device
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </Card>

        <Card>
          <CardTitle>Operator feed</CardTitle>
          <CardDescription>Audit and event visibility for the current backend scaffolding.</CardDescription>
          <div className="mt-5 space-y-5">
            <section className="space-y-3">
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <div className="font-medium">Recent audit events</div>
                  <div className="text-sm text-muted-foreground">Filter the operator feed to focus on the control-plane changes you are investigating.</div>
                </div>
                <div className="flex flex-wrap gap-2">
                  {[
                    ["all", "All events"],
                    ["runtime", "Runtime"],
                    ["notifications", "Notifications"],
                    ["devices", "Devices"],
                    ["rulesets", "Rulesets"],
                  ].map(([value, label]) => (
                    <Button key={value} variant={auditEventFilter === value ? "primary" : "ghost"} size="sm" onClick={() => setAuditEventFilter(value as "all" | "runtime" | "notifications" | "devices" | "rulesets")}>
                      {label}
                    </Button>
                  ))}
                </div>
              </div>
              <div className="grid gap-3">
                {filteredAuditEvents.length === 0 ? (
                  <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                    No audit events match the selected filter.
                  </div>
                ) : (
                  filteredAuditEvents.map((event) => {
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
                        <div className="mt-2 text-xs text-muted-foreground">{new Date(event.created_at).toLocaleString()}</div>
                      </div>
                    );
                  })
                )}
              </div>
            </section>

            <Separator />

            <section className="space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div className="font-medium">Runtime notes</div>
                <Button variant="ghost" size="sm" onClick={handleRuntimeHealthCheck} disabled={busyAction === "runtime-health-check"}>
                  {busyAction === "runtime-health-check" ? "Checking..." : "Run health check"}
                </Button>
              </div>
              <div className="grid gap-3">
                {dashboard.runtime_health.notes.length === 0 ? (
                  <div className="rounded-2xl border border-dashed border-border/80 bg-muted/30 p-4 text-sm text-muted-foreground">
                    No runtime regressions detected.
                  </div>
                ) : (
                  dashboard.runtime_health.notes.map((note) => (
                    <div key={note} className="rounded-2xl border border-border/70 bg-muted/60 p-3 text-sm">
                      {note}
                    </div>
                  ))
                )}
              </div>
            </section>
          </div>
        </Card>
      </section>

      {state === "loading" ? <div className="text-sm text-muted-foreground">Loading control plane data...</div> : null}
      {state === "ready" ? (
        <div className="text-sm text-muted-foreground">
          {enabledBlocklists.length} enabled blocklists, {settings.devices.length} named devices, classifier threshold {settings.classifier.threshold.toFixed(2)}.
        </div>
      ) : null}
    </main>
  );
}

function Metric({ label, value, icon }: { label: string; value: string; icon: ReactNode }) {
  return (
    <div className="rounded-[24px] border border-border/70 bg-muted/60 p-4">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">{icon}{label}</div>
      <div className="mt-2 font-display text-2xl font-semibold">{value}</div>
    </div>
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
