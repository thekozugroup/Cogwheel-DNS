import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Activity, ListFilter, RefreshCw, ShieldCheck, Sparkles, Undo2 } from "lucide-react";
import { api, type DashboardSummary, type SettingsSummary } from "@/lib/api";
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
  const [serviceSearch, setServiceSearch] = useState("");

  const [deviceId, setDeviceId] = useState<string | null>(null);
  const [deviceName, setDeviceName] = useState("");
  const [deviceIpAddress, setDeviceIpAddress] = useState("");
  const [devicePolicyMode, setDevicePolicyMode] = useState<"global" | "custom">("global");
  const [deviceProfileOverride, setDeviceProfileOverride] = useState("");
  const [deviceProtectionOverride, setDeviceProtectionOverride] = useState<"inherit" | "bypass">("inherit");

  async function load() {
    setState("loading");
    setError(null);
    try {
      const [dashboardData, settingsData] = await Promise.all([api.dashboard(), api.settings()]);
      setDashboard(dashboardData);
      setSettings(settingsData);
      setState("ready");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unknown error");
      setState("error");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    setClassifierThreshold(settings.classifier.threshold.toFixed(2));
  }, [settings.classifier.threshold]);

  useEffect(() => {
    setNotificationEnabled(settings.notifications.enabled);
    setNotificationWebhookUrl(settings.notifications.webhook_url ?? "");
    setNotificationMinSeverity(settings.notifications.min_severity);
  }, [settings.notifications]);

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
          <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
            <div className="space-y-4">
              <Badge className="bg-primary/10 text-primary">Cogwheel Control Plane</Badge>
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
        </Card>

        <Card>
          <CardTitle>Quick health</CardTitle>
          <CardDescription>Backend-facing summary for dashboard, recovery, and operator workflows.</CardDescription>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <Metric label="Sources" value={String(dashboard.source_count)} icon={<ListFilter className="size-4" />} />
            <Metric label="Enabled" value={String(dashboard.enabled_source_count)} icon={<ShieldCheck className="size-4" />} />
            <Metric label="Services" value={String(dashboard.service_toggle_count)} icon={<Sparkles className="size-4" />} />
            <Metric label="Devices" value={String(dashboard.device_count)} icon={<Activity className="size-4" />} />
          </div>
        </Card>
      </section>

      {error ? <Card className="border-accent/30 bg-accent/10 text-accent-foreground">{error}</Card> : null}

      <section className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
        <Card>
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

        <Card>
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
                <Button variant="secondary" onClick={() => void handleNotificationSave()} disabled={busyAction === "notifications-save"}>
                  Save alerts
                </Button>
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
        <Card>
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

        <Card>
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
        <Card>
          <CardTitle>Devices</CardTitle>
          <CardDescription>Name devices and choose whether they inherit the global policy or carry a custom profile override.</CardDescription>
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
              <div className="flex gap-2">
                <Button onClick={() => void handleDeviceSubmit()} disabled={!deviceName || !deviceIpAddress || busyAction === "device-submit"}>
                  {deviceId ? "Save device" : "Add device"}
                </Button>
                {deviceId ? <Button variant="ghost" onClick={resetDeviceForm}>Cancel</Button> : null}
              </div>
            </div>
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
          </div>
        </Card>

        <Card>
          <CardTitle>Operator feed</CardTitle>
          <CardDescription>Audit and event visibility for the current backend scaffolding.</CardDescription>
          <div className="mt-5 space-y-5">
            <section className="space-y-3">
              <div className="font-medium">Recent audit events</div>
              <div className="grid gap-3">
                {dashboard.latest_audit_events.map((event) => (
                  <div key={event.id} className="rounded-2xl border border-border/70 bg-muted/60 p-3 text-sm">
                    <div className="font-medium">{event.event_type}</div>
                    <div className="text-muted-foreground">{new Date(event.created_at).toLocaleString()}</div>
                  </div>
                ))}
              </div>
            </section>

            <Separator />

            <section className="space-y-3">
              <div className="font-medium">Runtime notes</div>
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
