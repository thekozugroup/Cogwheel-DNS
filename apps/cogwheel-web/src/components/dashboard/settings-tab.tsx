import { useEffect, useMemo, useState } from "react";
import { useCogwheel } from "@/contexts/cogwheel-context";
import {
  api,
  type AuditEvent,
  type SettingsSummary,
  type ServiceToggle,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function SettingsTab() {
  const {
    dashboard,
    settings,
    syncStatus,
    tailscaleStatus,
    tailscaleDnsCheck,
    threatIntelSettings,
    setThreatIntelSettings,
    federatedLearningSettings,
    setFederatedLearningSettings,
    latencyBudget,
    busyAction,
    setBusyAction,
    pushToast,
    load,
    handleRefreshSources,
    handleRollbackRuleset,
    handleRuntimeHealthCheck,
  } = useCogwheel();

  const [classifierThreshold, setClassifierThreshold] = useState("0.92");
  const [notificationEnabled, setNotificationEnabled] = useState(false);
  const [notificationWebhookUrl, setNotificationWebhookUrl] = useState("");
  const [notificationMinSeverity, setNotificationMinSeverity] = useState<
    "medium" | "high" | "critical"
  >("high");
  const [notificationTestDomain] = useState(
    "notification-test.cogwheel.local",
  );
  const [notificationTestSeverity, setNotificationTestSeverity] = useState<
    "medium" | "high" | "critical"
  >("high");
  const [notificationTestDeviceName] = useState("Control Plane Test");
  const [notificationDryRun] = useState(false);
  const [serviceSearch] = useState("");
  const [auditEventFilter, setAuditEventFilter] = useState<
    "all" | "runtime" | "notifications" | "devices" | "rulesets"
  >("all");
  const [showServicesView, setShowServicesView] = useState(false);
  const [syncProfileDraft, setSyncProfileDraft] = useState("full");
  const [syncTransportModeDraft, setSyncTransportModeDraft] =
    useState("opportunistic");
  const [syncTransportTokenDraft, setSyncTransportTokenDraft] = useState("");

  const [blocklistName, setBlocklistName] = useState("");
  const [blocklistUrl, setBlocklistUrl] = useState("");
  const [blocklistProfile, setBlocklistProfile] = useState("custom");
  const [blocklistStrictness, setBlocklistStrictness] = useState<
    "strict" | "balanced" | "relaxed"
  >("balanced");
  const [blocklistInterval, setBlocklistInterval] = useState("60");

  // Sync local state from context
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

  const filteredServices = useMemo(
    () =>
      settings.services.filter((service) => {
        const query = serviceSearch.trim().toLowerCase();
        if (!query) return true;
        return `${service.manifest.display_name} ${service.manifest.category} ${service.manifest.risk_notes}`
          .toLowerCase()
          .includes(query);
      }),
    [serviceSearch, settings.services],
  );

  const filteredAuditEvents = useMemo(
    () =>
      dashboard.latest_audit_events.filter((event) => {
        if (auditEventFilter === "all") return true;
        if (auditEventFilter === "notifications")
          return (
            event.event_type.startsWith("notification.") ||
            event.event_type.startsWith("security.alert")
          );
        if (auditEventFilter === "runtime")
          return event.event_type.startsWith("runtime.");
        if (auditEventFilter === "devices")
          return event.event_type.startsWith("device.");
        if (auditEventFilter === "rulesets")
          return event.event_type.startsWith("ruleset.");
        return true;
      }),
    [auditEventFilter, dashboard.latest_audit_events],
  );

  const recoveryActions = useMemo(() => {
    const actions: Array<{
      title: string;
      detail: string;
      steps: string[];
      actionLabel: string;
      actionKey:
        | "runtime-health-check"
        | "notifications"
        | "refresh-sources"
        | "rollback-ruleset";
      disabled?: boolean;
    }> = [];

    if (dashboard.runtime_health.degraded) {
      actions.push({
        title: "Check runtime health again",
        detail:
          dashboard.runtime_health.notes[0] ??
          "Probe the runtime again to confirm whether the issue is still active.",
        steps: [
          "Run an active health check to refresh probe results.",
          "If probes still fail, compare the runtime notes with the most recent ruleset change.",
          "Roll back if the degraded state appeared after a fresh source update.",
        ],
        actionLabel:
          busyAction === "runtime-health-check"
            ? "Checking..."
            : "Run health check",
        actionKey: "runtime-health-check",
        disabled: busyAction === "runtime-health-check",
      });
    }

    if (dashboard.notification_health.failed_count > 0) {
      actions.push({
        title: "Review notification delivery",
        detail:
          "Open recent notification events and look for repeated delivery failures before the next alert is missed.",
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
        detail:
          "The resolver does not have an active ruleset yet, so request a fresh source refresh from the control plane.",
        steps: [
          "Refresh sources to build a fresh candidate ruleset.",
          "Confirm the active ruleset hash appears in the dashboard summary.",
          "Re-run a runtime health check once the new ruleset is active.",
        ],
        actionLabel:
          busyAction === "refresh-sources"
            ? "Refreshing..."
            : "Refresh sources",
        actionKey: "refresh-sources",
        disabled: busyAction === "refresh-sources",
      });
    }

    if (dashboard.active_ruleset && dashboard.runtime_health.degraded) {
      actions.push({
        title: "Roll back to the previous ruleset",
        detail:
          "If the degraded state appeared after a recent change, roll back to the last known-good policy set.",
        steps: [
          "Roll back to the previous verified ruleset.",
          "Watch the notification history for rollback delivery events.",
          "Run the health check again to confirm the runtime recovered.",
        ],
        actionLabel:
          busyAction === "rollback-ruleset" ? "Rolling back..." : "Roll back",
        actionKey: "rollback-ruleset",
        disabled: busyAction === "rollback-ruleset",
      });
    }

    if (actions.length === 0) {
      actions.push({
        title: "System looks steady",
        detail:
          "No immediate recovery flow is needed right now. Use refresh or device editing when you are ready to make the next change.",
        steps: [
          "Keep sources fresh before the next policy edit.",
          "Use the checklist to finish any incomplete setup items.",
          "Review recent audit events after each meaningful control-plane change.",
        ],
        actionLabel:
          busyAction === "refresh-sources"
            ? "Refreshing..."
            : "Refresh sources",
        actionKey: "refresh-sources",
        disabled: busyAction === "refresh-sources",
      });
    }

    return actions.slice(0, 3);
  }, [
    busyAction,
    dashboard.active_ruleset,
    dashboard.notification_health.failed_count,
    dashboard.runtime_health.degraded,
    dashboard.runtime_health.notes,
  ]);

  // --- Handlers ---

  async function handleSyncProfileSave() {
    setBusyAction("sync-profile-save");
    try {
      await api.updateSyncProfile(syncProfileDraft);
      pushToast(
        "Sync profile updated",
        `Node sync profile is now ${syncProfileDraft}.`,
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast(
        "Sync profile update failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleSyncTransportSave() {
    setBusyAction("sync-transport-save");
    try {
      await api.updateSyncTransport(
        syncTransportModeDraft,
        syncTransportTokenDraft,
      );
      pushToast(
        "Sync transport updated",
        `Transport mode is now ${syncTransportModeDraft}.`,
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast(
        "Sync transport update failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleClassifierUpdate(
    mode: SettingsSummary["classifier"]["mode"],
  ) {
    setBusyAction(`classifier-mode-${mode}`);
    try {
      await api.updateClassifier(
        mode,
        Number.parseFloat(classifierThreshold) ||
          settings.classifier.threshold,
      );
      pushToast("Classifier updated", `Mode switched to ${mode}.`, "success");
      await load();
    } catch (mutationError) {
      pushToast(
        "Classifier update failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleClassifierThresholdSave() {
    setBusyAction("classifier-threshold");
    try {
      const threshold =
        Number.parseFloat(classifierThreshold) ||
        settings.classifier.threshold;
      await api.updateClassifier(settings.classifier.mode, threshold);
      pushToast(
        "Threshold saved",
        `Classifier threshold is now ${threshold.toFixed(2)}.`,
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast(
        "Threshold update failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
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
      pushToast(
        "Notifications updated",
        notificationEnabled
          ? "Webhook delivery is configured."
          : "Webhook delivery is disabled.",
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast(
        "Notification update failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
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
      pushToast(
        "Test notification failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
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
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
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
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleThreatIntelProviderSave(providerId: string) {
    const provider = threatIntelSettings.providers.find(
      (item) => item.id === providerId,
    );
    if (!provider) {
      pushToast(
        "Provider missing",
        "The selected provider could not be found.",
        "error",
      );
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
      pushToast(
        "Threat intel updated",
        `${provider.display_name} settings saved.`,
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast(
        "Threat intel update failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
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
      pushToast(
        "Federated learning updated",
        next.enabled
          ? "Coordinator settings are active with model-updates-only privacy."
          : "Federated learning is disabled.",
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast(
        "Federated learning update failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleServiceUpdate(
    serviceId: string,
    mode: ServiceToggle["mode"],
  ) {
    setBusyAction(`service-${serviceId}`);
    try {
      await api.updateService(serviceId, mode);
      pushToast("Service updated", `Service mode set to ${mode}.`, "success");
      await load();
    } catch (mutationError) {
      pushToast(
        "Service update failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
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
        refresh_interval_minutes:
          Number.parseInt(blocklistInterval, 10) || 60,
        profile: blocklistProfile,
        verification_strictness: blocklistStrictness,
      });
      setBlocklistName("");
      setBlocklistUrl("");
      setBlocklistProfile("custom");
      setBlocklistStrictness("balanced");
      setBlocklistInterval("60");
      pushToast(
        "Blocklist added",
        "The source was saved and refreshed.",
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast(
        "Blocklist add failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  async function handleBlocklistToggle(id: string, enabled: boolean) {
    setBusyAction(`blocklist-toggle-${id}`);
    try {
      await api.setBlocklistEnabled(id, enabled);
      pushToast(
        enabled ? "Blocklist enabled" : "Blocklist disabled",
        "Ruleset refresh requested.",
        "success",
      );
      await load();
    } catch (mutationError) {
      pushToast(
        "Blocklist update failed",
        mutationError instanceof Error
          ? mutationError.message
          : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <div className="p-4 md:p-6 space-y-6">
      <Tabs defaultValue="everyday">
        <TabsList>
          <TabsTrigger value="everyday">Everyday</TabsTrigger>
          <TabsTrigger value="advanced">Advanced</TabsTrigger>
        </TabsList>

        {/* ---------------------------------------------------------------- */}
        {/* Everyday tab                                                      */}
        {/* ---------------------------------------------------------------- */}
        <TabsContent value="everyday" className="space-y-6">
          {/* Alert delivery card */}
          <Card>
            <CardHeader>
              <CardTitle>Alert delivery</CardTitle>
              <CardDescription>
                Send high-severity security alerts to an external webhook
              </CardDescription>
              <CardAction>
                <Badge variant="secondary">
                  {notificationEnabled
                    ? `Webhook ${notificationMinSeverity}+`
                    : "Disabled"}
                </Badge>
              </CardAction>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-3">
                <Switch
                  id="notification-enabled"
                  checked={notificationEnabled}
                  onCheckedChange={setNotificationEnabled}
                />
                <Label htmlFor="notification-enabled">
                  Enable outbound alert notifications
                </Label>
              </div>
              <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_170px]">
                <div className="space-y-2">
                  <Label htmlFor="webhook-url">Webhook URL</Label>
                  <Input
                    id="webhook-url"
                    value={notificationWebhookUrl}
                    onChange={(event) =>
                      setNotificationWebhookUrl(event.target.value)
                    }
                    placeholder="https://hooks.example.com/cogwheel"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="min-severity">Min severity</Label>
                  <select
                    id="min-severity"
                    className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                    value={notificationMinSeverity}
                    onChange={(event) =>
                      setNotificationMinSeverity(
                        event.target.value as "medium" | "high" | "critical",
                      )
                    }
                  >
                    <option value="medium">Medium+</option>
                    <option value="high">High+</option>
                    <option value="critical">Critical only</option>
                  </select>
                </div>
              </div>
            </CardContent>
            <CardFooter className="justify-end gap-2">
              <Button
                variant="ghost"
                onClick={() => void handleNotificationTest()}
                disabled={
                  busyAction === "notifications-test" ||
                  !notificationWebhookUrl
                }
              >
                Send test
              </Button>
              <Button
                onClick={() => void handleNotificationSave()}
                disabled={busyAction === "notifications-save"}
              >
                Save alerts
              </Button>
            </CardFooter>
          </Card>

          {/* Sources card with Table for blocklists */}
          <Card>
            <CardHeader>
              <CardTitle>Sources</CardTitle>
              <CardDescription>
                Imported blocklists and their refresh schedules
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3 rounded-lg border border-border p-4">
                <div className="text-sm font-medium">Add blocklist</div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="bl-name">Name</Label>
                    <Input
                      id="bl-name"
                      value={blocklistName}
                      onChange={(event) =>
                        setBlocklistName(event.target.value)
                      }
                      placeholder="Human-readable name"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="bl-url">Source URL</Label>
                    <Input
                      id="bl-url"
                      value={blocklistUrl}
                      onChange={(event) =>
                        setBlocklistUrl(event.target.value)
                      }
                      placeholder="Source URL or data: URL"
                    />
                  </div>
                </div>
                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="space-y-2">
                    <Label htmlFor="bl-profile">Profile</Label>
                    <select
                      id="bl-profile"
                      className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                      value={blocklistProfile}
                      onChange={(event) =>
                        setBlocklistProfile(event.target.value)
                      }
                    >
                      <option value="custom">Custom</option>
                      <option value="essential">Essential</option>
                      <option value="balanced">Balanced</option>
                      <option value="aggressive">Aggressive</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="bl-strictness">Strictness</Label>
                    <select
                      id="bl-strictness"
                      className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                      value={blocklistStrictness}
                      onChange={(event) =>
                        setBlocklistStrictness(
                          event.target.value as
                            | "strict"
                            | "balanced"
                            | "relaxed",
                        )
                      }
                    >
                      <option value="strict">Strict</option>
                      <option value="balanced">Balanced</option>
                      <option value="relaxed">Relaxed</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="bl-interval">Refresh (min)</Label>
                    <Input
                      id="bl-interval"
                      value={blocklistInterval}
                      onChange={(event) =>
                        setBlocklistInterval(event.target.value)
                      }
                      placeholder="60"
                    />
                  </div>
                </div>
                <div className="flex justify-end">
                  <Button
                    onClick={() => void handleBlocklistCreate()}
                    disabled={
                      !blocklistName ||
                      !blocklistUrl ||
                      busyAction === "create-blocklist"
                    }
                  >
                    Add blocklist
                  </Button>
                </div>
              </div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Profile</TableHead>
                    <TableHead>Refresh</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {settings.blocklists.length === 0 ? (
                    <TableRow>
                      <TableCell
                        colSpan={5}
                        className="h-24 text-center text-muted-foreground"
                      >
                        No blocklists configured yet.
                      </TableCell>
                    </TableRow>
                  ) : (
                    settings.blocklists.map((source) => (
                      <TableRow key={source.id}>
                        <TableCell className="font-medium">
                          {source.name}
                        </TableCell>
                        <TableCell>{source.profile}</TableCell>
                        <TableCell>
                          {source.refresh_interval_minutes}m
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              source.enabled ? "default" : "secondary"
                            }
                          >
                            {source.enabled ? "Enabled" : "Disabled"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              void handleBlocklistToggle(
                                source.id,
                                !source.enabled,
                              )
                            }
                            disabled={
                              busyAction ===
                              `blocklist-toggle-${source.id}`
                            }
                          >
                            {source.enabled ? "Disable" : "Enable"}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Services card with Table */}
          <Card>
            <CardHeader>
              <CardTitle>Services</CardTitle>
              <CardDescription>
                Curated allow/block toggles for common apps
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Service</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead>Mode</TableHead>
                    <TableHead></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredServices.length === 0 ? (
                    <TableRow>
                      <TableCell
                        colSpan={4}
                        className="h-24 text-center text-muted-foreground"
                      >
                        No services configured.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredServices
                      .slice(
                        0,
                        showServicesView ? filteredServices.length : 5,
                      )
                      .map((service) => (
                        <TableRow key={service.manifest.service_id}>
                          <TableCell className="font-medium">
                            {service.manifest.display_name}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {service.manifest.risk_notes}
                          </TableCell>
                          <TableCell>
                            <Badge variant="secondary">{service.mode}</Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex gap-1">
                              {(["Inherit", "Allow", "Block"] as const).map(
                                (mode) => (
                                  <Button
                                    key={mode}
                                    variant={
                                      service.mode === mode
                                        ? "default"
                                        : "ghost"
                                    }
                                    size="sm"
                                    onClick={() =>
                                      void handleServiceUpdate(
                                        service.manifest.service_id,
                                        mode,
                                      )
                                    }
                                    disabled={
                                      busyAction ===
                                      `service-${service.manifest.service_id}`
                                    }
                                  >
                                    {mode}
                                  </Button>
                                ),
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))
                  )}
                </TableBody>
              </Table>
              {!showServicesView && filteredServices.length > 5 ? (
                <div className="mt-4 flex justify-end">
                  <Button
                    variant="ghost"
                    onClick={() => setShowServicesView(true)}
                  >
                    Show all services
                  </Button>
                </div>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ---------------------------------------------------------------- */}
        {/* Advanced tab                                                       */}
        {/* ---------------------------------------------------------------- */}
        <TabsContent value="advanced" className="space-y-6">
          {/* Sync card */}
          <Card>
            <CardHeader>
              <CardTitle>Sync and replication</CardTitle>
              <CardDescription>
                Control how this node synchronizes with peers
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-3 text-sm">
                <div>
                  <span className="text-muted-foreground">Profile: </span>
                  <span className="font-medium">{syncStatus.profile}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Revision: </span>
                  <span className="font-medium">{syncStatus.revision}</span>
                </div>
                <div>
                  <span className="text-muted-foreground">Peers: </span>
                  <span className="font-medium">
                    {syncStatus.peers.length}
                  </span>
                </div>
              </div>
              <div className="grid gap-3 xl:grid-cols-[1fr_auto]">
                <div className="space-y-2">
                  <Label htmlFor="sync-profile">Sync profile</Label>
                  <select
                    id="sync-profile"
                    className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                    value={syncProfileDraft}
                    onChange={(event) =>
                      setSyncProfileDraft(event.target.value)
                    }
                  >
                    <option value="full">Full replication</option>
                    <option value="settings-only">Settings only</option>
                    <option value="read-only-follower">
                      Read-only follower
                    </option>
                  </select>
                </div>
                <div className="flex items-end">
                  <Button
                    variant="secondary"
                    onClick={() => void handleSyncProfileSave()}
                    disabled={busyAction === "sync-profile-save"}
                  >
                    Save profile
                  </Button>
                </div>
              </div>
              <div className="grid gap-3 xl:grid-cols-[180px_minmax(0,1fr)_auto]">
                <div className="space-y-2">
                  <Label htmlFor="transport-mode">Transport mode</Label>
                  <select
                    id="transport-mode"
                    className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                    value={syncTransportModeDraft}
                    onChange={(event) =>
                      setSyncTransportModeDraft(event.target.value)
                    }
                  >
                    <option value="opportunistic">Opportunistic</option>
                    <option value="https-required">HTTPS required</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="transport-token">Bearer token</Label>
                  <Input
                    id="transport-token"
                    value={syncTransportTokenDraft}
                    onChange={(event) =>
                      setSyncTransportTokenDraft(event.target.value)
                    }
                    placeholder={
                      syncStatus.transport_token_configured
                        ? "Set new token or leave blank to clear"
                        : "Optional bearer token"
                    }
                  />
                </div>
                <div className="flex items-end">
                  <Button
                    variant="secondary"
                    onClick={() => void handleSyncTransportSave()}
                    disabled={busyAction === "sync-transport-save"}
                  >
                    Save transport
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Tailscale card */}
          <Card>
            <CardHeader>
              <CardTitle>Tailscale</CardTitle>
              <CardDescription>
                When enabled, Cogwheel advertises this machine as a Tailscale
                exit node and keeps DNS on the local filter path for exit-node
                traffic only.
              </CardDescription>
              <CardAction>
                <Badge variant="secondary">
                  {tailscaleStatus.exit_node_active
                    ? "Exit node advertised"
                    : tailscaleStatus.installed
                      ? "Installed"
                      : "Not installed"}
                </Badge>
              </CardAction>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-3 text-sm">
                <div>
                  <span className="text-muted-foreground">Host: </span>
                  <span className="font-medium">
                    {tailscaleStatus.hostname ?? "-"}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Tailnet: </span>
                  <span className="font-medium">
                    {tailscaleStatus.tailnet_name ?? "-"}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Peers: </span>
                  <span className="font-medium">
                    {tailscaleStatus.peer_count}
                  </span>
                </div>
              </div>
              {tailscaleDnsCheck.suggestions.length > 0 ? (
                <p className="rounded-md bg-primary/10 px-3 py-2 text-sm text-primary">
                  {tailscaleDnsCheck.message}
                </p>
              ) : null}
            </CardContent>
            <CardFooter className="gap-2">
              <Button
                variant={
                  tailscaleStatus.exit_node_active ? "ghost" : "secondary"
                }
                onClick={() => void handleTailscaleExitNodeToggle()}
                disabled={busyAction === "tailscale-exit-node"}
              >
                {busyAction === "tailscale-exit-node"
                  ? "Updating..."
                  : tailscaleStatus.exit_node_active
                    ? "Disable exit-node filtering"
                    : "Enable exit-node filtering"}
              </Button>
              <Button
                variant="ghost"
                onClick={() => void handleTailscaleRollback()}
                disabled={busyAction === "tailscale-rollback"}
              >
                {busyAction === "tailscale-rollback"
                  ? "Rolling back..."
                  : "Roll back"}
              </Button>
            </CardFooter>
          </Card>

          {/* Classifier card */}
          <Card>
            <CardHeader>
              <CardTitle>Classifier</CardTitle>
              <CardDescription>
                Persisted directly in the backend control plane
              </CardDescription>
              <CardAction>
                <Badge variant="secondary">{settings.classifier.mode}</Badge>
              </CardAction>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap gap-2">
                {(["Off", "Monitor", "Protect"] as const).map((mode) => (
                  <Button
                    key={mode}
                    variant={
                      settings.classifier.mode === mode
                        ? "default"
                        : "secondary"
                    }
                    size="sm"
                    onClick={() => void handleClassifierUpdate(mode)}
                    disabled={busyAction === `classifier-mode-${mode}`}
                  >
                    {mode}
                  </Button>
                ))}
              </div>
              <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                <div className="space-y-2">
                  <Label htmlFor="classifier-threshold">Threshold</Label>
                  <Input
                    id="classifier-threshold"
                    value={classifierThreshold}
                    onChange={(event) =>
                      setClassifierThreshold(event.target.value)
                    }
                    placeholder="0.92"
                  />
                </div>
                <div className="flex items-end">
                  <Button
                    variant="secondary"
                    onClick={() => void handleClassifierThresholdSave()}
                    disabled={busyAction === "classifier-threshold"}
                  >
                    Save threshold
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Threat intel card */}
          <Card>
            <CardHeader>
              <CardTitle>Threat intelligence feeds</CardTitle>
              <CardDescription>
                Keep enrichment providers off the DNS hot path and enable them
                only when needed
              </CardDescription>
              <CardAction>
                <Badge variant="secondary">
                  {
                    threatIntelSettings.providers.filter(
                      (provider) => provider.enabled,
                    ).length
                  }{" "}
                  enabled
                </Badge>
              </CardAction>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Provider</TableHead>
                    <TableHead>Capabilities</TableHead>
                    <TableHead>Feed URL</TableHead>
                    <TableHead>Interval</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {threatIntelSettings.providers.length === 0 ? (
                    <TableRow>
                      <TableCell
                        colSpan={6}
                        className="h-24 text-center text-muted-foreground"
                      >
                        No threat intelligence providers configured.
                      </TableCell>
                    </TableRow>
                  ) : (
                    threatIntelSettings.providers.map((provider) => (
                      <TableRow key={provider.id}>
                        <TableCell className="font-medium">
                          {provider.display_name}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {provider.capabilities.join(" \u2022 ")}
                        </TableCell>
                        <TableCell>
                          <Input
                            className="h-8 text-xs"
                            value={provider.feed_url ?? ""}
                            onChange={(event) =>
                              setThreatIntelSettings((current) => ({
                                ...current,
                                providers: current.providers.map((item) =>
                                  item.id === provider.id
                                    ? {
                                        ...item,
                                        feed_url:
                                          event.target.value || null,
                                      }
                                    : item,
                                ),
                              }))
                            }
                            placeholder="https://feed.example.invalid/dns"
                          />
                        </TableCell>
                        <TableCell>
                          <Input
                            className="h-8 w-20 text-xs"
                            value={String(
                              provider.update_interval_minutes,
                            )}
                            onChange={(event) => {
                              const nextValue = Number.parseInt(
                                event.target.value,
                                10,
                              );
                              setThreatIntelSettings((current) => ({
                                ...current,
                                providers: current.providers.map((item) =>
                                  item.id === provider.id
                                    ? {
                                        ...item,
                                        update_interval_minutes:
                                          Number.isNaN(nextValue)
                                            ? item.update_interval_minutes
                                            : nextValue,
                                      }
                                    : item,
                                ),
                              }));
                            }}
                            placeholder="60"
                          />
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              provider.enabled ? "default" : "secondary"
                            }
                          >
                            {provider.enabled ? "Enabled" : "Disabled"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() =>
                              void handleThreatIntelProviderSave(
                                provider.id,
                              )
                            }
                            disabled={
                              busyAction ===
                              `threat-intel-${provider.id}`
                            }
                          >
                            {busyAction ===
                            `threat-intel-${provider.id}`
                              ? "Saving..."
                              : "Save"}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Federated learning card */}
          <Card>
            <CardHeader>
              <CardTitle>Federated learning</CardTitle>
              <CardDescription>
                Share model updates only. Raw logs stay local.
              </CardDescription>
              <CardAction>
                <Badge variant="secondary">
                  {federatedLearningSettings.enabled
                    ? federatedLearningSettings.privacy_mode
                    : "Disabled"}
                </Badge>
              </CardAction>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-3">
                <Switch
                  id="federated-enabled"
                  checked={federatedLearningSettings.enabled}
                  onCheckedChange={(checked) =>
                    setFederatedLearningSettings((current) => ({
                      ...current,
                      enabled: checked,
                    }))
                  }
                />
                <Label htmlFor="federated-enabled">
                  Enable federated learning coordinator sync
                </Label>
              </div>
              <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_180px]">
                <div className="space-y-2">
                  <Label htmlFor="coordinator-url">Coordinator URL</Label>
                  <Input
                    id="coordinator-url"
                    value={federatedLearningSettings.coordinator_url ?? ""}
                    onChange={(event) =>
                      setFederatedLearningSettings((current) => ({
                        ...current,
                        coordinator_url: event.target.value || null,
                      }))
                    }
                    placeholder="https://coordinator.example.invalid"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="round-interval">Round interval (h)</Label>
                  <Input
                    id="round-interval"
                    value={String(
                      federatedLearningSettings.round_interval_hours,
                    )}
                    onChange={(event) => {
                      const nextValue = Number.parseInt(
                        event.target.value,
                        10,
                      );
                      setFederatedLearningSettings((current) => ({
                        ...current,
                        round_interval_hours: Number.isNaN(nextValue)
                          ? current.round_interval_hours
                          : nextValue,
                      }));
                    }}
                    placeholder="24"
                  />
                </div>
              </div>
            </CardContent>
            <CardFooter className="justify-end">
              <Button
                onClick={() => void handleFederatedLearningSave()}
                disabled={busyAction === "federated-learning-save"}
              >
                {busyAction === "federated-learning-save"
                  ? "Saving..."
                  : "Save"}
              </Button>
            </CardFooter>
          </Card>

          {/* Latency budgets card */}
          <Card>
            <CardHeader>
              <CardTitle>Latency budgets</CardTitle>
              <CardDescription>
                Tracks the DNS hot path against the documented p50 budgets for
                cache hits, cache misses, and classifier work
              </CardDescription>
              <CardAction>
                <Badge variant="secondary">
                  {latencyBudget.within_budget
                    ? "Within budget"
                    : "Needs attention"}
                </Badge>
              </CardAction>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="text-sm">
                <span className="text-muted-foreground">
                  Current cache hit rate:{" "}
                </span>
                <span className="text-2xl font-semibold">
                  {(latencyBudget.cache_hit_rate * 100).toFixed(1)}%
                </span>
              </div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Path</TableHead>
                    <TableHead>Target p50</TableHead>
                    <TableHead>Observed</TableHead>
                    <TableHead>Samples</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {latencyBudget.checks.map((check) => (
                    <TableRow key={check.label}>
                      <TableCell className="font-medium">
                        {check.label}
                      </TableCell>
                      <TableCell>
                        {check.target_p50_ms.toFixed(1)} ms
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {check.observed_ms.toFixed(3)} ms
                      </TableCell>
                      <TableCell>{check.sample_count}</TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            check.status === "ok" ? "secondary" : "default"
                          }
                        >
                          {check.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {latencyBudget.recommendations.length > 0 ? (
                <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
                  {latencyBudget.recommendations.join(" ")}
                </p>
              ) : null}
            </CardContent>
          </Card>

          {/* Audit trail card with Table */}
          <Card>
            <CardHeader>
              <CardTitle>Audit trail</CardTitle>
              <CardDescription>
                Recent control-plane events for operator review
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Recovery actions */}
              <div className="space-y-3">
                <h4 className="text-sm font-medium">Guided recovery</h4>
                {recoveryActions.map((item) => (
                  <div
                    key={item.title}
                    className="flex items-start justify-between gap-4 rounded-lg border border-border p-4"
                  >
                    <div className="space-y-1">
                      <div className="text-sm font-medium">{item.title}</div>
                      <p className="text-sm text-muted-foreground">
                        {item.detail}
                      </p>
                    </div>
                    <Button
                      variant="secondary"
                      size="sm"
                      className="shrink-0"
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
                ))}
              </div>

              <Separator />

              {/* Audit event filters */}
              <div className="flex flex-wrap gap-2">
                {(
                  [
                    ["all", "All events"],
                    ["runtime", "Runtime"],
                    ["notifications", "Notifications"],
                    ["devices", "Devices"],
                    ["rulesets", "Rulesets"],
                  ] as const
                ).map(([value, label]) => (
                  <Button
                    key={value}
                    variant={
                      auditEventFilter === value ? "default" : "ghost"
                    }
                    size="sm"
                    onClick={() =>
                      setAuditEventFilter(
                        value as
                          | "all"
                          | "runtime"
                          | "notifications"
                          | "devices"
                          | "rulesets",
                      )
                    }
                  >
                    {label}
                  </Button>
                ))}
              </div>

              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Event</TableHead>
                    <TableHead>Detail</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Category</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAuditEvents.length === 0 ? (
                    <TableRow>
                      <TableCell
                        colSpan={4}
                        className="h-24 text-center text-muted-foreground"
                      >
                        No audit events match the current filter.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredAuditEvents.slice(0, 8).map((event) => {
                      const summary = summarizeAuditEvent(event);
                      return (
                        <TableRow key={event.id}>
                          <TableCell className="font-medium">
                            {summary.title}
                          </TableCell>
                          <TableCell className="text-muted-foreground">
                            {summary.detail}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {event.event_type}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline">
                              {summary.category}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit event helpers (moved from App.tsx)
// ---------------------------------------------------------------------------

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
      detail: String(
        firstPayloadItem(payload.notes) ??
          "Runtime guard restored the previous verified ruleset.",
      ),
    };
  }

  if (event.event_type === "ruleset.refresh_rejected") {
    return {
      category,
      title: "Ruleset refresh rejected",
      detail: String(
        firstPayloadItem(payload.notes) ??
          "Verification blocked the candidate ruleset before activation.",
      ),
    };
  }

  if (
    event.event_type.startsWith("notification.delivery_") ||
    event.event_type.startsWith("security.alert_delivery_")
  ) {
    return {
      category,
      title: String(
        payload.title ?? payload.domain ?? "Notification delivery",
      ),
      detail: String(
        payload.summary ??
          `${payload.severity ?? "unknown"} delivery to ${payload.client_ip ?? payload.device_name ?? "control-plane"}.`,
      ),
    };
  }

  if (event.event_type.startsWith("runtime.health_check_")) {
    return {
      category,
      title: event.event_type.endsWith("degraded")
        ? "Runtime health degraded"
        : "Runtime health check passed",
      detail: String(
        firstPayloadItem(payload.notes) ??
          "Manual runtime health check completed.",
      ),
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
    detail: firstKey
      ? `${firstKey}: ${stringifyAuditValue(firstValue)}`
      : "No structured payload details recorded.",
  };
}

function parseAuditPayload(payload: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(payload) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

function firstPayloadItem(value: unknown) {
  return Array.isArray(value) && value.length > 0 ? value[0] : undefined;
}

function stringifyAuditValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  if (Array.isArray(value) && value.length > 0)
    return stringifyAuditValue(value[0]);
  if (value && typeof value === "object") {
    const [firstKey, firstValue] = Object.entries(value)[0] ?? [];
    return firstKey
      ? `${firstKey}: ${stringifyAuditValue(firstValue)}`
      : "details available";
  }
  return "details available";
}
