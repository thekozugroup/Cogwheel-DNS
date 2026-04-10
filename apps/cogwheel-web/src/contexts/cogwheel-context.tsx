import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  api,
  type BlockProfileListRecord,
  type BlockProfileRecord,
  type DashboardSummary,
  type FederatedLearningSettings,
  type LatencyBudgetStatus,
  type ResolverAccessStatus,
  type SettingsSummary,
  type SyncNodeStatus,
  type TailscaleDnsCheckResult,
  type TailscaleStatus,
  type ThreatIntelSettings,
  type ServiceToggle,
  type NotificationSettings,
  type NotificationTestRequest,
} from "@/lib/api";
import {
  CACHE_KEYS,
  emptyDashboard,
  emptyFederatedLearningSettings,
  emptyLatencyBudget,
  emptyResolverAccess,
  emptySettings,
  emptySyncStatus,
  emptyTailscaleDnsCheck,
  emptyTailscaleStatus,
  emptyThreatIntelSettings,
} from "@/lib/constants";
import { pushToast, type ToastTone } from "@/hooks/use-toast";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type LoadState = "idle" | "loading" | "ready" | "error";

export interface CogwheelContextValue {
  // Core data
  dashboard: DashboardSummary;
  settings: SettingsSummary;
  syncStatus: SyncNodeStatus;
  tailscaleStatus: TailscaleStatus;
  tailscaleDnsCheck: TailscaleDnsCheckResult;
  threatIntelSettings: ThreatIntelSettings;
  federatedLearningSettings: FederatedLearningSettings;
  latencyBudget: LatencyBudgetStatus;
  resolverAccess: ResolverAccessStatus;

  // UI state
  state: LoadState;
  error: string | null;
  busyAction: string | null;
  setBusyAction: React.Dispatch<React.SetStateAction<string | null>>;

  // Data setters (for local optimistic updates from child components)
  setSettings: React.Dispatch<React.SetStateAction<SettingsSummary>>;
  setThreatIntelSettings: React.Dispatch<React.SetStateAction<ThreatIntelSettings>>;
  setFederatedLearningSettings: React.Dispatch<React.SetStateAction<FederatedLearningSettings>>;

  // Data loading
  load: () => Promise<void>;
  refreshLiveData: () => Promise<void>;

  // Toast
  pushToast: (title: string, detail: string | undefined, tone: ToastTone) => void;

  // Mutation handlers — runtime
  handlePauseRuntime: (minutes: number) => Promise<void>;
  handleResumeRuntime: () => Promise<void>;
  handleRefreshSources: () => Promise<void>;
  handleRollbackRuleset: () => Promise<void>;
  handleRuntimeHealthCheck: () => Promise<void>;

  // Mutation handlers — classifier
  handleClassifierUpdate: (mode: SettingsSummary["classifier"]["mode"], thresholdStr: string) => Promise<void>;
  handleClassifierThresholdSave: (thresholdStr: string) => Promise<void>;

  // Mutation handlers — notifications
  handleNotificationSave: (input: NotificationSettings) => Promise<void>;
  handleNotificationTest: (request?: NotificationTestRequest) => Promise<void>;

  // Mutation handlers — sync
  handleSyncProfileSave: (profile: string) => Promise<void>;
  handleSyncTransportSave: (mode: string, token: string) => Promise<void>;

  // Mutation handlers — tailscale
  handleTailscaleExitNodeToggle: () => Promise<void>;
  handleTailscaleRollback: () => Promise<void>;

  // Mutation handlers — threat intel & federated learning
  handleThreatIntelProviderSave: (providerId: string) => Promise<void>;
  handleFederatedLearningSave: () => Promise<void>;

  // Mutation handlers — blocklists
  handleBlocklistCreate: (input: {
    name: string;
    url: string;
    profile: string;
    strictness: string;
    interval: string;
  }) => Promise<void>;
  handleBlocklistToggle: (id: string, enabled: boolean) => Promise<void>;

  // Mutation handlers — services
  handleServiceUpdate: (serviceId: string, mode: ServiceToggle["mode"]) => Promise<void>;

  // Mutation handlers — block profiles
  handleBlockProfileSave: (
    draft: BlockProfileRecord,
    allowlistStr: string,
  ) => Promise<void>;
  handleBlockProfileDelete: (profileId: string, profileName: string) => Promise<void>;

  // Mutation handlers — devices
  handleDeviceSubmit: (input: {
    id?: string;
    name: string;
    ip_address: string;
    policy_mode: "global" | "custom";
    blocklist_profile_override?: string | null;
    protection_override?: "inherit" | "bypass";
    allowed_domains?: string[];
    service_overrides?: Array<{ service_id: string; mode: "allow" | "block" }>;
  }) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const CogwheelContext = createContext<CogwheelContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

const REFRESH_INTERVAL_MS = 5_000;

export function CogwheelProvider({ children }: { children: ReactNode }) {
  // -- Core data state ------------------------------------------------------
  const [dashboard, setDashboard] = useState<DashboardSummary>(emptyDashboard);
  const [settings, setSettings] = useState<SettingsSummary>(emptySettings);
  const [syncStatus, setSyncStatus] = useState<SyncNodeStatus>(emptySyncStatus);
  const [tailscaleStatus, setTailscaleStatus] =
    useState<TailscaleStatus>(emptyTailscaleStatus);
  const [tailscaleDnsCheck, setTailscaleDnsCheck] =
    useState<TailscaleDnsCheckResult>(emptyTailscaleDnsCheck);
  const [threatIntelSettings, setThreatIntelSettings] =
    useState<ThreatIntelSettings>(emptyThreatIntelSettings);
  const [federatedLearningSettings, setFederatedLearningSettings] =
    useState<FederatedLearningSettings>(emptyFederatedLearningSettings);
  const [latencyBudget, setLatencyBudget] =
    useState<LatencyBudgetStatus>(emptyLatencyBudget);
  const [resolverAccess, setResolverAccess] =
    useState<ResolverAccessStatus>(emptyResolverAccess);

  // -- UI state -------------------------------------------------------------
  const [state, setState] = useState<LoadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  // The notification windows are fixed for now; if they become user-editable,
  // they can be lifted into state here.
  const notificationAnalyticsWindow = 30;
  const notificationHistoryWindow = 10;

  // -- Data loading ---------------------------------------------------------

  const load = useCallback(async () => {
    setState("loading");
    setError(null);
    try {
      const [
        dashboardData,
        settingsData,
        syncStatusData,
        tailscaleData,
        tailscaleDns,
        threatIntelData,
        federatedLearningData,
        latencyBudgetData,
        resolverAccessData,
      ] = await Promise.all([
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

      // Persist to localStorage for offline fallback
      localStorage.setItem(CACHE_KEYS.dashboard, JSON.stringify(dashboardData));
      localStorage.setItem(CACHE_KEYS.settings, JSON.stringify(settingsData));
      localStorage.setItem(CACHE_KEYS.syncStatus, JSON.stringify(syncStatusData));
      localStorage.setItem(CACHE_KEYS.tailscale, JSON.stringify(tailscaleData));
      localStorage.setItem(CACHE_KEYS.tailscaleDns, JSON.stringify(tailscaleDns));
      localStorage.setItem(CACHE_KEYS.threatIntel, JSON.stringify(threatIntelData));
      localStorage.setItem(CACHE_KEYS.federatedLearning, JSON.stringify(federatedLearningData));
      localStorage.setItem(CACHE_KEYS.latencyBudget, JSON.stringify(latencyBudgetData));
      localStorage.setItem(CACHE_KEYS.resolverAccess, JSON.stringify(resolverAccessData));

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
      // Attempt offline fallback from localStorage
      const cachedDashboard = localStorage.getItem(CACHE_KEYS.dashboard);
      const cachedSettings = localStorage.getItem(CACHE_KEYS.settings);
      const cachedSyncStatus = localStorage.getItem(CACHE_KEYS.syncStatus);
      const cachedTailscale = localStorage.getItem(CACHE_KEYS.tailscale);
      const cachedTailscaleDns = localStorage.getItem(CACHE_KEYS.tailscaleDns);
      const cachedThreatIntel = localStorage.getItem(CACHE_KEYS.threatIntel);
      const cachedFederatedLearning = localStorage.getItem(CACHE_KEYS.federatedLearning);
      const cachedLatencyBudget = localStorage.getItem(CACHE_KEYS.latencyBudget);
      const cachedResolverAccess = localStorage.getItem(CACHE_KEYS.resolverAccess);

      if (
        cachedDashboard &&
        cachedSettings &&
        cachedSyncStatus &&
        cachedTailscale &&
        cachedTailscaleDns &&
        cachedThreatIntel &&
        cachedFederatedLearning &&
        cachedLatencyBudget &&
        cachedResolverAccess
      ) {
        try {
          setDashboard(JSON.parse(cachedDashboard) as DashboardSummary);
          setSettings(JSON.parse(cachedSettings) as SettingsSummary);
          setSyncStatus(JSON.parse(cachedSyncStatus) as SyncNodeStatus);
          setTailscaleStatus(JSON.parse(cachedTailscale) as TailscaleStatus);
          setTailscaleDnsCheck(
            JSON.parse(cachedTailscaleDns) as TailscaleDnsCheckResult,
          );
          setThreatIntelSettings(
            JSON.parse(cachedThreatIntel) as ThreatIntelSettings,
          );
          setFederatedLearningSettings(
            JSON.parse(cachedFederatedLearning) as FederatedLearningSettings,
          );
          setLatencyBudget(
            JSON.parse(cachedLatencyBudget) as LatencyBudgetStatus,
          );
          setResolverAccess(
            JSON.parse(cachedResolverAccess) as ResolverAccessStatus,
          );
          setState("ready");
          pushToast(
            "Working offline",
            "Showing cached data while the server is unreachable.",
            "info",
          );
          return;
        } catch {
          // Fall through if parse fails
        }
      }

      setError(
        loadError instanceof Error ? loadError.message : "Unknown error",
      );
      setState("ready");
    }
  }, []);

  const refreshLiveData = useCallback(async () => {
    try {
      const [
        dashboardData,
        syncStatusData,
        tailscaleData,
        tailscaleDns,
        latencyBudgetData,
        resolverAccessData,
      ] = await Promise.all([
        api.dashboard(notificationAnalyticsWindow, notificationHistoryWindow),
        api.syncStatus(),
        api.tailscaleStatus(),
        api.tailscaleDnsCheck(),
        api.latencyBudget(),
        api.resolverAccess(),
      ]);

      localStorage.setItem(CACHE_KEYS.dashboard, JSON.stringify(dashboardData));
      localStorage.setItem(CACHE_KEYS.syncStatus, JSON.stringify(syncStatusData));
      localStorage.setItem(CACHE_KEYS.tailscale, JSON.stringify(tailscaleData));
      localStorage.setItem(CACHE_KEYS.tailscaleDns, JSON.stringify(tailscaleDns));
      localStorage.setItem(CACHE_KEYS.latencyBudget, JSON.stringify(latencyBudgetData));
      localStorage.setItem(CACHE_KEYS.resolverAccess, JSON.stringify(resolverAccessData));

      setDashboard(dashboardData);
      setSyncStatus(syncStatusData);
      setTailscaleStatus(tailscaleData);
      setTailscaleDnsCheck(tailscaleDns);
      setLatencyBudget(latencyBudgetData);
      setResolverAccess(resolverAccessData);
      setError(null);
      setState("ready");
    } catch (refreshError) {
      if (state === "ready") {
        setError(
          refreshError instanceof Error
            ? refreshError.message
            : "Unknown error",
        );
      }
    }
  }, [state]);

  // -- Auto-refresh on mount and visibility ---------------------------------

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (state !== "ready") return;

    const refreshIfVisible = () => {
      if (document.visibilityState === "visible") {
        void refreshLiveData();
      }
    };

    const intervalId = window.setInterval(refreshIfVisible, REFRESH_INTERVAL_MS);
    window.addEventListener("focus", refreshIfVisible);
    document.addEventListener("visibilitychange", refreshIfVisible);

    return () => {
      window.clearInterval(intervalId);
      window.removeEventListener("focus", refreshIfVisible);
      document.removeEventListener("visibilitychange", refreshIfVisible);
    };
  }, [refreshLiveData, state]);

  // -- Mutation helpers (shared pattern) ------------------------------------

  const withBusy = useCallback(
    (actionKey: string, fn: () => Promise<void>) => {
      return async () => {
        setBusyAction(actionKey);
        try {
          await fn();
        } finally {
          setBusyAction(null);
        }
      };
    },
    [],
  );

  // -- Mutation handlers: runtime -------------------------------------------

  const handlePauseRuntime = useCallback(
    async (minutes: number) => {
      setBusyAction("pause-runtime");
      try {
        await api.pauseRuntime(minutes);
        pushToast(
          "Protection paused",
          `Adblocking and classification paused for ${minutes} minutes.`,
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Pause failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  const handleResumeRuntime = useCallback(async () => {
    setBusyAction("resume-runtime");
    try {
      await api.resumeRuntime();
      pushToast(
        "Protection resumed",
        "Adblocking and classification are active again.",
        "success",
      );
      await load();
    } catch (err) {
      pushToast(
        "Resume failed",
        err instanceof Error ? err.message : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }, [load]);

  const handleRefreshSources = useCallback(async () => {
    setBusyAction("refresh-sources");
    try {
      const result = await api.refreshSources();
      pushToast("Sources refreshed", result.notes[0], "success");
      await load();
    } catch (err) {
      pushToast(
        "Refresh failed",
        err instanceof Error ? err.message : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }, [load]);

  const handleRollbackRuleset = useCallback(async () => {
    setBusyAction("rollback-ruleset");
    try {
      const ruleset = await api.rollbackRuleset();
      pushToast(
        "Rollback completed",
        `Restored ruleset ${ruleset.hash.slice(0, 12)}.`,
        "success",
      );
      await load();
    } catch (err) {
      pushToast(
        "Rollback failed",
        err instanceof Error ? err.message : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }, [load]);

  const handleRuntimeHealthCheck = useCallback(async () => {
    setBusyAction("runtime-health-check");
    try {
      const report = await api.runtimeHealthCheck();
      pushToast(
        report.degraded ? "Runtime degraded" : "Runtime healthy",
        report.notes[0] ?? "Runtime guard probes completed without regressions.",
        report.degraded ? "error" : "success",
      );
      await load();
    } catch (err) {
      pushToast(
        "Runtime health check failed",
        err instanceof Error ? err.message : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }, [load]);

  // -- Mutation handlers: classifier ----------------------------------------

  const handleClassifierUpdate = useCallback(
    async (mode: SettingsSummary["classifier"]["mode"], thresholdStr: string) => {
      setBusyAction(`classifier-mode-${mode}`);
      try {
        await api.updateClassifier(
          mode,
          Number.parseFloat(thresholdStr) || settings.classifier.threshold,
        );
        pushToast("Classifier updated", `Mode switched to ${mode}.`, "success");
        await load();
      } catch (err) {
        pushToast(
          "Classifier update failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load, settings.classifier.threshold],
  );

  const handleClassifierThresholdSave = useCallback(
    async (thresholdStr: string) => {
      setBusyAction("classifier-threshold");
      try {
        const threshold =
          Number.parseFloat(thresholdStr) || settings.classifier.threshold;
        await api.updateClassifier(settings.classifier.mode, threshold);
        pushToast(
          "Threshold saved",
          `Classifier threshold is now ${threshold.toFixed(2)}.`,
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Threshold update failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load, settings.classifier.mode, settings.classifier.threshold],
  );

  // -- Mutation handlers: notifications -------------------------------------

  const handleNotificationSave = useCallback(
    async (input: NotificationSettings) => {
      setBusyAction("notifications-save");
      try {
        await api.updateNotifications(input);
        pushToast(
          "Notifications updated",
          input.enabled
            ? "Webhook delivery is configured."
            : "Webhook delivery is disabled.",
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Notification update failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  const handleNotificationTest = useCallback(
    async (request?: NotificationTestRequest) => {
      setBusyAction("notifications-test");
      try {
        const result = await api.testNotifications(request);
        const isDryRun = request?.dry_run ?? false;
        pushToast(
          isDryRun ? "Webhook validated" : "Test notification sent",
          isDryRun
            ? `Validated ${result.target} without sending a live request.`
            : `Delivered to ${result.target} and added to recent history.`,
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Test notification failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  // -- Mutation handlers: sync ----------------------------------------------

  const handleSyncProfileSave = useCallback(
    async (profile: string) => {
      setBusyAction("sync-profile-save");
      try {
        await api.updateSyncProfile(profile);
        pushToast(
          "Sync profile updated",
          `Node sync profile is now ${profile}.`,
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Sync profile update failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  const handleSyncTransportSave = useCallback(
    async (mode: string, token: string) => {
      setBusyAction("sync-transport-save");
      try {
        await api.updateSyncTransport(mode, token);
        pushToast(
          "Sync transport updated",
          `Transport mode is now ${mode}.`,
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Sync transport update failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  // -- Mutation handlers: Tailscale -----------------------------------------

  const handleTailscaleExitNodeToggle = useCallback(async () => {
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
    } catch (err) {
      pushToast(
        "Exit node toggle failed",
        err instanceof Error ? err.message : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }, [load, tailscaleStatus.exit_node_active]);

  const handleTailscaleRollback = useCallback(async () => {
    setBusyAction("tailscale-rollback");
    try {
      const result = await api.tailscaleRollback();
      pushToast("Exit node rolled back", result.message, "success");
      await load();
    } catch (err) {
      pushToast(
        "Rollback failed",
        err instanceof Error ? err.message : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }, [load]);

  // -- Mutation handlers: threat intel & federated learning ------------------

  const handleThreatIntelProviderSave = useCallback(
    async (providerId: string) => {
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
      } catch (err) {
        pushToast(
          "Threat intel update failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load, threatIntelSettings.providers],
  );

  const handleFederatedLearningSave = useCallback(async () => {
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
    } catch (err) {
      pushToast(
        "Federated learning update failed",
        err instanceof Error ? err.message : "Unknown error",
        "error",
      );
    } finally {
      setBusyAction(null);
    }
  }, [
    federatedLearningSettings.coordinator_url,
    federatedLearningSettings.enabled,
    federatedLearningSettings.round_interval_hours,
    load,
  ]);

  // -- Mutation handlers: blocklists ----------------------------------------

  const handleBlocklistCreate = useCallback(
    async (input: {
      name: string;
      url: string;
      profile: string;
      strictness: string;
      interval: string;
    }) => {
      setBusyAction("create-blocklist");
      try {
        await api.upsertBlocklist({
          name: input.name,
          url: input.url,
          kind: "domains",
          enabled: true,
          refresh_interval_minutes:
            Number.parseInt(input.interval, 10) || 60,
          profile: input.profile,
          verification_strictness: input.strictness,
        });
        pushToast(
          "Blocklist added",
          "The source was saved and refreshed.",
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Blocklist add failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  const handleBlocklistToggle = useCallback(
    async (id: string, enabled: boolean) => {
      setBusyAction(`blocklist-toggle-${id}`);
      try {
        await api.setBlocklistEnabled(id, enabled);
        pushToast(
          enabled ? "Blocklist enabled" : "Blocklist disabled",
          "Ruleset refresh requested.",
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Blocklist update failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  // -- Mutation handlers: services ------------------------------------------

  const handleServiceUpdate = useCallback(
    async (serviceId: string, mode: ServiceToggle["mode"]) => {
      setBusyAction(`service-${serviceId}`);
      try {
        await api.updateService(serviceId, mode);
        pushToast(
          "Service updated",
          `Service mode set to ${mode}.`,
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Service update failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  // -- Mutation handlers: block profiles ------------------------------------

  const handleBlockProfileSave = useCallback(
    async (draft: BlockProfileRecord, allowlistStr: string) => {
      if (!draft.name.trim()) {
        pushToast(
          "Name required",
          "Give the block profile a friendly name before saving.",
          "error",
        );
        return;
      }

      setBusyAction("block-profile-save");
      try {
        const updatedProfiles = await api.upsertBlockProfile({
          id: draft.id || undefined,
          emoji: draft.emoji,
          name: draft.name,
          description: draft.description,
          blocklists: draft.blocklists,
          allowlists: allowlistStr
            .split(",")
            .map((entry) => entry.trim())
            .filter(Boolean),
        });
        setSettings((current) => ({
          ...current,
          block_profiles: updatedProfiles,
        }));
        pushToast(
          "Block profile saved",
          `${draft.name} is ready for device assignment.`,
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Block profile save failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  const handleBlockProfileDelete = useCallback(
    async (profileId: string, profileName: string) => {
      if (!profileId) {
        pushToast(
          "Profile required",
          "Choose a saved profile before deleting it.",
          "error",
        );
        return;
      }

      setBusyAction("block-profile-delete");
      try {
        const updatedProfiles = await api.deleteBlockProfile(profileId);
        setSettings((current) => ({
          ...current,
          block_profiles: updatedProfiles,
        }));
        pushToast(
          "Block profile deleted",
          `${profileName} was removed.`,
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Block profile delete failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  // -- Mutation handlers: devices -------------------------------------------

  const handleDeviceSubmit = useCallback(
    async (input: {
      id?: string;
      name: string;
      ip_address: string;
      policy_mode: "global" | "custom";
      blocklist_profile_override?: string | null;
      protection_override?: "inherit" | "bypass";
      allowed_domains?: string[];
      service_overrides?: Array<{ service_id: string; mode: "allow" | "block" }>;
    }) => {
      setBusyAction("device-submit");
      try {
        await api.upsertDevice({
          id: input.id,
          name: input.name,
          ip_address: input.ip_address,
          policy_mode: input.policy_mode,
          blocklist_profile_override:
            input.policy_mode === "custom"
              ? input.blocklist_profile_override ?? null
              : null,
          protection_override:
            input.policy_mode === "custom"
              ? input.protection_override ?? "inherit"
              : "inherit",
          allowed_domains:
            input.policy_mode === "custom" ? input.allowed_domains ?? [] : [],
          service_overrides:
            input.policy_mode === "custom"
              ? input.service_overrides ?? []
              : [],
        });
        pushToast(
          input.id ? "Device updated" : "Device added",
          `${input.name} is now tracked in the control plane.`,
          "success",
        );
        await load();
      } catch (err) {
        pushToast(
          "Device update failed",
          err instanceof Error ? err.message : "Unknown error",
          "error",
        );
      } finally {
        setBusyAction(null);
      }
    },
    [load],
  );

  // -- Context value --------------------------------------------------------

  const value: CogwheelContextValue = {
    // Data
    dashboard,
    settings,
    syncStatus,
    tailscaleStatus,
    tailscaleDnsCheck,
    threatIntelSettings,
    federatedLearningSettings,
    latencyBudget,
    resolverAccess,

    // UI state
    state,
    error,
    busyAction,
    setBusyAction,

    // Setters for local optimistic updates
    setSettings,
    setThreatIntelSettings,
    setFederatedLearningSettings,

    // Loading
    load,
    refreshLiveData,

    // Toast
    pushToast,

    // Mutations
    handlePauseRuntime,
    handleResumeRuntime,
    handleRefreshSources,
    handleRollbackRuleset,
    handleRuntimeHealthCheck,
    handleClassifierUpdate,
    handleClassifierThresholdSave,
    handleNotificationSave,
    handleNotificationTest,
    handleSyncProfileSave,
    handleSyncTransportSave,
    handleTailscaleExitNodeToggle,
    handleTailscaleRollback,
    handleThreatIntelProviderSave,
    handleFederatedLearningSave,
    handleBlocklistCreate,
    handleBlocklistToggle,
    handleServiceUpdate,
    handleBlockProfileSave,
    handleBlockProfileDelete,
    handleDeviceSubmit,
  };

  return (
    <CogwheelContext.Provider value={value}>
      {children}
    </CogwheelContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useCogwheel(): CogwheelContextValue {
  const ctx = useContext(CogwheelContext);
  if (!ctx) {
    throw new Error(
      "useCogwheel() must be used inside a <CogwheelProvider>. " +
        "Wrap your component tree with <CogwheelProvider> in your app root.",
    );
  }
  return ctx;
}
