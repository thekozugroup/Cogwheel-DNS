import React from "react";
import { api, errorMessage } from "@/lib/api";
import {
  CACHE_KEYS,
  REFRESH_INTERVAL_MS,
  emptyDashboard,
  emptyResolverAccess,
  emptySettings,
} from "@/lib/constants";
import { notify } from "@/lib/toast";
import {
  CogwheelContext,
  type CogwheelContextValue,
  type ControlPlaneSnapshot,
  type LoadPhase,
  type MutationOptions,
} from "@/data/context";

const INITIAL: ControlPlaneSnapshot = {
  dashboard: emptyDashboard,
  settings: emptySettings,
  resolverAccess: emptyResolverAccess,
};

const CACHE_KEY_BY_FIELD: Record<keyof ControlPlaneSnapshot, string> = {
  dashboard: CACHE_KEYS.dashboard,
  settings: CACHE_KEYS.settings,
  resolverAccess: CACHE_KEYS.resolverAccess,
};

function readCache<T>(key: string): T | null {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    // A corrupt or quota-blocked cache must never stop the app from starting.
    return null;
  }
}

function writeCache(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* Private-mode or full quota; the cache is an optimisation, not a requirement. */
  }
}

/** Restores whatever the last successful session persisted, field by field. */
function hydrateFromCache(): { snapshot: ControlPlaneSnapshot; hit: boolean } {
  const snapshot = { ...INITIAL };
  let hit = false;
  for (const field of Object.keys(CACHE_KEY_BY_FIELD) as (keyof ControlPlaneSnapshot)[]) {
    const cached = readCache<unknown>(CACHE_KEY_BY_FIELD[field]);
    if (cached !== null) {
      // Field types are disjoint; the cache round-trips the same shape it wrote.
      (snapshot as Record<string, unknown>)[field] = cached;
      hit = true;
    }
  }
  return { snapshot, hit };
}

type Loader = { field: keyof ControlPlaneSnapshot; load: (signal: AbortSignal) => Promise<unknown> };

/** Everything, used on first paint, manual refresh and after every mutation. */
const FULL_LOADERS: Loader[] = [
  { field: "dashboard", load: (signal) => api.dashboard({ signal }) },
  { field: "settings", load: (signal) => api.settings({ signal }) },
  { field: "resolverAccess", load: (signal) => api.resolverAccess({ signal }) },
];

/**
 * The poll set. Only the dashboard is genuinely live; settings and the
 * resolver-access report (which shells out to `hostname` on the appliance)
 * refresh on mount, on demand, and after any mutation.
 */
const LIVE_FIELDS = new Set<keyof ControlPlaneSnapshot>(["dashboard"]);
const LIVE_LOADERS = FULL_LOADERS.filter((loader) => LIVE_FIELDS.has(loader.field));

export function CogwheelProvider({ children }: { children: React.ReactNode }) {
  const [data, setData] = React.useState<ControlPlaneSnapshot>(INITIAL);
  const [phase, setPhase] = React.useState<LoadPhase>("loading");
  const [error, setError] = React.useState<string | null>(null);
  const [stale, setStale] = React.useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = React.useState<number | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);

  const inFlight = React.useRef<AbortController | null>(null);
  const announcedOffline = React.useRef(false);

  const run = React.useCallback(async (loaders: Loader[]) => {
    inFlight.current?.abort();
    const controller = new AbortController();
    inFlight.current = controller;

    const results = await Promise.allSettled(
      loaders.map(async (loader) => ({ field: loader.field, value: await loader.load(controller.signal) })),
    );
    if (controller.signal.aborted) return;

    const patch: Record<string, unknown> = {};
    const failures: string[] = [];

    for (const [index, result] of results.entries()) {
      if (result.status === "fulfilled") {
        patch[result.value.field] = result.value.value;
        writeCache(CACHE_KEY_BY_FIELD[result.value.field], result.value.value);
      } else if (!(result.reason instanceof DOMException && result.reason.name === "AbortError")) {
        failures.push(`${loaders[index].field}: ${errorMessage(result.reason)}`);
      }
    }

    if (Object.keys(patch).length > 0) {
      setData((current) => ({ ...current, ...(patch as Partial<ControlPlaneSnapshot>) }));
    }

    // A partial failure keeps the last-known values on screen and flags them as
    // stale — a blank page would throw away information the operator still needs.
    if (failures.length === 0) {
      setError(null);
      setStale(false);
      setLastUpdatedAt(Date.now());
      announcedOffline.current = false;
    } else {
      setError(failures[0]);
      setStale(true);
      if (Object.keys(patch).length > 0) setLastUpdatedAt(Date.now());
    }

    setPhase("ready");
  }, []);

  const reload = React.useCallback(() => run(FULL_LOADERS), [run]);
  const refresh = React.useCallback(() => run(LIVE_LOADERS), [run]);

  const patch = React.useCallback((partial: Partial<ControlPlaneSnapshot>) => {
    setData((current) => ({ ...current, ...partial }));
  }, []);

  // First paint: show whatever the last session cached, then go to the network.
  React.useEffect(() => {
    const { snapshot, hit } = hydrateFromCache();
    if (hit) {
      setData(snapshot);
      setStale(true);
    }
    void reload();
    return () => inFlight.current?.abort();
  }, [reload]);

  // Poll only while the tab is visible, and catch up immediately on refocus.
  React.useEffect(() => {
    if (phase !== "ready") return;

    const tick = () => {
      if (document.visibilityState === "visible") void refresh();
    };
    const interval = window.setInterval(tick, REFRESH_INTERVAL_MS);
    window.addEventListener("focus", tick);
    document.addEventListener("visibilitychange", tick);

    return () => {
      window.clearInterval(interval);
      window.removeEventListener("focus", tick);
      document.removeEventListener("visibilitychange", tick);
    };
  }, [phase, refresh]);

  // One notice per outage, not one per failed poll.
  React.useEffect(() => {
    if (stale && error && !announcedOffline.current) {
      announcedOffline.current = true;
      notify.warning("Showing last-known data", "The control plane did not answer the most recent poll.");
    }
  }, [stale, error]);

  const mutate = React.useCallback(
    async <T,>(options: MutationOptions<T>): Promise<T | null> => {
      const { key, action, successTitle, successDetail, failureTitle, optimistic, after = "full" } = options;

      let rollback: Partial<ControlPlaneSnapshot> | null = null;
      if (optimistic) {
        setData((current) => {
          const previous: Record<string, unknown> = {};
          for (const field of Object.keys(optimistic)) {
            previous[field] = (current as Record<string, unknown>)[field];
          }
          rollback = previous as Partial<ControlPlaneSnapshot>;
          return { ...current, ...optimistic };
        });
      }

      setBusy(key);
      try {
        const result = await action();
        notify.success(
          typeof successTitle === "function" ? successTitle(result) : successTitle,
          typeof successDetail === "function" ? successDetail(result) : successDetail,
        );
        if (after === "full") await reload();
        else if (after === "light") await refresh();
        return result;
      } catch (cause) {
        // Roll the optimistic write back so the control visibly snaps to the
        // server's actual state rather than silently lying.
        if (rollback) setData((current) => ({ ...current, ...(rollback as Partial<ControlPlaneSnapshot>) }));
        notify.error(failureTitle, errorMessage(cause));
        return null;
      } finally {
        setBusy(null);
      }
    },
    [refresh, reload],
  );

  const value = React.useMemo<CogwheelContextValue>(
    () => ({ data, phase, error, stale, lastUpdatedAt, busy, reload, refresh, patch, mutate }),
    [data, phase, error, stale, lastUpdatedAt, busy, reload, refresh, patch, mutate],
  );

  return <CogwheelContext.Provider value={value}>{children}</CogwheelContext.Provider>;
}
