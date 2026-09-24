import React from "react";
import { api, errorMessage, type Overview } from "@/lib/api";
import { trackRuntime, upstreamFailing, type RuntimeSample } from "@/lib/derive";
import {
  CACHE_KEYS,
  REFRESH_INTERVAL_MS,
  emptyDevices,
  emptyLists,
  emptyOverview,
  emptyRules,
  emptySettings,
} from "@/lib/constants";
import { notify } from "@/lib/toast";
import {
  CogwheelActionsContext,
  CogwheelStatusContext,
  type CogwheelActions,
  type CogwheelStatus,
  type ControlPlaneSnapshot,
  type FreshnessStore,
  type LoadPhase,
  type MutationOptions,
  type SnapshotStore,
} from "@/data/context";

const INITIAL: ControlPlaneSnapshot = {
  overview: emptyOverview,
  settings: emptySettings,
  lists: emptyLists,
  devices: emptyDevices,
  rules: emptyRules,
};

const CACHE_KEY_BY_FIELD: Record<keyof ControlPlaneSnapshot, string> = {
  overview: CACHE_KEYS.overview,
  settings: CACHE_KEYS.settings,
  lists: CACHE_KEYS.lists,
  devices: CACHE_KEYS.devices,
  rules: CACHE_KEYS.rules,
};

function readCacheRaw(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    // A corrupt or quota-blocked cache must never stop the app from starting.
    return null;
  }
}

function writeCacheRaw(key: string, json: string): void {
  try {
    window.localStorage.setItem(key, json);
  } catch {
    /* Private-mode or full quota; the cache is an optimisation, not a requirement. */
  }
}

type Field = keyof ControlPlaneSnapshot;

/**
 * Restores whatever the last successful session persisted, field by field,
 * and returns the raw JSON alongside so the first network answer that matches
 * the cache is recognised as no change at all.
 */
function hydrateFromCache(): { snapshot: ControlPlaneSnapshot; hit: boolean; raw: Partial<Record<Field, string>> } {
  const snapshot = { ...INITIAL };
  const raw: Partial<Record<Field, string>> = {};
  let hit = false;
  for (const field of Object.keys(CACHE_KEY_BY_FIELD) as Field[]) {
    const json = readCacheRaw(CACHE_KEY_BY_FIELD[field]);
    if (json === null) continue;
    try {
      // Field types are disjoint; the cache round-trips the same shape it wrote.
      (snapshot as Record<string, unknown>)[field] = JSON.parse(json);
      raw[field] = json;
      hit = true;
    } catch {
      /* A corrupt entry is skipped, not fatal. */
    }
  }
  return { snapshot, hit, raw };
}

/** The poll clock: a value and its subscribers, outside React state. */
function createFreshnessStore(): FreshnessStore & { set: (value: number) => void } {
  let value: number | null = null;
  const listeners = new Set<() => void>();
  return {
    get: () => value,
    set(next) {
      value = next;
      for (const listener of listeners) listener();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

/** A minimal external store: `useSyncExternalStore` reads it, the provider writes it. */
function createSnapshotStore(initial: ControlPlaneSnapshot): SnapshotStore {
  let state = initial;
  const listeners = new Set<() => void>();
  return {
    get: () => state,
    set(next) {
      const value = typeof next === "function" ? next(state) : next;
      if (value === state) return;
      state = value;
      for (const listener of listeners) listener();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}

type Loader = { field: keyof ControlPlaneSnapshot; load: (signal: AbortSignal) => Promise<unknown> };

/** Everything, used on first paint, manual refresh and after every mutation. */
const FULL_LOADERS: Loader[] = [
  { field: "overview", load: (signal) => api.overview({ signal }) },
  { field: "settings", load: (signal) => api.settings({ signal }) },
  { field: "lists", load: (signal) => api.lists({ signal }) },
  { field: "devices", load: (signal) => api.devices({ signal }) },
  { field: "rules", load: (signal) => api.rules(undefined, { signal }) },
];

/**
 * The poll set. Only the overview moves on its own; lists, devices, rules and
 * the env-only settings change when the operator changes them, so they refresh
 * on mount, on demand and after every mutation instead of every five seconds.
 */
const LIVE_FIELDS = new Set<keyof ControlPlaneSnapshot>(["overview"]);
const LIVE_LOADERS = FULL_LOADERS.filter((loader) => LIVE_FIELDS.has(loader.field));

export function CogwheelProvider({ children }: { children: React.ReactNode }) {
  const [store] = React.useState(() => createSnapshotStore(INITIAL));
  const setData = store.set;
  // The last JSON the server sent for each field. A response that serialises
  // to the same string is dropped before it reaches the store: no new object,
  // no subscriber woken, no localStorage write. An idle five-second poll used
  // to hand every screen a fresh overview object identical to the old one.
  const lastJson = React.useRef<Partial<Record<Field, string>>>({});
  const [phase, setPhase] = React.useState<LoadPhase>("loading");
  const [error, setError] = React.useState<string | null>(null);
  const [stale, setStale] = React.useState(false);
  // Not state: it moves on every successful poll, and as state it re-rendered
  // the provider — and through it every consumer — every five seconds. Only
  // the stale banner reads it, through `useLastUpdatedAt()`.
  const [freshness] = React.useState(createFreshnessStore);
  const setLastUpdatedAt = freshness.set;
  // Whether there has ever been an answer. Flips once.
  const [connected, setConnected] = React.useState(false);
  const [busy, setBusy] = React.useState<string | null>(null);

  // Two controllers, not one. A five-second poll landing mid-reload must not cancel the refetch
  // a mutation is awaiting: these writes carry no optimistic patch, so a cancelled refetch means
  // the row the operator just saved does not appear until the next mutation or the Reload button.
  // The poll owns `background` and yields to anything foreground; first paint, Reload and every
  // post-mutation refetch own `foreground`.
  const foreground = React.useRef<AbortController | null>(null);
  const background = React.useRef<AbortController | null>(null);
  // The resolver's counters over the last minute, to tell whether the upstream
  // is answering at all (lib/derive.ts, upstreamFailing).
  const samples = React.useRef<RuntimeSample[]>([]);
  const [upstreamDown, setUpstreamFailing] = React.useState(false);

  const run = React.useCallback(async (loaders: Loader[], intent: "foreground" | "background") => {
    // A poll never outranks work the operator started, and never cancels it.
    if (intent === "background" && foreground.current) return;
    const controller = new AbortController();
    if (intent === "foreground") {
      foreground.current?.abort();
      background.current?.abort();
      foreground.current = controller;
    } else {
      background.current?.abort();
      background.current = controller;
    }

    const results = await Promise.allSettled(
      loaders.map(async (loader) => ({ field: loader.field, value: await loader.load(controller.signal) })),
    );
    // Whoever replaced this run owns the ref now, so only the current occupant clears it.
    if (foreground.current === controller) foreground.current = null;
    if (background.current === controller) background.current = null;
    if (controller.signal.aborted) return;

    const patch: Record<string, unknown> = {};
    const failures: string[] = [];

    for (const result of results) {
      if (result.status === "fulfilled") {
        const { field, value } = result.value;
        const json = JSON.stringify(value);
        if (json === lastJson.current[field]) continue;
        lastJson.current[field] = json;
        patch[field] = value;
        writeCacheRaw(CACHE_KEY_BY_FIELD[field], json);
      } else if (!(result.reason instanceof DOMException && result.reason.name === "AbortError")) {
        // The reason alone. It used to lead with the field — "overview: The
        // control plane is unreachable." — which is the code's name for it.
        failures.push(errorMessage(result.reason));
      }
    }

    if (Object.keys(patch).length > 0) {
      setData((current) => ({ ...current, ...(patch as Partial<ControlPlaneSnapshot>) }));
    }
    if (patch.overview) {
      const { runtime } = patch.overview as Overview;
      samples.current = trackRuntime(samples.current, {
        at: Date.now(),
        queries: runtime.queries_total,
        hits: runtime.cache_hits_total,
        failures: runtime.upstream_failures_total,
      });
      setUpstreamFailing(upstreamFailing(samples.current));
    }

    // A partial failure keeps the last-known values on screen and flags them as
    // stale — a blank page would throw away information the operator still needs.
    const answered = results.some((result) => result.status === "fulfilled");
    if (answered) {
      setLastUpdatedAt(Date.now());
      setConnected(true);
    }
    if (failures.length === 0) {
      setError(null);
      setStale(false);
    } else {
      setError(failures[0]);
      setStale(true);
    }

    setPhase("ready");
  }, [setData, setLastUpdatedAt]);

  const reload = React.useCallback(() => run(FULL_LOADERS, "foreground"), [run]);
  const refresh = React.useCallback(() => run(LIVE_LOADERS, "background"), [run]);

  // A local write means the screen no longer shows what the server last sent,
  // so the next answer for those fields must be applied even if it equals it.
  const forget = React.useCallback((partial: Partial<ControlPlaneSnapshot>) => {
    for (const field of Object.keys(partial) as Field[]) delete lastJson.current[field];
  }, []);

  const patch = React.useCallback(
    (partial: Partial<ControlPlaneSnapshot>) => {
      forget(partial);
      setData((current) => ({ ...current, ...partial }));
    },
    [forget, setData],
  );

  // First paint: show whatever the last session cached, then go to the network.
  React.useEffect(() => {
    const { snapshot, hit, raw } = hydrateFromCache();
    if (hit) {
      setData(snapshot);
      lastJson.current = { ...raw };
      setStale(true);
    }
    void reload();
    return () => {
      foreground.current?.abort();
      background.current?.abort();
    };
  }, [reload, setData]);

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

  // No toast for an outage. The stale banner says it, stays for as long as it
  // is true, and is announced; a toast beside it said the same thing twice and
  // then went away while the outage did not.

  const mutate = React.useCallback(
    async <T,>(options: MutationOptions<T>): Promise<T | null> => {
      const { key, action, successTitle, successDetail, failureTitle, optimistic, after = "full", undo } = options;

      let rollback: Partial<ControlPlaneSnapshot> | null = null;
      if (optimistic) {
        forget(optimistic);
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
          undo
            ? {
                label: "Undo",
                onClick: () => {
                  undo(result)
                    .then(() => run(FULL_LOADERS, "foreground"))
                    .catch((cause) => notify.error("Could not undo that", errorMessage(cause)));
                },
              }
            : undefined,
        );
        // Foreground either way: this is the refetch that makes the write visible, and the
        // poll may not cancel it.
        if (after !== "none") await run(after === "full" ? FULL_LOADERS : LIVE_LOADERS, "foreground");
        return result;
      } catch (cause) {
        // Roll the optimistic write back so the control visibly snaps to the
        // server's actual state rather than silently lying.
        if (rollback) {
          forget(rollback);
          setData((current) => ({ ...current, ...(rollback as Partial<ControlPlaneSnapshot>) }));
        }
        notify.error(failureTitle, errorMessage(cause));
        return null;
      } finally {
        setBusy(null);
      }
    },
    [run, forget, setData],
  );

  // Split by how often things change. The verbs and the two stores never
  // change identity; status changes on transitions; the snapshot's fields and
  // the poll clock are read through their stores, per field. A component pays
  // only for what it reads, and a poll that brings nothing new renders nothing.
  const actions = React.useMemo<CogwheelActions>(
    () => ({ store, freshness, reload, refresh, patch, mutate }),
    [store, freshness, reload, refresh, patch, mutate],
  );
  const status = React.useMemo<CogwheelStatus>(
    () => ({ phase, error, stale, busy, connected, upstreamFailing: upstreamDown }),
    [phase, error, stale, busy, connected, upstreamDown],
  );

  return (
    <CogwheelActionsContext.Provider value={actions}>
      <CogwheelStatusContext.Provider value={status}>{children}</CogwheelStatusContext.Provider>
    </CogwheelActionsContext.Provider>
  );
}
