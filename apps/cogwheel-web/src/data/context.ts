import { createContext, useContext, useSyncExternalStore } from "react";
import type { DeviceList, ListCatalogue, Overview, Rule, Settings } from "@/lib/api";

/** One snapshot of everything the control plane exposes as read state. */
export type ControlPlaneSnapshot = {
  overview: Overview;
  settings: Settings;
  lists: ListCatalogue;
  devices: DeviceList;
  rules: Rule[];
};

export type LoadPhase = "loading" | "ready";

export type MutationOptions<T> = {
  /** Busy key; components disable their own control by comparing against `busy`. */
  key: string;
  action: () => Promise<T>;
  successTitle: string | ((result: T) => string);
  successDetail?: string | ((result: T) => string | undefined);
  failureTitle: string;
  /** Applied immediately and rolled back if `action` rejects. */
  optimistic?: Partial<ControlPlaneSnapshot>;
  /** Defaults to "full": every mutation the server exposes has side effects elsewhere. */
  after?: "full" | "light" | "none";
  /**
   * Puts things back. The success toast then carries Undo, for a change made
   * in one click with no confirmation — removing a household rule.
   */
  undo?: (result: T) => Promise<unknown>;
};

/**
 * The snapshot lives in a small external store rather than in React state, so
 * a component can subscribe to the one field it reads (`useSnapshot`) and not
 * re-render when another one moves. Fields keep their identity until the
 * server sends something different: the provider compares each response with
 * the last one and drops it when they are equal.
 */
export type SnapshotStore = {
  get: () => ControlPlaneSnapshot;
  set: (next: ControlPlaneSnapshot | ((current: ControlPlaneSnapshot) => ControlPlaneSnapshot)) => void;
  subscribe: (listener: () => void) => () => void;
};

/** When the last successful poll landed, in ms; a store so that reading it is opt-in. */
export type FreshnessStore = {
  get: () => number | null;
  subscribe: (listener: () => void) => () => void;
};

/** Stable for the life of the app: the stores and the verbs that act on them. */
export type CogwheelActions = {
  store: SnapshotStore;
  freshness: FreshnessStore;
  reload: () => Promise<void>;
  refresh: () => Promise<void>;
  patch: (partial: Partial<ControlPlaneSnapshot>) => void;
  mutate: <T>(options: MutationOptions<T>) => Promise<T | null>;
};

/** Changes only on transitions: first load, an outage starting or ending, a mutation. */
export type CogwheelStatus = {
  phase: LoadPhase;
  /** Set when the most recent attempt failed; on-screen data may be last-known. */
  error: string | null;
  /** True when at least one field on screen is older than the last poll attempt. */
  stale: boolean;
  busy: string | null;
  /** False until the first successful answer; "Unreachable" means never, not once. */
  connected: boolean;
  /** The upstream resolver has failed most lookups sent to it in the last minute. */
  upstreamFailing: boolean;
};

export const CogwheelActionsContext = createContext<CogwheelActions | null>(null);
export const CogwheelStatusContext = createContext<CogwheelStatus | null>(null);

function required<T>(value: T | null | undefined, hook: string): T {
  if (value === null || value === undefined) throw new Error(`${hook} must be used inside <CogwheelProvider>`);
  return value;
}

/** The verbs (reload, refresh, patch, mutate). Never re-renders on its own. */
export function useCogwheelActions(): Omit<CogwheelActions, "store" | "freshness"> {
  const { reload, refresh, patch, mutate } = required(useContext(CogwheelActionsContext), "useCogwheelActions");
  return { reload, refresh, patch, mutate };
}

/** Load phase, error, staleness, busy key. Re-renders only on transitions. */
export function useCogwheelStatus(): CogwheelStatus {
  return required(useContext(CogwheelStatusContext), "useCogwheelStatus");
}

/**
 * When the last successful poll landed, in ms. Moves every five seconds, so
 * only the component that prints it should read it; nothing else — not even
 * the provider — re-renders when it moves.
 */
export function useLastUpdatedAt(): number | null {
  const { freshness } = required(useContext(CogwheelActionsContext), "useLastUpdatedAt");
  return useSyncExternalStore(freshness.subscribe, freshness.get);
}

/**
 * One field of the snapshot, re-rendering only when that field changes.
 * `useSnapshot("devices")` on the Devices page does not re-render when the
 * overview counters tick.
 */
export function useSnapshot<K extends keyof ControlPlaneSnapshot>(field: K): ControlPlaneSnapshot[K] {
  const { store } = required(useContext(CogwheelActionsContext), "useSnapshot");
  return useSyncExternalStore(store.subscribe, () => store.get()[field]);
}
