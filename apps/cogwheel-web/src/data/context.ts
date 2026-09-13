import { createContext, useContext } from "react";
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
};

export type CogwheelContextValue = {
  data: ControlPlaneSnapshot;
  phase: LoadPhase;
  /** Set when the most recent attempt failed; on-screen data may be last-known. */
  error: string | null;
  /** True when at least one field on screen is older than the last poll attempt. */
  stale: boolean;
  lastUpdatedAt: number | null;
  busy: string | null;
  reload: () => Promise<void>;
  refresh: () => Promise<void>;
  patch: (partial: Partial<ControlPlaneSnapshot>) => void;
  mutate: <T>(options: MutationOptions<T>) => Promise<T | null>;
};

export const CogwheelContext = createContext<CogwheelContextValue | null>(null);

export function useCogwheel(): CogwheelContextValue {
  const value = useContext(CogwheelContext);
  if (!value) throw new Error("useCogwheel must be used inside <CogwheelProvider>");
  return value;
}
