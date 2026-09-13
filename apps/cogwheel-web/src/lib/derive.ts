import type { DashboardSummary } from "@/lib/api";
import type { Tone } from "@/components/app/status-indicator";

export type ProtectionState = {
  tone: Tone;
  label: string;
  detail: string;
  paused: boolean;
};

/**
 * `protection_status` is derived server-side as Paused / Protected. Anything
 * else (including the "Loading" placeholder) is treated as unknown rather than
 * guessed at.
 */
export function protectionState(dashboard: DashboardSummary, offline: boolean): ProtectionState {
  if (offline) {
    return {
      tone: "bad",
      label: "Unreachable",
      detail: "The control plane did not answer. Filtering may still be running on the appliance.",
      paused: false,
    };
  }

  switch (dashboard.protection_status) {
    case "Paused":
      return {
        tone: "warn",
        label: "Paused",
        detail: "Blocking is suspended until the snooze expires.",
        paused: true,
      };
    case "Protected":
      return {
        tone: "good",
        label: "Protected",
        detail: "Filtering is active.",
        paused: false,
      };
    default:
      return {
        tone: "idle",
        label: "Unknown",
        detail: "Waiting for the first response from the control plane.",
        paused: false,
      };
  }
}

/** Seconds left on the pause window, or 0 when protection is not paused. */
export function pauseSecondsRemaining(dashboard: DashboardSummary, now = Date.now()): number {
  if (!dashboard.protection_paused_until) return 0;
  const until = new Date(dashboard.protection_paused_until).getTime();
  if (Number.isNaN(until)) return 0;
  return Math.max(0, Math.round((until - now) / 1000));
}

export function blockedRatio(dashboard: DashboardSummary): number {
  const { queries_total, blocked_total } = dashboard.runtime;
  if (queries_total <= 0) return 0;
  return blocked_total / queries_total;
}

export function splitDomainList(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

export function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}
