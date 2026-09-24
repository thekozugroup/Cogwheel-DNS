import React from "react";
import { useCogwheelStatus, useSnapshot } from "@/data/context";
import { emptyOverview } from "@/lib/constants";
import { pauseSecondsRemaining, protectionState } from "@/lib/derive";

/** Seconds left on a pause, re-rendering once a second only while one runs. */
function useCountdown(pausedUntil: number | null): number {
  const [now, setNow] = React.useState(() => Date.now());

  React.useEffect(() => {
    if (!pausedUntil) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [pausedUntil]);

  return pauseSecondsRemaining(pausedUntil, now);
}

/**
 * The protection state, the pause countdown and the enabled-list count, read
 * from the overview field only so the rest of the snapshot does not wake it.
 */
export function useProtectionSummary() {
  const overview = useSnapshot("overview");
  const { error, connected, upstreamFailing } = useCogwheelStatus();
  const pausedUntil = overview.protection.paused_until;
  const remaining = useCountdown(pausedUntil);
  // "Unreachable" means there has never been an answer, not that one poll
  // missed; a single failed poll is the stale banner's job.
  const offline = Boolean(error) && !connected;
  // The empty default is the only overview that has never been loaded, from
  // the network or the cache: nothing it says is true yet.
  const known = overview !== emptyOverview;
  const { lists, last_24h: day } = overview;
  const state = protectionState({
    pausedUntil,
    offline,
    upstreamFailing,
    day: known
      ? { enabled: lists.enabled, total: lists.total, downloaded: lists.downloaded, queries: day.queries }
      : undefined,
  });
  const paused = state.paused && remaining > 0;

  return { state, paused, remaining, known, offline, listsEnabled: lists.enabled };
}
