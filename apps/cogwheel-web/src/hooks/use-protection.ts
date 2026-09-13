import React from "react";
import { api } from "@/lib/api";
import { pauseSecondsRemaining } from "@/lib/derive";
import { useCogwheel } from "@/data/context";

/** Ticks once a second only while a pause window is actually open. */
export function usePauseCountdown(): number {
  const { data } = useCogwheel();
  const pausedUntil = data.overview.protection.paused_until;
  const [now, setNow] = React.useState(() => Date.now());

  React.useEffect(() => {
    if (!pausedUntil) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [pausedUntil]);

  return pauseSecondsRemaining(pausedUntil, now);
}

export function useProtectionActions() {
  const { mutate } = useCogwheel();

  const pause = React.useCallback(
    (minutes: number) =>
      mutate({
        key: "pause-runtime",
        action: () => api.pause(minutes),
        after: "light",
        successTitle: "Protection paused",
        successDetail: `Blocking is off for ${minutes} minutes.`,
        failureTitle: "Could not pause protection",
      }),
    [mutate],
  );

  const resume = React.useCallback(
    () =>
      mutate({
        key: "resume-runtime",
        action: () => api.resume(),
        after: "light",
        successTitle: "Protection resumed",
        successDetail: "Blocking is active again.",
        failureTitle: "Could not resume protection",
      }),
    [mutate],
  );

  return { pause, resume };
}
