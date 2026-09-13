import React from "react";
import { api } from "@/lib/api";
import { pauseSecondsRemaining } from "@/lib/derive";
import { useCogwheel } from "@/data/context";

/** Ticks once a second only while a pause window is actually open. */
export function usePauseCountdown(): number {
  const { data } = useCogwheel();
  const [now, setNow] = React.useState(() => Date.now());
  const remaining = pauseSecondsRemaining(data.dashboard, now);

  React.useEffect(() => {
    if (!data.dashboard.protection_paused_until) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, [data.dashboard.protection_paused_until]);

  return remaining;
}

export function useProtectionActions() {
  const { mutate } = useCogwheel();

  const pause = React.useCallback(
    (minutes: number) =>
      mutate({
        key: "pause-runtime",
        action: () => api.pauseRuntime(minutes),
        successTitle: "Protection paused",
        successDetail: `Blocking is suspended for ${minutes} minutes.`,
        failureTitle: "Could not pause protection",
      }),
    [mutate],
  );

  const resume = React.useCallback(
    () =>
      mutate({
        key: "resume-runtime",
        action: () => api.resumeRuntime(),
        successTitle: "Protection resumed",
        successDetail: "Blocking is active again.",
        failureTitle: "Could not resume protection",
      }),
    [mutate],
  );

  return { pause, resume };
}
