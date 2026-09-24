import React from "react";
import { api } from "@/lib/api";
import { useCogwheelActions } from "@/data/context";

/**
 * Pause and resume. Reads the verbs only, so a component that pauses does not
 * re-render when the overview moves.
 */
export function useProtectionActions() {
  const { mutate } = useCogwheelActions();

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
