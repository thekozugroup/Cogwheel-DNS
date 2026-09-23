import React from "react";
import { PauseIcon, PlayIcon } from "lucide-react";
import { useCogwheel } from "@/data/context";
import { protectionState } from "@/lib/derive";
import { formatDuration } from "@/lib/format";
import { PAUSE_OPTIONS } from "@/lib/constants";
import { usePauseCountdown, useProtectionActions } from "@/hooks/use-protection";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/app/confirm-dialog";

/**
 * Pausing lives in the sidebar footer because it is the one control whose state
 * a person needs to see from every screen — a silently-paused appliance is the
 * failure mode this whole product has to avoid.
 *
 * One verb throughout: the tile says Paused, the route is `/runtime/pause`, the
 * toast says "Protection paused", and so does this. "Snooze" was a second name
 * for the same thing and read, beside them, as a second feature.
 */
export function PauseControl() {
  const { data, busy, error, lastUpdatedAt } = useCogwheel();
  const { pause, resume } = useProtectionActions();
  const remaining = usePauseCountdown();
  const [pending, setPending] = React.useState<number | null>(null);

  const state = protectionState(data.overview.protection.paused_until, Boolean(error) && lastUpdatedAt === null);
  const pausing = busy === "pause-runtime";
  const resuming = busy === "resume-runtime";

  if (state.paused && remaining > 0) {
    return (
      <div className="flex flex-col gap-2 rounded-lg border border-warning/40 bg-warning/10 p-2">
        <p className="font-medium text-foreground text-xs">
          Paused · <span className="tabular">{formatDuration(remaining)}</span> left
        </p>
        <Button
          className="w-full"
          isLoading={resuming}
          onClick={() => void resume()}
          size="sm"
          variant="outline"
        >
          <PlayIcon aria-hidden />
          Resume protection
        </Button>
      </div>
    );
  }

  return (
    <>
      <div className="flex flex-col gap-2">
        <p className="text-muted-foreground text-xs">Pause protection</p>
        <div className="flex gap-1">
          {PAUSE_OPTIONS.map((minutes) => (
            <Button
              className="flex-1"
              disabled={pausing}
              key={minutes}
              onClick={() => setPending(minutes)}
              size="sm"
              title={`Pause blocking for ${minutes} minutes`}
              variant="outline"
            >
              <PauseIcon aria-hidden />
              {minutes}m
            </Button>
          ))}
        </div>
      </div>

      {/* The description says what happens; the consequence says only what the
          description does not. They used to say the same thing twice. */}
      <ConfirmDialog
        confirmLabel={`Pause for ${pending ?? 0} minutes`}
        consequence="The pause is stored on the appliance, so restarting it does not end the pause early."
        description={`Blocking stops for ${pending ?? 0} minutes across the whole network, not just this browser. Every device resolves unfiltered until it expires or you resume.`}
        destructive
        onConfirm={async () => {
          if (pending !== null) await pause(pending);
        }}
        onOpenChange={(open) => {
          if (!open) setPending(null);
        }}
        open={pending !== null}
        title="Pause protection?"
      />
    </>
  );
}
