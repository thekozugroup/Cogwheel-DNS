import React from "react";
import { PauseIcon, PlayIcon } from "lucide-react";
import { useCogwheelStatus } from "@/data/context";
import type { ProtectionState } from "@/lib/derive";
import { formatDuration, pluralize } from "@/lib/format";
import { PAUSE_OPTIONS } from "@/lib/constants";
import { useProtectionActions } from "@/hooks/use-protection";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { IconButton } from "@/components/ui/icon-button";
import { Status } from "@/components/ui/status";
import { useSidebar } from "@/components/ui/sidebar";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { RowMenu } from "@/components/app/row-menu";
import { StatusChip } from "@/components/app/status-chip";
import { useProtectionSummary } from "@/components/layout/protection-state";

/**
 * Protection, wherever the chrome is.
 *
 * A silently paused appliance is the failure this product exists to avoid, and
 * the only persistent readout used to be two sidebar rows that the icon rail
 * hid and a phone kept in a closed drawer. So there are now three forms of the
 * same state, and at every width one of them is on screen:
 *
 *   expanded sidebar   ProtectionPanel — the words, the lists behind them,
 *                      and the pause/resume control, under the nav
 *   icon rail          a dot on the mark tile, and ProtectionRailButton
 *   rail or phone      ProtectionChip in the top bar, whenever the state is
 *                      anything but Protected
 */

const DOT: Record<ProtectionState["tone"], "success" | "warning" | "destructive" | "default"> = {
  good: "success",
  warn: "warning",
  bad: "destructive",
  idle: "default",
};

/** "Paused · 12:31 left", with the numerals tabular so it does not jitter. */
function StateWords({ label, paused, remaining }: { label: string; paused: boolean; remaining: number }) {
  if (!paused) return <>{label}</>;
  return (
    <>
      {label} · <span className="tabular">{formatDuration(remaining)}</span> left
    </>
  );
}

/**
 * Asking before pausing, shared by the panel's buttons and the rail's menu.
 * Pausing stops filtering for every device on the network, so it is confirmed;
 * resuming is not, because it only puts things back.
 */
function usePauseConfirm() {
  const { pause } = useProtectionActions();
  const [pending, setPending] = React.useState<number | null>(null);

  // The description says what happens; the consequence says only what the
  // description does not. They used to say the same thing twice.
  const dialog = (
    <ConfirmDialog
      confirmLabel={`Pause for ${pending ?? 0} minutes`}
      consequence="The pause is stored on the appliance, so restarting it does not end the pause early."
      description={`Blocking stops for ${pending ?? 0} minutes across the whole network, not just this browser. Every device resolves unfiltered until it expires or you resume.`}
      tone="warn"
      onConfirm={async () => {
        if (pending !== null) await pause(pending);
      }}
      onOpenChange={(open) => {
        if (!open) setPending(null);
      }}
      open={pending !== null}
      title="Pause protection?"
    />
  );

  return { request: setPending, dialog };
}

/**
 * The expanded sidebar's protection block: the state in words with the lists
 * behind it, then the control that changes it. One block, no group label —
 * "Right now" used to head a group that held a single fact on Overview.
 *
 * One verb throughout: the tile says Paused, the route is `/runtime/pause`, the
 * toast says "Protection paused", and so does this.
 */
export function ProtectionPanel() {
  const { state, paused, remaining, known, offline, listsEnabled } = useProtectionSummary();
  const { resume } = useProtectionActions();
  const { busy } = useCogwheelStatus();
  const confirm = usePauseConfirm();
  const labelId = React.useId();

  if (paused) {
    // The one tinted block in the chrome, because this is the one state that
    // must not be missed: the §2 tint, text in --foreground.
    return (
      <div className="flex flex-col gap-2 rounded-lg border border-warning/40 bg-warning/10 p-2">
        <p className="flex items-center gap-2 font-medium text-foreground text-sm">
          <Status size="sm" variant="warning" />
          <span>
            <StateWords label={state.label} paused remaining={remaining} />
          </span>
        </p>
        <Button
          className="w-full"
          isLoading={busy === "resume-runtime"}
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
    <div className="flex flex-col gap-3">
      <p className="flex items-center gap-2 text-sm">
        <Status size="sm" variant={DOT[state.tone]} />
        <span className="font-medium text-foreground">{state.label}</span>
        {/* What the protection is made of, as a qualifier on the same line:
            "Protected" by nothing would be a different sentence. Only once
            the count is known and is not the reason for the state — beside
            "Unreachable" it said "0 lists", which nobody had counted. */}
        {known && listsEnabled > 0 ? (
          <span className="tabular ms-auto text-muted-foreground text-xs">{pluralize(listsEnabled, "list")}</span>
        ) : null}
      </p>

      {/* Not offered while the appliance is not answering: the pause could
          not be sent, and three buttons that can only fail are not a control. */}
      {offline ? null : (
        <div aria-labelledby={labelId} className="flex flex-col gap-2" role="group">
          <p className="text-muted-foreground text-xs" id={labelId}>
            Pause for
          </p>
          <div className="flex gap-1">
            {PAUSE_OPTIONS.map((minutes) => (
              <Button
                className="flex-1"
                disabled={busy === "pause-runtime"}
                key={minutes}
                onClick={() => confirm.request(minutes)}
                size="sm"
                variant="outline"
              >
                {minutes} min
              </Button>
            ))}
          </div>
        </div>
      )}

      {confirm.dialog}
    </div>
  );
}

/**
 * The icon rail's form: one button that does what the panel's control does.
 * Paused, it resumes, and its tooltip carries the countdown; otherwise it
 * opens the three durations, and each asks first like the panel's buttons.
 */
export function ProtectionRailButton() {
  const { state, paused, remaining, offline } = useProtectionSummary();
  const { resume } = useProtectionActions();
  const { busy } = useCogwheelStatus();
  const confirm = usePauseConfirm();

  // As in the panel: nothing to pause while the appliance is not answering.
  if (offline) return null;

  if (paused) {
    return (
      <IconButton
        isLoading={busy === "resume-runtime"}
        label="Resume protection"
        onClick={() => void resume()}
        tooltip={`Resume protection · ${formatDuration(remaining)} left`}
        tooltipPlacement="right"
        variant="outline"
      >
        <PlayIcon aria-hidden />
      </IconButton>
    );
  }

  return (
    <>
      <RowMenu
        actions={PAUSE_OPTIONS.map((minutes) => ({
          value: String(minutes),
          label: `Pause for ${minutes} minutes…`,
          disabled: busy === "pause-runtime",
        }))}
        icon={PauseIcon}
        label="Pause protection"
        onSelect={(value) => confirm.request(Number(value))}
        tooltip={`${state.label} · Pause protection`}
        tooltipPlacement="right"
      />
      {confirm.dialog}
    </>
  );
}

/** The dot on the mark tile in the icon rail. Words are in the tooltip and the link's name. */
export function ProtectionDot({ className }: { className?: string }) {
  const { state } = useProtectionSummary();
  return <Status className={cn("ring-2 ring-sidebar", className)} size="md" variant={DOT[state.tone]} />;
}

/**
 * The top bar's chip. Drawn only when the sidebar cannot say it — collapsed to
 * the rail, or a drawer on a phone — and only when the state is not the one
 * the household is supposed to be in: a chip reading "Protected" on every
 * screen would be chrome, and would teach people not to look at it.
 */
export function ProtectionChip() {
  const { isMobile, state: sidebar } = useSidebar();
  const { state, paused, remaining } = useProtectionSummary();
  const { resume } = useProtectionActions();
  const { busy } = useCogwheelStatus();

  // Only a state that needs a look: Protected is the household working, and
  // Ready or Checking are not something to act on either.
  const sidebarHidden = isMobile || sidebar === "collapsed";
  if (!sidebarHidden || (state.tone !== "warn" && state.tone !== "bad")) return null;

  return (
    <StatusChip
      action={
        paused ? (
          <Button isLoading={busy === "resume-runtime"} onClick={() => void resume()} size="sm" variant="outline">
            Resume
          </Button>
        ) : null
      }
      tone={state.tone}
    >
      <StateWords label={state.label} paused={paused} remaining={remaining} />
    </StatusChip>
  );
}
