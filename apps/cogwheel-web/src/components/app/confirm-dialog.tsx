import React from "react";
import {
  AlertDialog,
  AlertDialogBody,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * Guard for anything irreversible. `description` must name the exact target —
 * "Delete OISD Big" reads very differently from "Delete this item" when the
 * wrong row is selected.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  tone = "neutral",
  consequence,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  /**
   * The state the appliance will be in afterwards, which colours the
   * consequence line: `bad` for what is lost (a deleted list, a cleared log),
   * `warn` for what is degraded (a pause, a device left with no list), and
   * `neutral` for the rest. The pause said red for a state that is yellow
   * everywhere else in the product.
   */
  tone?: "bad" | "warn" | "neutral";
  /** Extra line spelling out what changes on the appliance. */
  consequence?: string;
  onConfirm: () => void | Promise<void>;
}) {
  const [working, setWorking] = React.useState(false);

  const confirm = async () => {
    setWorking(true);
    try {
      await onConfirm();
      onOpenChange(false);
    } finally {
      setWorking(false);
    }
  };

  return (
    <AlertDialog
      onOpenChange={(details) => {
        if (!working) onOpenChange(details.open);
      }}
      open={open}
    >
      <AlertDialogContent size="sm">
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        {consequence ? (
          <AlertDialogBody>
            {/* The §3.3 tint, not free-floating red prose. Sixty words of
                untinted red-700 was the largest chromatic mass in the product
                and the only place red appeared as text rather than as a dot;
                inside a tinted aside the same sentence reads as marked out
                rather than as an alarm. The description above stays plain, and
                this line carries only what the description does not. */}
            <p
              className={cn(
                "rounded-xl border px-3 py-3 text-sm",
                tone === "bad"
                  ? "border-destructive/24 bg-destructive/8 text-destructive-foreground"
                  : tone === "warn"
                    ? "border-warning/32 bg-warning/10 text-warning-foreground"
                    : "border-border bg-muted text-foreground",
              )}
            >
              {consequence}
            </p>
          </AlertDialogBody>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={working}>Cancel</AlertDialogCancel>
          <Button isLoading={working} onClick={confirm}>
            {confirmLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
