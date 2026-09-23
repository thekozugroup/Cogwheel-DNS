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
  destructive = false,
  consequence,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  destructive?: boolean;
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
                destructive
                  ? "border-destructive/24 bg-destructive/8 text-destructive-foreground"
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
