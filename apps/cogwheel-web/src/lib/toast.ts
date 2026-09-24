import { toast } from "@/components/ui/toast";

/**
 * Thin wrapper over Shark's toaster so every call site uses the same tone
 * vocabulary and every mutation reports both outcomes.
 */
export type ToastAction = { label: string; onClick: () => void };

export const notify = {
  /** With an action ("Undo"), the toast stays twice as long, so the action can be reached. */
  success(title: string, description?: string, action?: ToastAction) {
    toast.create({ title, description, type: "success", action, duration: action ? 10_000 : undefined });
  },
  error(title: string, description?: string) {
    toast.create({ title, description, type: "error", duration: 8_000 });
  },
  warning(title: string, description?: string) {
    toast.create({ title, description, type: "warning" });
  },
  info(title: string, description?: string) {
    toast.create({ title, description, type: "info" });
  },
};
