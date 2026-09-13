import { cn } from "@/lib/utils";
import { Status } from "@/components/ui/status";

export type Tone = "good" | "warn" | "bad" | "idle";

/**
 * Colour never carries meaning on its own here: every tone pairs a 400-weight
 * dot with a word, and the accessible name states the status in text.
 */
const TONE: Record<Tone, { variant: "success" | "warning" | "destructive" | "default"; word: string }> = {
  good: { variant: "success", word: "OK" },
  warn: { variant: "warning", word: "Warning" },
  bad: { variant: "destructive", word: "Problem" },
  idle: { variant: "default", word: "Idle" },
};

/**
 * The compact status used inside table rows: a bordered pill whose text sits in
 * `--foreground`, never in the 400 accent (which fails contrast on white).
 */
export function StatusPill({ tone, label, className }: { tone: Tone; label: string; className?: string }) {
  const { variant, word } = TONE[tone];

  return (
    <span
      className={cn(
        "inline-flex h-6 items-center gap-1.5 rounded-full border border-border px-2",
        "font-medium text-foreground text-xs",
        className,
      )}
    >
      <Status size="sm" variant={variant} />
      <span className="sr-only">{word}: </span>
      {label}
    </span>
  );
}
