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
 *
 * A pill holds one or two words. It is floored rather than fixed at 24px and
 * capped in width so that a caller who hands it something longer gets a pill
 * that grows, not a sentence printed across the row above it — which is what a
 * failed list's error used to do at 375px, where `.stacked-value` forces
 * `overflow: visible`. Anything longer than a label belongs in prose, not here.
 */
export function StatusPill({ tone, label, className }: { tone: Tone; label: string; className?: string }) {
  const { variant, word } = TONE[tone];

  return (
    <span
      className={cn(
        "inline-flex min-h-6 max-w-56 items-center gap-2 rounded-full border border-border px-2 py-0.5",
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
