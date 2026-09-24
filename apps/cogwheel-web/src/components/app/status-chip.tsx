import type React from "react";
import { cn } from "@/lib/utils";
import { Status } from "@/components/ui/status";
import type { Tone } from "@/components/app/status-indicator";

const TONE: Record<Tone, { variant: "success" | "warning" | "destructive" | "default"; word: string }> = {
  good: { variant: "success", word: "OK" },
  warn: { variant: "warning", word: "Warning" },
  bad: { variant: "destructive", word: "Problem" },
  idle: { variant: "default", word: "Idle" },
};

/**
 * A state that has to be seen from anywhere: a 400 dot, the words in
 * --foreground, a hairline pill, and optionally the one action that ends the
 * state sitting beside it. The top bar's "Paused · 12:31 left · Resume" is
 * the reason it exists.
 *
 * StatusPill's larger sibling. A pill is a table cell's label, 24px, one or
 * two words; a chip is chrome, 32px, and its label can carry live values (a
 * countdown), so it takes nodes. Same rule as the pill: never a dot alone —
 * the accessible name leads with the tone in words.
 */
export function StatusChip({
  tone,
  children,
  action,
  className,
}: {
  tone: Tone;
  /** The state in words. Put changing numbers in a `tabular` span. */
  children: React.ReactNode;
  /** The control that ends the state, e.g. a Resume button. */
  action?: React.ReactNode;
  className?: string;
}) {
  const { variant, word } = TONE[tone];

  return (
    <span className={cn("inline-flex min-w-0 items-center gap-2", className)}>
      <span
        className={cn(
          // As tall as the Resume beside it: 32px, or 44px on a touch screen,
          // where the button grows to its target size and the chip did not.
          "inline-flex h-8 min-w-0 items-center gap-2 rounded-full border border-border bg-card px-3 pointer-coarse:h-11",
          "whitespace-nowrap font-medium text-foreground text-sm",
        )}
      >
        <Status size="sm" variant={variant} />
        {/* One inline run, so the gap between dot and words does not also
            open up between "Paused ·", the countdown and "left". */}
        <span className="min-w-0 truncate">
          <span className="sr-only">{word}: </span>
          {children}
        </span>
      </span>
      {action}
    </span>
  );
}
