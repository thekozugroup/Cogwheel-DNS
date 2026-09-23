import type React from "react";
import { cn } from "@/lib/utils";
import { Status } from "@/components/ui/status";
import type { Tone } from "@/components/app/status-indicator";

const DOT: Record<Exclude<Tone, "idle"> | "neutral", "success" | "warning" | "destructive" | "default"> = {
  good: "success",
  warn: "warning",
  bad: "destructive",
  neutral: "default",
};

export type StatTone = "neutral" | "good" | "warn" | "bad";

export function StatTile({
  label,
  value,
  delta,
  tone = "neutral",
  toneLabel,
  hint,
  footer,
  className,
  variant = "metric",
}: {
  label: string;
  value: React.ReactNode;
  /** Nodes are allowed so a tile can link onward without a second row. */
  delta?: React.ReactNode;
  tone?: StatTone;
  /**
   * The word behind the dot. Omit it when the tile's own value already says the
   * same thing — "PROTECTION / ● Protected / Protected" is one state written
   * three times.
   */
  toneLabel?: string;
  hint?: React.ReactNode;
  footer?: React.ReactNode;
  className?: string;
  /**
   * `state` is for a tile whose value is a word, not a quantity. Protection
   * sat in a row of three numerals with "Protected" set at 24px/600 as though
   * it were one of them; a state reads as a status line with the dot in front
   * of it, which is what it is.
   */
  variant?: "metric" | "state";
}) {
  const state = variant === "state";

  return (
    <div className={cn("flex flex-col rounded-xl border border-border bg-card p-4", className)}>
      {/* Sentence case, normal tracking. These labels were the only uppercase
          letter-spaced text in the product. */}
      <div className="flex items-center justify-between gap-2">
        <p className="font-medium text-muted-foreground text-xs">{label}</p>
        {state || tone === "neutral" ? null : (
          <span className="flex items-center gap-2 text-foreground text-xs">
            <Status size="sm" variant={DOT[tone]} />
            {toneLabel}
          </span>
        )}
      </div>

      {state ? (
        <p className="mt-2 flex items-center gap-2 font-semibold text-base text-foreground">
          {tone === "neutral" ? null : <Status size="sm" variant={DOT[tone]} />}
          {value}
        </p>
      ) : (
        <p className="display-tight tabular mt-2 font-semibold text-2xl text-foreground">{value}</p>
      )}

      {delta ? <p className="tabular mt-1 text-muted-foreground text-sm">{delta}</p> : null}
      {hint ? <p className="mt-1 text-muted-foreground text-sm">{hint}</p> : null}
      {footer ? <div className="mt-3">{footer}</div> : null}
    </div>
  );
}
