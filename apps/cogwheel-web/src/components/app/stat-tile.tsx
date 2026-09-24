import type React from "react";
import { cn } from "@/lib/utils";

/**
 * One number with its label and a line or two of context. The tile's inset is
 * the gutter, the same as every card's: at 16px the tiles' text started 8px
 * left of the card under them, two left edges down one column.
 */
export function StatTile({
  label,
  value,
  delta,
  hint,
  className,
}: {
  label: string;
  value: React.ReactNode;
  /** Nodes are allowed so a tile can link onward without a second row. */
  delta?: React.ReactNode;
  hint?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col rounded-xl border border-border bg-card p-gutter", className)}>
      {/* Sentence case, normal tracking. These labels were the only uppercase
          letter-spaced text in the product. */}
      <p className="font-medium text-muted-foreground text-xs">{label}</p>
      <p className="display-tight tabular mt-2 font-semibold text-2xl text-foreground">{value}</p>
      {delta ? <p className="tabular mt-1 text-muted-foreground text-sm">{delta}</p> : null}
      {hint ? <p className="mt-1 text-muted-foreground text-sm">{hint}</p> : null}
    </div>
  );
}
