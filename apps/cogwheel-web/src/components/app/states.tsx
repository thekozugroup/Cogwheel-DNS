import type React from "react";
import { RotateCwIcon, TriangleAlertIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
}: {
  icon: React.ElementType;
  title: string;
  description: string;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    // No box of its own. It always sits inside a section card, and the card is
    // the container: a dashed border inside the card's border was a second
    // frame around nothing.
    <div className={cn("flex flex-col items-center justify-center gap-3 px-gutter py-10 text-center", className)}>
      <Icon aria-hidden className="size-5 text-muted-foreground" />
      <div className="space-y-1">
        <p className="font-medium text-foreground text-sm">{title}</p>
        <p className="mx-auto max-w-md text-muted-foreground text-sm">{description}</p>
      </div>
      {action}
    </div>
  );
}

export function ErrorState({
  title,
  detail,
  onRetry,
  className,
}: {
  title: string;
  detail?: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      className={cn(
        // Tint + 700-weight text: the accent is the surface, never the copy.
        "flex flex-col gap-3 rounded-xl border border-destructive/24",
        "bg-destructive/8 px-[16px] py-[12px]",
        className,
      )}
      role="alert"
    >
      <div className="flex items-start gap-2">
        <TriangleAlertIcon aria-hidden className="mt-0.5 size-4 shrink-0 text-destructive-foreground" />
        <div className="min-w-0 space-y-1">
          <p className="font-medium text-destructive-foreground text-sm">{title}</p>
          {detail ? <p className="break-words text-foreground/80 text-sm">{detail}</p> : null}
        </div>
      </div>
      {onRetry ? (
        <div>
          <Button onClick={onRetry} size="sm" variant="outline">
            <RotateCwIcon aria-hidden />
            Try again
          </Button>
        </div>
      ) : null}
    </div>
  );
}

export function LoadingSkeleton({
  rows = 4,
  variant = "table",
  className,
}: {
  rows?: number;
  variant?: "table" | "cards" | "text";
  className?: string;
}) {
  const keys = Array.from({ length: rows }, (_, index) => `skeleton-${variant}-${index}`);

  if (variant === "cards") {
    // The same container-query grid as Overview's tiles, so the columns do not
    // jump from two to one (320px, or 200% text) when the numbers arrive.
    return (
      <div aria-busy="true" aria-label="Loading" className={cn("@container", className)}>
        <div className="grid grid-cols-1 gap-gutter @2xs:grid-cols-2 @3xl:grid-cols-4">
          {keys.map((key) => (
            <div className="rounded-xl border border-border p-gutter" key={key}>
              <Skeleton className="h-3 w-24" />
              <Skeleton className="mt-3 h-7 w-20" />
              <Skeleton className="mt-3 h-3 w-32" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  if (variant === "text") {
    return (
      <div aria-busy="true" aria-label="Loading" className={cn("space-y-2", className)}>
        {keys.map((key) => (
          <Skeleton className="h-4 w-full last:w-2/3" key={key} />
        ))}
      </div>
    );
  }

  return (
    <div aria-busy="true" aria-label="Loading" className={cn("space-y-2", className)}>
      <Skeleton className="h-8 w-full" />
      {keys.map((key) => (
        <Skeleton className="h-10 w-full" key={key} />
      ))}
    </div>
  );
}

/** Banner for degraded-but-usable states, e.g. a failed poll over cached data. */
export function NoticeBanner({
  tone = "warn",
  title,
  detail,
  actions,
  className,
}: {
  tone?: "warn" | "bad" | "neutral";
  title: string;
  detail?: string;
  actions?: React.ReactNode;
  className?: string;
}) {
  // Tone is carried by the surface tint and the border, not by a coloured rule
  // down one edge. The strip read as decoration rather than information.
  const toneClass =
    tone === "bad"
      ? "border-destructive/24 bg-destructive/8 text-destructive-foreground"
      : tone === "warn"
        ? "border-warning/32 bg-warning/10 text-warning-foreground"
        : "border-border bg-muted text-foreground";

  return (
    <div
      className={cn(
        "flex flex-col gap-2 rounded-xl border px-[16px] py-[12px] sm:flex-row sm:items-center sm:justify-between",
        toneClass,
        className,
      )}
      role="status"
    >
      <div className="min-w-0">
        <p className="font-medium text-sm">{title}</p>
        {detail ? <p className="text-foreground/80 text-sm">{detail}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2 sm:shrink-0">{actions}</div> : null}
    </div>
  );
}
