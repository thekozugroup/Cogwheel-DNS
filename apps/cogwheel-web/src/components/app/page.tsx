import type React from "react";
import { cn } from "@/lib/utils";

/**
 * The 1200px column and its page padding: the 24px gutter on a phone, 32–40px
 * wider. In pixels like the gutter itself, so 200% text gets the room rather
 * than the margins (DESIGN.md §5).
 */
export function PageShell({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "mx-auto w-full max-w-[1200px] px-gutter py-gutter sm:px-[32px] lg:px-[40px] lg:py-[32px]",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** The one gutter, 24px, between the cards of a page (DESIGN.md §5). */
export function PageSections({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("flex flex-col gap-gutter", className)}>{children}</div>;
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <header className="mb-gutter flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-gutter">
      <div className="min-w-0">
        <h1 className="display-tight font-semibold text-2xl text-foreground">{title}</h1>
        {description ? (
          <p className="mt-1 max-w-2xl text-muted-foreground text-sm">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}
