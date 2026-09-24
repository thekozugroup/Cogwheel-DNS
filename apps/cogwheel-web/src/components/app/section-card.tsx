import React from "react";
import { cn } from "@/lib/utils";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function SectionCard({
  title,
  description,
  actions,
  footer,
  children,
  className,
  contentClassName,
  id,
  busy = false,
  headingLevel = 2,
}: {
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  footer?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  contentClassName?: string;
  id?: string;
  /**
   * Draws a 2px indeterminate rule under the header. For work that changes
   * several rows at once and can take tens of seconds — refreshing every list —
   * where a spinner inside one 28px icon button is not visible from the card.
   */
  busy?: boolean;
  /**
   * The title is a real heading: h2 under the page's h1. Pass 3 only for a
   * card that genuinely sits under another card's h2 — the outline is how a
   * screen-reader user skims a page, and every page used to have one h1 and
   * nothing under it, because CardTitle renders a div.
   */
  headingLevel?: 2 | 3;
}) {
  const titleId = React.useId();
  const Heading = headingLevel === 3 ? "h3" : "h2";

  return (
    <Card
      aria-busy={busy || undefined}
      className={cn("@container/card shadow-none", className)}
      id={id}
    >
      {/* Where the card is narrow, the actions go under the title rather than
          beside it. Narrow by the card's own width, in rem, not the window's:
          at 375px the action row was wider than what was left of the card, and
          at 1024px with 200% text a desktop window held a 380px card whose
          title was squeezed to "Activity / log" while "Show the variable
          names" ran past its edge. */}
      <CardHeader className="@max-md/card:grid-cols-1!">
        <CardTitle asChild className="text-base">
          <Heading id={titleId}>{title}</Heading>
        </CardTitle>
        {description ? <CardDescription>{description}</CardDescription> : null}
        {actions ? (
          <CardAction className="flex max-w-full flex-wrap items-center justify-end gap-2 @max-md/card:col-start-1 @max-md/card:row-span-1 @max-md/card:row-start-3 @max-md/card:mt-2 @max-md/card:justify-self-start @max-md/card:justify-start">
            {actions}
          </CardAction>
        ) : null}
      </CardHeader>
      {busy ? <BusyRule /> : null}
      <CardContent className={cn("min-w-0", contentClassName)}>{children}</CardContent>
      {footer ? <CardFooter className="flex-wrap">{footer}</CardFooter> : null}
    </Card>
  );
}

/**
 * The indeterminate rule. Its motion and its reduced-motion form live in
 * index.css (`.busy-rule`): a sliding quarter-bar normally, and under reduced
 * motion the whole track pulsing in opacity, so that it never stops as a
 * quarter-width bar that reads as "25% done".
 */
function BusyRule() {
  return (
    <div aria-hidden className="mx-(--space) h-0.5 overflow-hidden rounded-full bg-muted">
      <div className="busy-rule h-full rounded-full bg-foreground/60" />
    </div>
  );
}
