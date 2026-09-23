import type React from "react";
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
}: {
  title: string;
  description?: string;
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
}) {
  return (
    <Card className={cn("shadow-none", className)} id={id}>
      {/* Below sm the action row is wider than what is left of a 375px card:
          it squeezed "Showing 50 of 200 rows held." into a five-line column and
          pushed Clear log off the edge. There, the actions go under the title. */}
      <CardHeader className="max-sm:grid-cols-1!">
        {/* The h1–h4 rule in index.css cannot reach this: CardTitle renders a
            div. Without the tracking a 16px card title is the one heading in
            the product set at letter-spacing: normal. */}
        <CardTitle className="-tracking-[0.011em] text-base">{title}</CardTitle>
        {description ? <CardDescription>{description}</CardDescription> : null}
        {actions ? (
          <CardAction className="flex flex-wrap items-center gap-2 max-sm:col-start-1 max-sm:row-span-1 max-sm:row-start-3 max-sm:mt-2 max-sm:justify-self-start">
            {actions}
          </CardAction>
        ) : null}
      </CardHeader>
      {busy ? (
        <div aria-hidden className="mx-(--space) h-0.5 overflow-hidden rounded-full bg-muted">
          <div className="h-full w-1/4 animate-indeterminate rounded-full bg-foreground/60" />
        </div>
      ) : null}
      <CardContent className={cn("min-w-0", contentClassName)}>{children}</CardContent>
      {footer ? <CardFooter className="flex-wrap">{footer}</CardFooter> : null}
    </Card>
  );
}
