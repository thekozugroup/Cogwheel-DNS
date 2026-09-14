"use client";

import { ark } from "@ark-ui/react/factory";
import type React from "react";
import { tv, type VariantProps } from "tailwind-variants";
import { cn } from "@/lib/utils";

const statusVariants = tv({
  base: [
    "shrink-0 rounded-full",
    "flex items-center justify-center",
    "font-medium text-[10px]",
    "ring-2 ring-background",
  ],
  variants: {
    /**
     * The dot itself is the §3.3 "Status dot" pattern — a 400 fill, always
     * paired with a text label by its callers. Any glyph placed inside sits on
     * a mid-luminance 400 surface that does not change between themes, so the
     * glyph colour must not change either: plain white on green-400 is
     * 1.60:1, while neutral-950 clears 6:1 on every accent here.
     */
    variant: {
      default: "bg-foreground text-background",
      success: "bg-success text-neutral-950",
      info: "bg-info text-neutral-950",
      warning: "bg-warning text-neutral-950",
      destructive: "bg-destructive text-neutral-950",
    },
    size: {
      sm: "size-2 [&_svg:not([class*='size-'])]:size-1.5 [&_svg]:pointer-events-none [&_svg]:shrink-0",
      md: "size-2.5 [&_svg:not([class*='size-'])]:size-2 [&_svg]:pointer-events-none [&_svg]:shrink-0",
      lg: "size-3 [&_svg:not([class*='size-'])]:size-2.5 [&_svg]:pointer-events-none [&_svg]:shrink-0",
    },
  },
  defaultVariants: {
    variant: "default",
    size: "md",
  },
});

interface StatusProps
  extends React.ComponentProps<typeof ark.span>,
    VariantProps<typeof statusVariants> {}

export const Status = (props: StatusProps) => {
  const { variant, size, className, ...rest } = props;

  return (
    <ark.span
      aria-hidden="true"
      className={cn(statusVariants({ variant, size }), className)}
      data-size={size}
      data-slot="status-indicator"
      {...rest}
    />
  );
};
