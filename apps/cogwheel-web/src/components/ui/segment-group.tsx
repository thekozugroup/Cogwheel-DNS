"use client";

import {
  SegmentGroup as ArkSegmentGroup,
} from "@ark-ui/react/segment-group";
import type React from "react";
import { cn } from "@/lib/utils";

type SegmentGroupVariant = "default" | "underline";

interface SegmentGroupProps
  extends React.ComponentProps<typeof ArkSegmentGroup.Root> {
  /**
   * The visual variant of the segment group.
   *
   * @default "default"
   */
  variant?: SegmentGroupVariant;
}

/**
 * A segmented control: the theme toggle, Activity's verdict filter.
 *
 * The chosen segment is painted on the item itself, inverted — the primary
 * surface with the primary foreground, the same black-on-white pair as the
 * primary button — and set in medium weight, while the others sit in
 * --muted-foreground. It used to be a sliding `bg-input` indicator at
 * 1.42–1.73:1 with the label unchanged, which asked a person to find the
 * slightly greyer of three boxes.
 *
 * There is no sliding indicator any more, for two reasons. It animated
 * left/top/width/height, a layout transition on every change; and with an
 * inverted fill the label has to turn white at the moment the fill arrives
 * under it, which a fill that travels for 150ms cannot promise. A colour
 * crossfade on the item says "this one now" with neither problem.
 */
export const SegmentGroup = (props: SegmentGroupProps) => {
  const {
    orientation = "horizontal",
    variant = "default",
    className,
    children,
    ...rest
  } = props;

  return (
    <ArkSegmentGroup.Root
      className={cn(
        "group/segment-group relative",
        "flex gap-0.5",
        "isolate",
        "data-[orientation=vertical]:flex-col",
        "data-disabled:opacity-64",
        "data-[variant=underline]:gap-1",
        "data-[orientation=horizontal]:data-[variant=underline]:border-b",
        "data-[orientation=vertical]:data-[variant=underline]:border-l",
        className,
        // Last, so a caller's `border-border` cannot undo it: the group's edge
        // is a control edge and takes the 3:1 --input token, not the 1.26:1
        // hairline cards use.
        "border-input"
      )}
      data-slot="segment-group"
      data-variant={variant}
      orientation={orientation}
      {...rest}
    >
      {children}
    </ArkSegmentGroup.Root>
  );
};

export const SegmentGroupItem = (
  props: React.ComponentProps<typeof ArkSegmentGroup.Item>
) => {
  const { className, children, ...rest } = props;

  return (
    <ArkSegmentGroup.Item
      className={cn(
        "relative",
        "inline-flex items-center justify-center",
        "cursor-pointer select-none",
        "data-[orientation=vertical]:w-full data-[orientation=vertical]:justify-start",
        "rounded-[calc(var(--radius-lg)-3px)]",
        "text-muted-foreground",
        "transition-[color,background-color] duration-150",
        "hover:bg-accent hover:text-foreground",
        "data-[state=checked]:bg-primary data-[state=checked]:font-medium data-[state=checked]:text-primary-foreground",
        "data-[state=checked]:hover:bg-primary",
        // Underline variant: the chosen item is marked by a 2px foreground rule
        // along the group's edge instead of an inverted fill.
        "group-data-[variant=underline]/segment-group:rounded-none",
        "group-data-[variant=underline]/segment-group:data-[state=checked]:bg-transparent",
        "group-data-[variant=underline]/segment-group:data-[state=checked]:text-foreground",
        "group-data-[variant=underline]/segment-group:data-[state=checked]:shadow-[inset_0_-2px_0_var(--foreground)]",
        // The focusable element is Ark's visually hidden radio, so the ring the
        // global :focus-visible rule would draw lands on a 1px box. Ark mirrors
        // keyboard focus onto the item as data-focus-visible.
        "data-focus-visible:outline-2 data-focus-visible:outline-offset-2 data-focus-visible:outline-ring",
        "data-disabled:pointer-events-none data-disabled:opacity-64",
        "motion-reduce:transition-none!",
        className
      )}
      data-slot="segment-group-item"
      {...rest}
    >
      {children}

      <ArkSegmentGroup.ItemControl />
      <ArkSegmentGroup.ItemHiddenInput />
    </ArkSegmentGroup.Item>
  );
};

export const SegmentGroupItemText = (
  props: React.ComponentProps<typeof ArkSegmentGroup.ItemText>
) => {
  const { className, ...rest } = props;

  return (
    <ArkSegmentGroup.ItemText
      className={cn("relative", className)}
      data-slot="segment-group-item-text"
      {...rest}
    />
  );
};
