"use client";

import React from "react";
import { Button, type ButtonProps } from "@/components/ui/button";
import { Tooltip, TooltipContent } from "@/components/ui/tooltip";

type Placement = "top" | "bottom" | "left" | "right";

/**
 * A tooltip that costs nothing until it is wanted.
 *
 * DESIGN.md §7 asks for a tooltip on every icon-only button, and the obvious
 * way to give one — `<Tooltip><TooltipTrigger asChild>` around the button —
 * starts a tooltip state machine per instance. On Activity that is one per
 * row, two hundred of them, to show a word to the one row the pointer is on.
 *
 * So the trigger stays a plain element and the Ark tooltip is mounted beside
 * it only while it is showing, pointed at the trigger through `ids.trigger`
 * for positioning. Nothing is re-parented, so the trigger never remounts and
 * never loses focus. It opens on mouse hover and on keyboard focus, never on
 * touch (there is nothing to hover with, and a tap is the action), and closes
 * on leave, blur, Escape and press.
 */
function useLazyTooltip({
  id,
  label,
  placement = "top",
  disabled = false,
}: {
  id?: string;
  label: string;
  placement?: Placement;
  disabled?: boolean;
}) {
  const generated = React.useId();
  const triggerId = id ?? `tip-${generated}`;
  const [open, setOpen] = React.useState(false);

  const show = React.useCallback(() => {
    if (!disabled) setOpen(true);
  }, [disabled]);
  const hide = React.useCallback(() => setOpen(false), []);

  const triggerProps = {
    id: triggerId,
    onPointerEnter: (event: React.PointerEvent) => {
      if (event.pointerType === "mouse") show();
    },
    onPointerLeave: hide,
    onPointerDown: hide,
    onFocus: (event: React.FocusEvent<HTMLElement>) => {
      // Keyboard focus only. A click focuses the button too, and a tooltip
      // that then sits on top of the menu or dialog it opened is in the way.
      if (event.currentTarget.matches(":focus-visible")) show();
    },
    onBlur: hide,
    onKeyDown: (event: React.KeyboardEvent) => {
      if (event.key === "Escape") hide();
    },
  };

  const tooltip =
    open && !disabled ? (
      <Tooltip
        ids={{ trigger: triggerId }}
        onOpenChange={(details: { open: boolean }) => {
          if (!details.open) hide();
        }}
        open
        positioning={{ placement }}
      >
        <TooltipContent>{label}</TooltipContent>
      </Tooltip>
    ) : null;

  return { triggerProps, tooltip, open, hide };
}

/** Composes a handler the caller passed with the tooltip's own. */
function chain<E>(ours: (event: E) => void, theirs?: (event: E) => void) {
  return (event: E) => {
    theirs?.(event);
    ours(event);
  };
}

export interface IconButtonProps extends Omit<ButtonProps, "aria-label"> {
  /** The accessible name, and the tooltip's text unless `tooltip` is given. */
  label: string;
  /** Tooltip text when it should say more than the name, e.g. a countdown. */
  tooltip?: string;
  /** Where the tooltip sits. Rail buttons want `right`. */
  tooltipPlacement?: Placement;
}

/**
 * An icon-only button: a name for assistive technology and a tooltip for
 * everyone else, per DESIGN.md §7. Use it for every button whose visible
 * content is a glyph. Defaults to the ghost, 32px icon size the app uses for
 * row actions; any Button prop overrides.
 */
export function IconButton(props: IconButtonProps) {
  const {
    label,
    tooltip,
    tooltipPlacement = "top",
    id,
    size = "icon-md",
    variant = "ghost",
    onPointerEnter,
    onPointerLeave,
    onPointerDown,
    onFocus,
    onBlur,
    onKeyDown,
    children,
    ...rest
  } = props;

  const tip = useLazyTooltip({ id, label: tooltip ?? label, placement: tooltipPlacement });

  return (
    <>
      <Button
        aria-label={label}
        size={size}
        variant={variant}
        {...rest}
        id={tip.triggerProps.id}
        onBlur={chain(tip.triggerProps.onBlur, onBlur)}
        onFocus={chain(tip.triggerProps.onFocus, onFocus)}
        onKeyDown={chain(tip.triggerProps.onKeyDown, onKeyDown)}
        onPointerDown={chain(tip.triggerProps.onPointerDown, onPointerDown)}
        onPointerEnter={chain(tip.triggerProps.onPointerEnter, onPointerEnter)}
        onPointerLeave={chain(tip.triggerProps.onPointerLeave, onPointerLeave)}
      >
        {children}
      </Button>
      {tip.tooltip}
    </>
  );
}
