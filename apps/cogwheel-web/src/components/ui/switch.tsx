"use client";

import { Switch as ArkSwitch } from "@ark-ui/react/switch";
import React from "react";
import { cn } from "@/lib/utils";

/**
 * The control that takes focus is `ArkSwitch.HiddenInput`, a visually hidden
 * checkbox, so that is where the switch semantics and the name have to be.
 *
 * `role="switch"` on the input: an on/off setting announced as "checkbox,
 * checked" invites the reading that ticking it selects something. And the
 * `aria-label` the call sites pass is forwarded to the input rather than left
 * on the root <label>, which has no text of its own to name the input with.
 */
export const Switch = (props: React.ComponentProps<typeof ArkSwitch.Root>) => {
  const {
    className,
    tabIndex,
    "aria-label": ariaLabel,
    "aria-labelledby": ariaLabelledBy,
    "aria-describedby": ariaDescribedBy,
    onCheckedChange,
    ...rest
  } = props;

  // A controlled switch whose parent refuses a change — Lists asks before
  // disabling a list a device depends on — keeps its track, but the native
  // checkbox under it had already been toggled by the click, and a screen
  // reader read the new state. After the parent has had its render, the
  // input is put back in step with the `checked` it was actually given.
  const inputRef = React.useRef<HTMLInputElement>(null);
  const checkedRef = React.useRef(props.checked);
  checkedRef.current = props.checked;
  const handleCheckedChange = React.useCallback(
    (details: { checked: boolean }) => {
      onCheckedChange?.(details);
      requestAnimationFrame(() => {
        const input = inputRef.current;
        const checked = checkedRef.current;
        if (input && checked !== undefined && input.checked !== checked) input.checked = checked;
      });
    },
    [onCheckedChange],
  );

  return (
    <ArkSwitch.Root
      className={cn(
        "group/switch",
        "[--thumb-size:--spacing(5)] sm:[--thumb-size:--spacing(4)]",
        "h-[calc(var(--thumb-size)+2px)] w-[calc(var(--thumb-size)*2-2px)]",
        "p-px",
        "inline-flex shrink-0 items-center",
        "rounded-full border border-transparent",
        // Named, not `all`: `transition-all` eased the focus outline in over
        // 150ms, and a focus ring a fast keyboard user does not see is the
        // thing index.css says not to build.
        "transition-[background-color,border-color]",
        /*
         * The same outline every other control gets, drawn on the root.
         *
         * This used to be `ring-[3px]` plus `ring-ring/32`, which painted
         * nothing: tailwind-merge reads `ring-ring/32` as a ring *width* and
         * drops the width utility beside it, leaving a coloured ring zero
         * pixels wide. The global `:focus-visible` rule in index.css could not
         * cover for it either, because the element that takes focus here is
         * `ArkSwitch.HiddenInput` — a 1x1 sr-only input — so the outline landed
         * on a box nobody can see. Ark mirrors that input's state onto the root
         * as `data-focus-visible`, which is the element with the track on it.
         */
        "data-focus-visible:outline-2 data-focus-visible:outline-ring data-focus-visible:outline-offset-2",
        "data-invalid:border-destructive",
        "dark:data-invalid:border-destructive-foreground",
        "data-[state=checked]:bg-primary",
        // --input is the 3:1 control edge, so the unchecked track clears 3:1
        // against the surface and the white thumb clears it against the
        // track (3.47:1 light; the dark thumb is --foreground, 4.5:1).
        "data-[state=unchecked]:bg-input",
        "data-disabled:pointer-events-none data-disabled:opacity-64",
        "motion-reduce:transition-none!",
        className
      )}
      data-slot="switch"
      onCheckedChange={handleCheckedChange}
      {...rest}
    >
      <ArkSwitch.Control
        className="flex size-full items-center"
        data-slot="switch-control"
      >
        <ArkSwitch.Thumb
          className={cn(
            "block",
            "aspect-square h-full w-auto",
            "bg-background",
            "rounded-full ring-0",
            "pointer-events-none",
            "transition-transform",
            "data-[state=checked]:translate-x-[calc(var(--thumb-size)-4px)]",
            "dark:data-[state=checked]:bg-primary-foreground",
            "data-[state=unchecked]:translate-x-0",
            "dark:data-[state=unchecked]:bg-foreground",
            "motion-reduce:transition-none!"
          )}
          data-slot="switch-thumb"
        />
      </ArkSwitch.Control>

      <ArkSwitch.HiddenInput
        aria-describedby={ariaDescribedBy}
        aria-label={ariaLabel}
        aria-labelledby={ariaLabelledBy}
        ref={inputRef}
        role="switch"
        tabIndex={tabIndex}
      />
    </ArkSwitch.Root>
  );
};
