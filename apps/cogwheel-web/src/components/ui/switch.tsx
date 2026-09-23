"use client";

import { Switch as ArkSwitch } from "@ark-ui/react/switch";
import type React from "react";
import { cn } from "@/lib/utils";

export const Switch = (props: React.ComponentProps<typeof ArkSwitch.Root>) => {
  const { className, tabIndex, ...rest } = props;

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
        "data-[state=unchecked]:bg-input dark:data-[state=unchecked]:bg-input",
        "data-disabled:pointer-events-none data-disabled:opacity-64",
        "motion-reduce:transition-none!",
        className
      )}
      data-slot="switch"
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

      <ArkSwitch.HiddenInput tabIndex={tabIndex} />
    </ArkSwitch.Root>
  );
};
