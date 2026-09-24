"use client";

import { ark } from "@ark-ui/react/factory";
import { Field as ArkField } from "@ark-ui/react/field";
import { ChevronsUpDownIcon } from "lucide-react";
import type React from "react";
import { tv, type VariantProps } from "tailwind-variants";
import { cn } from "@/lib/utils";

const nativeSelectVariants = tv({
  base: [
    "appearance-none",
    "w-full min-w-0",
    "ps-2.5 pe-8",
    // 16px below md, like a text field: iOS zooms the page into any control
    // whose text is smaller than that when it takes focus.
    "select-none text-base md:text-sm",
    "bg-transparent dark:bg-muted/60",
    "rounded-lg border border-input shadow-xs/5",
    // Named rather than `transition-colors`, which in Tailwind v4 includes
    // `outline-color` and eased the focus ring in over 150ms.
    "transition-[color,background-color,border-color]",
    "[&:has(option[value='']:checked)]:text-muted-foreground",
    "disabled:pointer-events-none disabled:cursor-not-allowed",
    "focus-visible:border-primary",
    "aria-invalid:border-destructive",
    "dark:aria-invalid:border-destructive-foreground",
    "motion-reduce:transition-none!",
  ],
  variants: {
    size: {
      sm: ["h-7"],
      md: ["h-8"],
      lg: ["h-9"],
    },
  },
  defaultVariants: {
    size: "md",
  },
});

interface NativeSelectProps
  extends Omit<React.ComponentProps<typeof ArkField.Select>, "size">,
    VariantProps<typeof nativeSelectVariants> {
  /**
   * Whether the select is invalid.
   *
   * @default false
   */
  invalid?: boolean;
}

export const NativeSelect = (props: NativeSelectProps) => {
  const { size = "md", invalid, className, ...rest } = props;

  return (
    <ark.div
      className={cn(
        "relative w-fit",
        "has-[select:disabled]:opacity-64",
        "[&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 [&_svg]:text-muted-foreground",
        className
      )}
      data-slot="native-select-wrapper"
    >
      <ArkField.Select
        aria-invalid={invalid}
        className={cn(nativeSelectVariants({ size }))}
        data-slot="native-select"
        {...rest}
      />
      <ChevronsUpDownIcon
        aria-hidden="true"
        className={cn("absolute inset-e-2.5 top-1/2 -translate-y-1/2")}
        data-slot="native-select-icon"
      />
    </ark.div>
  );
};

export const NativeSelectOption = (
  props: React.ComponentProps<typeof ark.option>
) => <ark.option data-slot="native-select-option" {...props} />;
