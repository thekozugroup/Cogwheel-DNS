"use client";

import { Field as ArkField } from "@ark-ui/react/field";
import type React from "react";
import { tv, type VariantProps } from "tailwind-variants";
import { cn } from "@/lib/utils";

const fieldVariants = tv({
  base: [
    "group/field",
    "w-full",
    "flex gap-2",
    // The 700/300 partner in both themes — red-400 as text fails AA on white.
    "data-invalid:text-destructive-foreground",
  ],
  variants: {
    orientation: {
      vertical: ["flex-col *:w-full [&>.sr-only]:w-auto"],
      horizontal: [
        "flex-row items-center",
        "*:data-[slot=field-label]:flex-auto",
        "has-[>[data-slot=field-content]]:items-start has-[>[data-slot=field-content]]:[&>[role=checkbox],[role=radio]]:mt-px",
      ],
      responsive: [
        "flex-col *:w-full [&>.sr-only]:w-auto",
        "@md/field-group:flex-row @md/field-group:items-center @md/field-group:*:w-auto",
        "@md/field-group:*:data-[slot=field-label]:flex-auto",
        "@md/field-group:has-[>[data-slot=field-content]]:items-start",
        "@md/field-group:has-[>[data-slot=field-content]]:[&>[role=checkbox],[role=radio]]:mt-px",
      ],
    },
    reverse: {
      true: [
        "data-[orientation=horizontal]:flex-row-reverse",
        "data-[orientation=vertical]:flex-col-reverse",
        "data-[orientation=responsive]:flex-col-reverse",
        "data-[orientation=responsive]:@md/field-group:flex-row-reverse",
      ],
    },
  },
  defaultVariants: {
    orientation: "vertical",
    reverse: false,
  },
});

interface FieldProps
  extends React.ComponentProps<typeof ArkField.Root>,
    VariantProps<typeof fieldVariants> {}

export const Field = (props: FieldProps) => {
  const {
    orientation = "vertical",
    reverse = false,
    className,
    ...rest
  } = props;

  return (
    <ArkField.Root
      className={cn(fieldVariants({ orientation, reverse }), className)}
      data-orientation={orientation}
      data-slot="field"
      {...rest}
    />
  );
};

export const FieldLabel = (
  props: React.ComponentProps<typeof ArkField.Label>
) => {
  const { className, ...rest } = props;

  return (
    <ArkField.Label
      className={cn(
        "group/field-label peer/field-label",
        "select-none font-medium text-sm leading-snug",
        "flex w-fit gap-1",
        "has-[>[data-slot=field]]:w-full has-[>[data-slot=field]]:flex-col has-[>[data-slot=field]]:rounded-xl has-[>[data-slot=field]]:border *:data-[slot=field]:p-2.5",
        "has-data-[state=checked]:border-primary has-data-[state=checked]:bg-primary/5",
        "group-data-disabled/field:opacity-64",
        "dark:has-data-[state=checked]:bg-primary/10",
        className
      )}
      data-slot="field-label"
      {...rest}
    />
  );
};

export const FieldHelper = (
  props: React.ComponentProps<typeof ArkField.HelperText>
) => {
  const { className, ...rest } = props;

  return (
    <ArkField.HelperText
      className={cn("text-muted-foreground text-sm", className)}
      data-slot="field-helper"
      {...rest}
    />
  );
};

export const FieldError = (
  props: React.ComponentProps<typeof ArkField.ErrorText>
) => {
  const { className, ...rest } = props;

  return (
    <ArkField.ErrorText
      className={cn(
        "font-normal text-destructive-foreground text-sm",
        className
      )}
      data-slot="field-error"
      {...rest}
    />
  );
};
