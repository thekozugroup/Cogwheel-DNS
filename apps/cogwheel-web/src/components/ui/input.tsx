"use client";

import { FieldInput } from "@ark-ui/react/field";
import type React from "react";
import { tv, type VariantProps } from "tailwind-variants";
import { cn } from "@/lib/utils";

const inputVariants = tv({
  base: [
    "peer",
    "w-full min-w-0",
    "px-3",
    // The dark fill is --muted, not --input: --input is now the 3:1 edge
    // colour, and a field filled with its own border colour loses the edge.
    "bg-transparent dark:bg-muted/60",
    "text-base md:text-sm",
    "rounded-lg border border-input shadow-xs/5",
    // Full --muted-foreground: 4.74:1 light, 6.6:1 dark. At /64 it was 2.43:1,
    // a placeholder that is an example nobody can read.
    "placeholder:text-muted-foreground",
    "file:inline-flex file:h-7 file:items-center file:border-0",
    "file:font-medium file:text-foreground file:text-sm",
    "transition-[color,box-shadow]",
    "focus-visible:border-primary",
    // Invalid text takes the 700/300 partner in both themes; red-400 as text
    // is 2.89:1 on white. The 400 accent stays on the border and the ring.
    "aria-invalid:border-destructive aria-invalid:text-destructive-foreground",
    "data-invalid:border-destructive data-invalid:text-destructive-foreground",
    "dark:aria-invalid:border-destructive-foreground",
    "dark:data-invalid:border-destructive-foreground dark:data-invalid:ring-destructive-foreground/40",
    "disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-64",
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

export interface InputProps
  extends Omit<React.ComponentProps<typeof FieldInput>, "size">,
    VariantProps<typeof inputVariants> {}

export const Input = (props: InputProps) => {
  const { size = "md", type = "text", className, ...rest } = props;

  return (
    <FieldInput
      className={cn(inputVariants({ size }), className)}
      data-size={size}
      data-slot="input"
      type={type}
      {...rest}
    />
  );
};
