"use client";

import { ark } from "@ark-ui/react/factory";
import { tv, type VariantProps } from "tailwind-variants";
import { cn } from "@/lib/utils";

const badgeVariants = tv({
  base: [
    "relative",
    "inline-flex items-center justify-center gap-1",
    "select-none whitespace-nowrap font-medium text-xs",
    "rounded-md border border-transparent",
    "overflow-hidden",
    "transition-colors",
    "focus-visible:border-primary",
    "[&_svg]:pointer-events-none [&_svg]:size-3 [&_svg]:shrink-0",
    "[button&,a&]:cursor-pointer [button&,a&]:pointer-coarse:after:absolute [button&,a&]:pointer-coarse:after:size-full [button&,a&]:pointer-coarse:after:min-h-11 [button&,a&]:pointer-coarse:after:min-w-11",
    "motion-reduce:transition-none!",
  ],
  variants: {
    variant: {
      default: [
        "bg-foreground",
        "text-background",
        "focus-visible:border-foreground focus-visible:ring-foreground/20",
        "dark:focus-visible:ring-foreground/40",
        "[a&]:hover:bg-foreground/90",
      ],
      secondary: [
        "bg-secondary",
        "text-secondary-foreground",
        "border-secondary/20",
        "focus-visible:border-foreground focus-visible:ring-foreground/50",
        "[a&]:hover:bg-secondary/90",
      ],
      outline: [
        "text-foreground",
        "border-border",
        "[a&]:hover:bg-accent",
        "[a&]:hover:text-accent-foreground",
      ],
      /**
       * Status badges are the §3.3 "Tint" pattern: a 400 accent as the surface
       * and border, with the readable 700/300 partner as the label. The 400
       * token is never the text: green-400 lettering on a green-400/10 tint
       * measured 1.65:1 and yellow-400 on yellow-400/10 1.49:1, both far under
       * §7's 4.5:1.
       *
       * Hover deepens the hairline rather than the fill on purpose: a heavier
       * tint drags the 700-on-tint ratios down (green-700 on green-400/20 is
       * 4.29:1, under AA), while the border carries no text.
       *
       * Computed ratios at the /10 tint, label on tint over --card:
       *   success  green-700 / light 4.60:1   green-300 / dark 12.29:1
       *   warning  yellow-700 / light 4.69:1  yellow-300 / dark 12.71:1
       *   info     neutral-700 / light 9.58:1 neutral-300 / dark 11.85:1
       *   destructive red-700 / light 5.78:1  red-300 / dark 9.80:1 (at /5)
       */
      success: [
        "bg-success/10",
        "text-success-foreground",
        "border-success/24",
        "focus-visible:border-success focus-visible:ring-success/24",
        "[a&]:hover:border-success/56",
      ],
      info: [
        "bg-info/10",
        "text-info-foreground",
        "border-info/24",
        "focus-visible:border-info focus-visible:ring-info/50",
        "[a&]:hover:border-info/56",
      ],
      warning: [
        "bg-warning/10",
        "text-warning-foreground",
        "border-warning/24",
        "focus-visible:border-warning focus-visible:ring-warning/24",
        "dark:focus-visible:ring-warning/40",
        "[a&]:hover:border-warning/56",
      ],
      destructive: [
        "bg-destructive/10 dark:bg-destructive/5",
        "text-destructive-foreground",
        "border-destructive/24",
        "focus-visible:border-destructive focus-visible:ring-destructive/24",
        "dark:focus-visible:ring-destructive/40",
        "[a&]:hover:border-destructive/56",
      ],
    },
    size: {
      sm: ["h-5 min-w-5", "px-1"],
      md: ["h-5.5 min-w-5.5", "px-1.5"],
      lg: ["h-6.5 min-w-6.5", "px-2", "text-sm"],
    },
    pill: {
      true: [
        "rounded-full",
        "has-[>svg]:data-[size=sm]:pe-1.5",
        "has-[>svg]:data-[size=md]:pe-2",
        "has-[>svg]:data-[size=lg]:pe-2 sm:has-[>svg]:data-[size=lg]:pe-2.5",
      ],
    },
  },
  defaultVariants: {
    variant: "default",
    size: "md",
    pill: false,
  },
});

interface BadgeProps
  extends React.ComponentProps<typeof ark.span>,
    VariantProps<typeof badgeVariants> {}

export const Badge = (props: BadgeProps) => {
  const {
    variant = "default",
    size = "md",
    pill = false,
    className,
    ...rest
  } = props;

  return (
    <ark.span
      className={cn(badgeVariants({ variant, size, pill }), className)}
      data-size={size}
      data-slot="badge"
      data-variant={variant}
      {...rest}
    />
  );
};
