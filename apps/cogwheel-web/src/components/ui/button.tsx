import { ark } from "@ark-ui/react/factory";
import type React from "react";
import { tv, type VariantProps } from "tailwind-variants";
import { cn } from "@/lib/utils";
import { Spinner } from "@/components/ui/spinner";

const buttonVariants = tv({
  base: [
    "relative",
    "inline-flex shrink-0 items-center justify-center gap-2",
    // A label wraps rather than running off its card. Buttons keep their one-
    // line size everywhere they fit — `shrink-0` stops a flex row from
    // squeezing them — and only a container narrower than the label, which is
    // a phone at 200% text, makes it take a second line. It used to be
    // `whitespace-nowrap` and a fixed height, and "Load older than 9:59:47 PM"
    // ran 168px past a 375px card. So the sizes below are minimum heights.
    "max-w-full font-medium text-sm",
    "rounded-lg",
    // Everything a button animates, named rather than `transition-all`: the focus
    // outline is the one thing that must be there the instant the key is released,
    // and `all` was easing it in over 150 ms.
    "transition-[color,background-color,border-color,box-shadow,transform,opacity]",
    "disabled:pointer-events-none disabled:opacity-64",
    "data-disabled:pointer-events-none data-disabled:opacity-64",
    "aria-disabled:pointer-events-none aria-disabled:opacity-64",
    "data-[state=loading]:pointer-events-none",
    "aria-invalid:border-destructive",
    "[&_svg:not([class*='size-'])]:size-4 [&_svg]:pointer-events-none [&_svg]:shrink-0",
    "motion-reduce:transition-none!",
  ],
  variants: {
    variant: {
      default: [
        "bg-primary",
        "border border-transparent shadow-primary/24 shadow-sm",
        "text-primary-foreground",
        "hover:bg-primary/90",
        "focus-visible:border-background",
      ],
      outline: [
        "bg-transparent",
        "text-foreground",
        "border border-input shadow-sm/5",
        "hover:bg-accent hover:text-accent-foreground",
        // --muted, not --input: --input is the 3:1 edge now, and a fill in
        // the edge's own colour would swallow it.
        "dark:bg-muted/60 dark:hover:bg-accent",
        "focus-visible:border-primary",
      ],
      /**
       * Deliberately the same neutral outline as `outline`, and not a red one.
       * Red, green and yellow-400 are reserved for status in this product —
       * a StatusPill saying "Blocked", a list whose last fetch failed — and a
       * button is not a status: "Clear log" in red outline was decorating a
       * control with the palette that elsewhere means something is wrong. The
       * variant stays because the call sites mean it, and because the guard on
       * anything irreversible is the ConfirmDialog, which is where the red now
       * lives — on the sentence describing what the click does.
       */
      destructive: [
        "bg-transparent",
        "text-foreground",
        "border border-input shadow-sm/5",
        "hover:bg-accent hover:text-accent-foreground",
        "dark:bg-muted/60 dark:hover:bg-accent",
        "focus-visible:border-primary",
      ],
      secondary: [
        "bg-secondary",
        "text-secondary-foreground",
        "border border-transparent",
        "focus-visible:border-primary",
        "hover:bg-secondary/80",
      ],
      ghost: [
        "hover:bg-accent hover:text-accent-foreground",
        "border border-transparent",
        "focus-visible:border-primary",
      ],
      link: [
        "text-primary",
        "underline-offset-4",
        "border border-transparent",
        "hover:underline",
        "focus-visible:border-primary",
      ],
    },
    size: {
      xs: [
        "min-h-6",
        "gap-1.5",
        "px-2 py-0.5",
        "text-xs",
        "rounded-sm",
        "[&_svg:not([class*='size-'])]:size-2.5",
      ],
      sm: [
        "min-h-7",
        "px-2.5 py-1",
        "gap-1.5",
        "[&_svg:not([class*='size-'])]:size-3.5",
      ],
      md: ["min-h-8", "px-3", "py-1"],
      lg: ["min-h-9", "px-3.5", "py-1.5"],
      xl: ["min-h-10", "text-base", "px-4", "py-2"],
      "icon-xs": "size-6 rounded-sm",
      "icon-sm": "size-7",
      "icon-md": "size-8",
      "icon-lg": "size-9",
      "icon-xl": "size-10 [&_svg:not([class*='size-'])]:size-5",
    },
    clickEffect: {
      true: "active:not-aria-[haspopup]:scale-[0.98]",
    },
    pill: {
      true: [
        "rounded-full",
        "has-[>svg]:data-[size=xs]:pe-3",
        "has-[>svg]:data-[size=sm]:pe-3.5",
        "has-[>svg]:data-[size=md]:pe-4",
        "has-[>svg]:data-[size=lg]:pe-4.5",
        "has-[>svg]:data-[size=xl]:pe-5",
      ],
    },
  },
  defaultVariants: {
    variant: "default",
    size: "md",
    clickEffect: true,
    pill: false,
  },
});

export interface ButtonProps
  extends React.ComponentProps<typeof ark.button>,
    VariantProps<typeof buttonVariants> {
  /**
   * Apply a click effect to the button
   *
   * @default true
   */
  clickEffect?: boolean;
  /**
   * Show a loading indicator
   *
   * @default false
   */
  isLoading?: boolean;
}

export const Button = (props: ButtonProps) => {
  const {
    variant = "default",
    size = "md",
    clickEffect = true,
    pill = false,
    isLoading = false,
    className,
    children,
    ...rest
  } = props;

  return (
    <ark.button
      className={cn(
        buttonVariants({ variant, size, clickEffect, pill }),
        className
      )}
      data-size={size}
      data-slot="button"
      data-state={isLoading ? "loading" : "idle"}
      data-variant={variant}
      type="button"
      {...rest}
      aria-busy={isLoading}
      aria-disabled={isLoading}
    >
      {isLoading ? (
        <>
          <span aria-hidden className="invisible">
            {children}
          </span>

          <span className="sr-only">{children}</span>

          <span className="absolute inset-0 flex items-center justify-center">
            <Spinner aria-hidden />
          </span>
        </>
      ) : (
        children
      )}
    </ark.button>
  );
};
