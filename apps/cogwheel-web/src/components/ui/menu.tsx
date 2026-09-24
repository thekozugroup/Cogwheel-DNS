"use client";

import { Portal } from "@ark-ui/react";
import { Menu as ArkMenu, type MenuContentProps } from "@ark-ui/react/menu";
import type React from "react";
import { tv, type VariantProps } from "tailwind-variants";
import { cn } from "@/lib/utils";

export const Menu = (props: React.ComponentProps<typeof ArkMenu.Root>) => {
  const {
    lazyMount = true,
    positioning = { placement: "bottom-end" },
    unmountOnExit = true,
    ...rest
  } = props;

  return (
    <ArkMenu.Root
      data-slot="menu"
      lazyMount={lazyMount}
      positioning={positioning}
      unmountOnExit={unmountOnExit}
      {...rest}
    />
  );
};

export const MenuTrigger = (
  props: React.ComponentProps<typeof ArkMenu.Trigger>
) => <ArkMenu.Trigger data-slot="menu-trigger" {...props} />;

const MenuPositioner = (
  props: React.ComponentProps<typeof ArkMenu.Positioner>
) => {
  const { className, ...rest } = props;

  return (
    <ArkMenu.Positioner
      className={cn("outline-none", className)}
      data-slot="menu-positioner"
      {...rest}
    />
  );
};

const menuContentVariants = tv({
  base: [
    "z-[calc(50+var(--nested-layer-count,0))]",
    "max-h-(--available-height) not-[class*='w-']:min-w-32",
    "p-1",
    "bg-popover",
    "text-popover-foreground",
    "rounded-xl border shadow-lg/5",
    "origin-(--transform-origin)",
    "outline-none",
    "overflow-y-auto",
    "duration-100",
    "data-[state=open]:animate-in",
    "data-[state=open]:fade-in-0",
    "data-[state=open]:zoom-in-[98%]",
    "data-[placement=bottom]:slide-in-from-top-2",
    "data-[placement=left]:slide-in-from-end-2",
    "data-[placement=right]:slide-in-from-start-2",
    "data-[placement=top]:slide-in-from-bottom-2",
    "motion-reduce:animate-none!",
  ],
});

export const MenuContent = (props: MenuContentProps) => {
  const { className, children, ...rest } = props;

  return (
    <Portal>
      <MenuPositioner>
        <ArkMenu.Content
          className={cn(menuContentVariants(), className)}
          data-slot="menu-content"
          {...rest}
        >
          {children}
        </ArkMenu.Content>
      </MenuPositioner>
    </Portal>
  );
};

/**
 * The highlighted item — keyboard or pointer, Ark does not distinguish — is
 * inverted: primary surface, primary foreground. It was --accent on
 * --popover, #f5f5f5 on #fff, 1.09:1 with no outline, so a keyboard user
 * arrowing through a row menu could not see which verb Enter would fire. An
 * inverted row is how a native menu marks the same thing, and in a black and
 * white product it is the only highlight that reads at a glance.
 *
 * `destructive` keeps its name for the call sites but not its red. DESIGN.md
 * §2: a status colour on a control is a colour being used as a control. The
 * guard on "Delete list…" is the ConfirmDialog it opens, which is where the
 * red lives, on the sentence describing what the appliance will be in after.
 */
const menuItemVariants = tv({
  base: [
    "group/menu-item",
    "relative",
    "w-full",
    "px-2.5 py-1.5",
    "flex items-center gap-2",
    "select-none text-sm",
    "rounded-lg",
    "outline-hidden",
    "cursor-default",
    "data-highlighted:bg-primary data-highlighted:text-primary-foreground",
    "data-disabled:pointer-events-none data-disabled:opacity-64",
    "[&_svg:not([class*='size-'])]:size-3.5 [&_svg]:pointer-events-none [&_svg]:shrink-0",
    "pointer-coarse:min-h-11",
  ],
  variants: {
    variant: {
      default: [],
      destructive: [],
    },
  },
  defaultVariants: {
    variant: "default",
  },
});

interface MenuItemProps
  extends React.ComponentProps<typeof ArkMenu.Item>,
    VariantProps<typeof menuItemVariants> {}

export const MenuItem = (props: MenuItemProps) => {
  const { variant = "default", className, ...rest } = props;

  return (
    <ArkMenu.Item
      className={cn(menuItemVariants({ variant }), className)}
      data-variant={variant}
      {...rest}
    />
  );
};


/**
 * Items that act on the same scope — "for everyone", "on Sam's iPhone" — kept
 * together. The label is for assistive technology: the items' own words
 * already name the scope, and the separator draws the grouping.
 */
export const MenuItemGroup = (props: React.ComponentProps<typeof ArkMenu.ItemGroup>) => (
  <ArkMenu.ItemGroup data-slot="menu-item-group" {...props} />
);

export const MenuItemGroupLabel = (props: React.ComponentProps<typeof ArkMenu.ItemGroupLabel>) => {
  const { className, ...rest } = props;
  return <ArkMenu.ItemGroupLabel className={cn("sr-only", className)} data-slot="menu-item-group-label" {...rest} />;
};

export const MenuSeparator = (props: React.ComponentProps<typeof ArkMenu.Separator>) => {
  const { className, ...rest } = props;
  return <ArkMenu.Separator className={cn("-mx-1 my-1 h-px border-0 bg-border", className)} data-slot="menu-separator" {...rest} />;
};
