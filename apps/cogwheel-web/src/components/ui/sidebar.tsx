"use client";

import { ark } from "@ark-ui/react/factory";
import { PanelLeftIcon } from "lucide-react";
import React from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader } from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useIsMobile } from "@/hooks/use-is-mobile";

const SIDEBAR_COOKIE_NAME = "sidebar_state";
const SIDEBAR_COOKIE_MAX_AGE = 60 * 60 * 24 * 7;
const SIDEBAR_WIDTH = "16rem";
const SIDEBAR_WIDTH_MOBILE = "18rem";
const SIDEBAR_WIDTH_ICON = "3rem";
const SIDEBAR_KEYBOARD_SHORTCUT = "b";

interface SidebarContextProps {
  isMobile: boolean;
  open: boolean;
  openMobile: boolean;
  setOpen: (open: boolean) => void;
  setOpenMobile: (open: boolean) => void;
  state: "expanded" | "collapsed";
  toggleSidebar: () => void;
}

const SidebarContext = React.createContext<SidebarContextProps | null>(null);

interface SidebarProviderProps extends React.ComponentProps<"div"> {
  /**
   * The default open state of the sidebar.
   *
   * @default true
   */
  defaultOpen?: boolean;
  /**
   * The function to call when the open state of the sidebar changes.
   */
  onOpenChange?: (open: boolean) => void;
  /**
   * The open state of the sidebar.
   */
  open?: boolean;
}

export const SidebarProvider = (props: SidebarProviderProps) => {
  const {
    defaultOpen = true,
    open: openProp,
    onOpenChange: setOpenProp,
    className,
    style,
    ...rest
  } = props;

  const isMobile = useIsMobile();
  const [openMobile, setOpenMobile] = React.useState(false);

  const [_open, _setOpen] = React.useState(defaultOpen);
  const open = openProp ?? _open;
  const setOpen = React.useCallback(
    (value: boolean | ((value: boolean) => boolean)) => {
      const openState = typeof value === "function" ? value(open) : value;
      if (setOpenProp) {
        setOpenProp(openState);
      } else {
        _setOpen(openState);
      }

      // biome-ignore lint/suspicious/noDocumentCookie: Persist the sidebar state across reloads.
      document.cookie = `${SIDEBAR_COOKIE_NAME}=${openState}; path=/; max-age=${SIDEBAR_COOKIE_MAX_AGE}`;
    },
    [setOpenProp, open]
  );

  const toggleSidebar = React.useCallback(() => {
    if (isMobile) {
      setOpenMobile((open) => !open);
    } else {
      setOpen((open) => !open);
    }
  }, [isMobile, setOpen]);

  React.useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (
        event.key === SIDEBAR_KEYBOARD_SHORTCUT &&
        (event.metaKey || event.ctrlKey)
      ) {
        event.preventDefault();
        toggleSidebar();
      }
    };

    window.addEventListener("keydown", handleKeyDown);

    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [toggleSidebar]);

  const state = open ? "expanded" : "collapsed";

  const contextValue = React.useMemo<SidebarContextProps>(
    () => ({
      state,
      open,
      setOpen,
      isMobile,
      openMobile,
      setOpenMobile,
      toggleSidebar,
    }),
    [state, open, setOpen, isMobile, openMobile, toggleSidebar]
  );

  return (
    <SidebarContext.Provider value={contextValue}>
      <ark.div
        className={cn(
          "group/sidebar-wrapper",
          "flex",
          "min-h-svh w-full",
          className
        )}
        data-slot="sidebar-wrapper"
        style={
          {
            "--sidebar-width": SIDEBAR_WIDTH,
            "--sidebar-width-icon": SIDEBAR_WIDTH_ICON,
            ...style,
          } as React.CSSProperties
        }
        {...rest}
      />
    </SidebarContext.Provider>
  );
};

interface SidebarProps extends React.ComponentProps<typeof Sheet> {
  className?: string;
}

/**
 * Two forms, because the product has two: a fixed column on a desktop that the
 * trigger narrows to an icon rail, and a sheet on a phone.
 *
 * The upstream shell also carries `variant` (floating/inset), right-hand
 * `placement` and the offcanvas and non-collapsible modes. None of them is
 * reachable from this app's five-entry nav, and each was a branch of class
 * strings a reader had to rule out before understanding the one that renders.
 */
export const Sidebar = (props: SidebarProps) => {
  const { className, children, ...rest } = props;
  const { isMobile, state, openMobile, setOpenMobile } = useSidebar();

  if (isMobile) {
    return (
      <Sheet
        {...rest}
        onOpenChange={({ open }) => setOpenMobile(open)}
        open={openMobile}
      >
        <SheetContent
          className={cn(
            "w-(--sidebar-width)",
            "p-0",
            "bg-sidebar",
            "text-sidebar-foreground",
            "[&>button]:hidden"
          )}
          data-mobile="true"
          data-sidebar="sidebar"
          data-slot="sidebar"
          placement="left"
          style={
            {
              "--sidebar-width": SIDEBAR_WIDTH_MOBILE,
            } as React.CSSProperties
          }
        >
          <SheetHeader
            className="sr-only"
            description="Displays the mobile sidebar."
            title="Sidebar"
          />
          <ark.div className="flex size-full flex-col">{children}</ark.div>
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <ark.div
      className={cn("group peer", "hidden md:block", "text-sidebar-foreground")}
      data-collapsible={state === "collapsed" ? "icon" : ""}
      data-slot="sidebar"
      data-state={state}
    >
      {/* Holds the column's width in the flex row; the panel itself is fixed. */}
      <ark.div
        className={cn(
          "relative",
          "w-(--sidebar-width)",
          "bg-transparent",
          "transition-[width] duration-200 ease-linear",
          "group-data-[collapsible=icon]:w-(--sidebar-width-icon)",
          "motion-reduce:transition-none!"
        )}
        data-slot="sidebar-gap"
      />
      <ark.div
        className={cn(
          "fixed inset-y-0 z-10",
          "inset-s-0 w-(--sidebar-width)",
          "hidden md:flex",
          "h-svh",
          "border-e",
          "transition-[width] duration-200 ease-linear",
          "group-data-[collapsible=icon]:w-(--sidebar-width-icon)",
          "motion-reduce:transition-none!",
          className
        )}
        data-slot="sidebar-container"
        {...rest}
      >
        <ark.div
          className={cn("size-full", "flex flex-col", "bg-sidebar")}
          data-sidebar="sidebar"
          data-slot="sidebar-inner"
        >
          {children}
        </ark.div>
      </ark.div>
    </ark.div>
  );
};

export const SidebarTrigger = (props: React.ComponentProps<typeof Button>) => {
  const { className, onClick, ...rest } = props;

  const { toggleSidebar } = useSidebar();

  return (
    <Button
      className={cn("size-7", className)}
      data-sidebar="trigger"
      data-slot="sidebar-trigger"
      onClick={(event) => {
        onClick?.(event);
        toggleSidebar();
      }}
      size="icon-md"
      variant="ghost"
      {...rest}
    >
      <PanelLeftIcon className="rtl:rotate-180" />
      <ark.span className="sr-only">Toggle Sidebar</ark.span>
    </Button>
  );
};

export const SidebarInset = (props: React.ComponentProps<typeof ark.main>) => {
  const { className, ...rest } = props;

  return (
    <ark.main
      className={cn("relative flex w-full flex-1 flex-col bg-background", className)}
      data-slot="sidebar-inset"
      {...rest}
    />
  );
};

export const SidebarHeader = (props: React.ComponentProps<typeof ark.div>) => {
  const { className, ...rest } = props;

  return (
    <ark.div
      className={cn("flex flex-col gap-2 p-2", className)}
      data-sidebar="header"
      data-slot="sidebar-header"
      {...rest}
    />
  );
};

export const SidebarFooter = (props: React.ComponentProps<typeof ark.div>) => {
  const { className, ...rest } = props;

  return (
    <ark.div
      className={cn("flex flex-col gap-2 p-2", className)}
      data-sidebar="footer"
      data-slot="sidebar-footer"
      {...rest}
    />
  );
};

/** Plain overflow, not a scroll viewport: five entries never scroll. */
export const SidebarContent = (props: React.ComponentProps<typeof ark.div>) => {
  const { className, ...rest } = props;

  return (
    <ark.div
      className={cn(
        "min-h-0",
        "flex flex-1 flex-col gap-0",
        "overflow-auto",
        "group-data-[collapsible=icon]:overflow-hidden",
        className
      )}
      data-sidebar="content"
      data-slot="sidebar-content"
      {...rest}
    />
  );
};

export const SidebarGroup = (props: React.ComponentProps<typeof ark.div>) => {
  const { className, ...rest } = props;

  return (
    <ark.div
      className={cn("relative flex w-full min-w-0 flex-col p-2", className)}
      data-sidebar="group"
      data-slot="sidebar-group"
      {...rest}
    />
  );
};

export const SidebarGroupLabel = (
  props: React.ComponentProps<typeof ark.div>
) => {
  const { className, ...rest } = props;

  return (
    <ark.div
      className={cn(
        "h-8",
        "px-2",
        "flex shrink-0 items-center",
        "font-medium text-sidebar-foreground/70 text-xs",
        "rounded-md",
        "transition-[margin,opacity] duration-200 ease-linear",
        "outline-hidden ring-sidebar-ring focus-visible:ring-2",
        "[&_svg]:size-4 [&_svg]:shrink-0",
        "group-data-[collapsible=icon]:-mt-8 group-data-[collapsible=icon]:opacity-0",
        "motion-reduce:transition-none!",
        className
      )}
      data-sidebar="group-label"
      data-slot="sidebar-group-label"
      {...rest}
    />
  );
};

export const SidebarGroupContent = (
  props: React.ComponentProps<typeof ark.div>
) => {
  const { className, ...rest } = props;

  return (
    <ark.div
      className={cn("w-full text-sm", className)}
      data-sidebar="group-content"
      data-slot="sidebar-group-content"
      {...rest}
    />
  );
};

export const SidebarMenu = (props: React.ComponentProps<typeof ark.ul>) => {
  const { className, ...rest } = props;

  return (
    <ark.ul
      className={cn("w-full min-w-0", "flex flex-col gap-0", className)}
      data-sidebar="menu"
      data-slot="sidebar-menu"
      {...rest}
    />
  );
};

export const SidebarMenuItem = (props: React.ComponentProps<typeof ark.li>) => {
  const { className, ...rest } = props;

  return (
    <ark.li
      className={cn("group/menu-item relative", className)}
      data-sidebar="menu-item"
      data-slot="sidebar-menu-item"
      {...rest}
    />
  );
};

interface SidebarMenuButtonProps extends React.ComponentProps<typeof Button> {
  /** Whether the button is the current route. */
  isActive?: boolean;
  /** Label shown on hover, and the only labelling once collapsed to icons. */
  tooltip?: string;
}

export const SidebarMenuButton = ({
  tooltip,
  ...props
}: SidebarMenuButtonProps) => {
  const { isActive = false, className, ...rest } = props;
  const { isMobile, state } = useSidebar();

  const button = (
    <Button
      className={cn(
        "peer/menu-button group/menu-button",
        "w-full",
        "justify-start gap-2",
        "p-2",
        "overflow-hidden",
        "transition-[width,height,padding]",
        "group-data-[collapsible=icon]:size-8! group-data-[collapsible=icon]:p-2!",
        "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
        "active:bg-sidebar-accent active:text-sidebar-accent-foreground",
        "data-[active=true]:bg-sidebar-accent data-[active=true]:font-medium data-[active=true]:text-sidebar-accent-foreground",
        "[&>span:last-child]:truncate",
        "motion-reduce:transition-none!",
        className
      )}
      clickEffect={false}
      data-active={isActive}
      data-sidebar="menu-button"
      data-slot="sidebar-menu-button"
      size="md"
      variant="ghost"
      {...rest}
    />
  );

  if (!tooltip) {
    return button;
  }

  // Only while collapsed to the icon rail: with labels on screen a tooltip
  // repeating them is noise, and on a phone there is nothing to hover with.
  return (
    <Tooltip positioning={{ placement: "right" }}>
      <TooltipTrigger asChild>{button}</TooltipTrigger>
      <TooltipContent hidden={state !== "collapsed" || isMobile}>{tooltip}</TooltipContent>
    </Tooltip>
  );
};

export const useSidebar = () => {
  const context = React.useContext(SidebarContext);

  if (context === null) {
    throw new Error("useSidebar must be used within a SidebarProvider.");
  }

  return context;
};
