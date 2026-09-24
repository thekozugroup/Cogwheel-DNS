"use client";

import { ark } from "@ark-ui/react/factory";
import { PanelLeftIcon } from "lucide-react";
import React from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { IconButton } from "@/components/ui/icon-button";
import { Sheet, SheetContent, SheetHeader } from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useIsMobile } from "@/hooks/use-is-mobile";
import { SCREEN_SHORTCUTS_BOUND } from "@/lib/nav";

const SIDEBAR_COOKIE_NAME = "sidebar_state";
const SIDEBAR_COOKIE_MAX_AGE = 60 * 60 * 24 * 7;
const SIDEBAR_WIDTH = "16rem";
const SIDEBAR_WIDTH_MOBILE = "18rem";
const SIDEBAR_WIDTH_ICON = "3rem";
const SIDEBAR_KEYBOARD_SHORTCUT = "b";
/** The id the trigger's aria-controls points at, in both forms. */
export const SIDEBAR_ID = "app-sidebar";

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

  // ⌘B on a Mac only, for the reason lib/nav.ts binds ⌘1–⌘5 there only:
  // elsewhere Ctrl+B is the browser's (Firefox's bookmarks sidebar), and a
  // page that takes it takes away a way out of the page.
  React.useEffect(() => {
    if (!SCREEN_SHORTCUTS_BOUND) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (
        event.key === SIDEBAR_KEYBOARD_SHORTCUT &&
        event.metaKey &&
        !event.ctrlKey &&
        !event.altKey
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

  /*
   * From md up the shell is a two-column grid and collapsing the sidebar is a
   * change to the first column's track. That is the one thing that animates:
   * `grid-template-columns`, 200ms, on the wrapper. It used to be `width` on
   * two elements (a fixed panel and a spacer holding its place in the flex
   * row), `margin` and `opacity` on the group labels and `width, height,
   * padding` on every nav button — four layout transitions per toggle, each
   * forcing its own reflow. The panel now sits in the grid cell at 100% of the
   * track and follows it; nothing inside it transitions its geometry.
   */
  return (
    <SidebarContext.Provider value={contextValue}>
      <ark.div
        className={cn(
          "group/sidebar-wrapper",
          "flex",
          "min-h-svh w-full",
          "md:grid md:h-svh md:min-h-0",
          "md:grid-cols-[var(--sidebar-track)_minmax(0,1fr)]",
          "md:transition-[grid-template-columns] md:duration-200",
          "motion-reduce:transition-none!",
          className
        )}
        data-slot="sidebar-wrapper"
        data-state={state}
        style={
          {
            "--sidebar-width": SIDEBAR_WIDTH,
            "--sidebar-width-icon": SIDEBAR_WIDTH_ICON,
            "--sidebar-track": open ? "var(--sidebar-width)" : "var(--sidebar-width-icon)",
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
        ids={{ content: SIDEBAR_ID }}
        onOpenChange={({ open }) => setOpenMobile(open)}
        open={openMobile}
      >
        <SheetContent
          className={cn(
            "w-(--sidebar-width)",
            "p-0",
            "bg-sidebar",
            "text-sidebar-foreground"
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
          {/* The sheet's own Close stays: it was hidden, which left a phone
              drawer with no control that closes it — a tap on the dimmed page
              works for a finger, but a screen reader has nothing to find.

              The dialog's name is what a screen reader says when it opens.
              Shark's "Sidebar" / "Displays the mobile sidebar." described the
              widget to the person inside it; "Menu" is what it is to them. */}
          <SheetHeader className="sr-only" title="Menu" />
          <ark.div className="flex size-full flex-col">{children}</ark.div>
        </SheetContent>
      </Sheet>
    );
  }

  // <aside>, so the brand, the nav, the pause control and the theme toggle
  // are inside a landmark; the five links carry their own <nav> within it.
  return (
    <ark.aside
      aria-label="Sidebar"
      className={cn("group peer", "hidden md:block", "min-w-0", "text-sidebar-foreground")}
      data-collapsible={state === "collapsed" ? "icon" : ""}
      data-slot="sidebar"
      data-state={state}
      id={SIDEBAR_ID}
    >
      <ark.div
        className={cn(
          "sticky top-0",
          "h-svh w-full",
          "flex",
          "overflow-hidden",
          "border-e",
          className
        )}
        data-slot="sidebar-container"
        {...rest}
      >
        <ark.div
          className={cn("size-full min-w-0", "flex flex-col", "bg-sidebar")}
          data-sidebar="sidebar"
          data-slot="sidebar-inner"
        >
          {children}
        </ark.div>
      </ark.div>
    </ark.aside>
  );
};

/**
 * A disclosure: it says whether the sidebar is expanded and which element it
 * controls. On a phone it opens a dialog, and says that instead.
 */
export const SidebarTrigger = (
  props: Omit<React.ComponentProps<typeof IconButton>, "label"> & { label?: string }
) => {
  const { className, onClick, label, ...rest } = props;

  const { toggleSidebar, isMobile, open, openMobile } = useSidebar();
  const expanded = isMobile ? openMobile : open;

  return (
    <IconButton
      aria-controls={SIDEBAR_ID}
      aria-expanded={expanded}
      aria-haspopup={isMobile ? "dialog" : undefined}
      className={className}
      data-sidebar="trigger"
      data-slot="sidebar-trigger"
      label={label ?? (isMobile ? "Menu" : "Sidebar")}
      onClick={(event) => {
        onClick?.(event);
        toggleSidebar();
      }}
      tooltip={isMobile ? "Menu" : expanded ? "Collapse sidebar" : "Expand sidebar"}
      tooltipPlacement="bottom"
      {...rest}
    >
      <PanelLeftIcon aria-hidden className="rtl:rotate-180" />
    </IconButton>
  );
};

/**
 * The column beside the sidebar. A plain <div>: it holds the top bar (the
 * banner) and the page's <main>, and a <main> cannot contain a banner.
 */
export const SidebarInset = (props: React.ComponentProps<typeof ark.div>) => {
  const { className, ...rest } = props;

  return (
    <ark.div
      className={cn("relative flex w-full min-w-0 flex-1 flex-col bg-background", className)}
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
        // Full --sidebar-foreground: 7.4:1 in both themes. At /70 it was 3.55
        // and 4.05:1, small text under the 4.5:1 floor.
        "font-medium text-sidebar-foreground text-xs",
        "rounded-md",
        "[&_svg]:size-4 [&_svg]:shrink-0",
        // Gone from the rail rather than animated out of it: the rail has no
        // room for a word, and margin/opacity transitions were two of the four
        // layout animations a collapse used to run.
        "group-data-[collapsible=icon]:hidden",
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
        // A fixed 32px row with 8px padding: Button's heights are minimums
        // now (a label may wrap), and 8px padding round a 20px line is 36.
        "h-8 p-2",
        "overflow-hidden",
        "transition-[color,background-color]",
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
