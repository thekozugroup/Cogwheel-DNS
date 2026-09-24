import { NavLink, useLocation } from "react-router-dom";
import { PRIMARY_NAV, shortcutHint, type NavItem } from "@/lib/nav";
import { cn } from "@/lib/utils";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { Kbd } from "@/components/ui/kbd";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Mark } from "@/components/layout/mark";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import {
  ProtectionDot,
  ProtectionPanel,
  ProtectionRailButton,
} from "@/components/layout/protection";
import { useProtectionSummary } from "@/components/layout/protection-state";

function NavRow({ item, onNavigate }: { item: NavItem; onNavigate: () => void }) {
  const location = useLocation();
  const active = item.to === "/" ? location.pathname === "/" : location.pathname.startsWith(item.to);
  const hint = shortcutHint(item);

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        asChild
        isActive={active}
        tooltip={hint ? `${item.label} (${hint})` : item.label}
      >
        <NavLink onClick={onNavigate} to={item.to}>
          {/* The active row is marked by its surface and text colour, plus the
              aria-current NavLink sets. No accent rule down the edge. */}
          <item.icon aria-hidden />
          <span className="flex-1 truncate">{item.label}</span>
          {/* aria-hidden: the link's name is "Activity", not "Activity ⌘2".
              Printed only where it is bound (a Mac) and only for a pointer
              that has a keyboard beside it — not on a touch screen. */}
          {hint ? (
            <Kbd aria-hidden className="pointer-coarse:hidden group-data-[collapsible=icon]:hidden">
              {hint}
            </Kbd>
          ) : null}
        </NavLink>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

/**
 * The mark, the product's name and — on the icon rail, where the name is gone —
 * a status dot on the tile, so a collapsed sidebar still says whether the
 * household is protected. The dot's word is in the link's name and tooltip.
 */
function Brand({ onNavigate }: { onNavigate: () => void }) {
  const { state: sidebar, isMobile } = useSidebar();
  const { state } = useProtectionSummary();
  const rail = sidebar === "collapsed" && !isMobile;

  const link = (
    // In the phone drawer the sheet's Close sits at the header's far end, so
    // the link stops short of it instead of running underneath.
    <NavLink
      className={cn(
        "flex items-center gap-2 rounded-lg px-2 py-2 hover:bg-sidebar-accent group-data-[collapsible=icon]:px-0.5",
        isMobile && "me-12",
      )}
      onClick={onNavigate}
      to="/"
    >
      <span className="relative flex size-7 shrink-0 items-center justify-center rounded-md border border-sidebar-border bg-sidebar-primary text-sidebar-primary-foreground">
        <Mark className="size-4" />
        {rail ? <ProtectionDot className="absolute -end-1 -top-1" /> : null}
      </span>
      <span className="display-tight truncate font-semibold text-base text-foreground group-data-[collapsible=icon]:hidden">
        Cogwheel
      </span>
      {rail ? <span className="sr-only">Cogwheel, {state.label}</span> : null}
    </NavLink>
  );

  return (
    <Tooltip positioning={{ placement: "right" }}>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent hidden={!rail}>Cogwheel · {state.label}</TooltipContent>
    </Tooltip>
  );
}

export function AppSidebar() {
  const { isMobile, setOpenMobile, state } = useSidebar();
  const rail = state === "collapsed" && !isMobile;

  const closeOnMobile = () => {
    if (isMobile) setOpenMobile(false);
  };

  return (
    <Sidebar>
      <SidebarHeader>
        <Brand onNavigate={closeOnMobile} />
      </SidebarHeader>

      <SidebarContent>
        {/* No "Navigation" label: five links under a product name are
            navigation, and the heading said so to nobody. The <nav> says it
            to the people it is for. */}
        <SidebarGroup>
          <nav aria-label="Main">
            <SidebarMenu>
              {PRIMARY_NAV.map((item) => (
                <NavRow item={item} key={item.to} onNavigate={closeOnMobile} />
              ))}
            </SidebarMenu>
          </nav>
        </SidebarGroup>

        {/* Directly under the five rows rather than pinned to the bottom: on a
            900px window the bottom is 600px from where the eye is, and whether
            the household is protected is the one thing in here worth a glance.
            The state and the control that changes it are one block now. */}
        <SidebarGroup aria-label="Protection" role="group">
          {rail ? <ProtectionRailButton /> : <ProtectionPanel />}
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="border-sidebar-border border-t group-data-[collapsible=icon]:hidden">
        <ThemeToggle />
      </SidebarFooter>
    </Sidebar>
  );
}
