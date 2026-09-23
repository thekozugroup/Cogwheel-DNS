import { NavLink, useLocation } from "react-router-dom";
import { ListIcon } from "lucide-react";
import { PRIMARY_NAV, type NavItem } from "@/lib/nav";
import { pluralize } from "@/lib/format";
import { protectionState } from "@/lib/derive";
import { useCogwheel } from "@/data/context";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { Kbd } from "@/components/ui/kbd";
import { Status } from "@/components/ui/status";
import { Mark } from "@/components/layout/mark";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { PauseControl } from "@/components/layout/pause-control";

function NavRow({ item, onNavigate }: { item: NavItem; onNavigate: () => void }) {
  const location = useLocation();
  const active = item.to === "/" ? location.pathname === "/" : location.pathname.startsWith(item.to);

  return (
    <SidebarMenuItem>
      <SidebarMenuButton
        asChild
        isActive={active}
        tooltip={item.shortcut ? `${item.label} (${item.shortcut})` : item.label}
      >
        <NavLink onClick={onNavigate} to={item.to}>
          {/* The active row is marked by its surface and text colour, plus the
              aria-current NavLink sets. No accent rule down the edge. */}
          <item.icon aria-hidden />
          <span className="flex-1 truncate">{item.label}</span>
          {item.shortcut ? (
            <Kbd className="group-data-[collapsible=icon]:hidden">{item.shortcut}</Kbd>
          ) : null}
        </NavLink>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

export function AppSidebar() {
  const { data, error, lastUpdatedAt } = useCogwheel();
  const { isMobile, setOpenMobile } = useSidebar();
  const location = useLocation();

  const closeOnMobile = () => {
    if (isMobile) setOpenMobile(false);
  };

  // "Unreachable" means we have never had an answer, not that one poll missed;
  // a single failed poll is the StaleBanner's job, not the status line's.
  const offline = Boolean(error) && lastUpdatedAt === null;
  const state = protectionState(data.overview.protection.paused_until, offline);

  // Overview's Protection tile says the same word behind the same dot a hand's
  // width away, and says more besides — the pause countdown, the Resume button,
  // whether the lists have downloaded. One of the two has to go, and on the
  // other four screens this row is the only protection readout there is. The
  // exception is an outage: the tile is drawn from last-known data and cannot
  // know, so the row comes back to say so.
  const showProtection = location.pathname !== "/" || offline;

  const statusVariant =
    state.tone === "good"
      ? "success"
      : state.tone === "warn"
        ? "warning"
        : state.tone === "bad"
          ? "destructive"
          : "default";

  return (
    <Sidebar>
      <SidebarHeader>
        <NavLink
          className="flex items-center gap-2 rounded-lg px-2 py-2 hover:bg-sidebar-accent"
          onClick={closeOnMobile}
          to="/"
        >
          <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-sidebar-border bg-sidebar-primary text-sidebar-primary-foreground">
            <Mark className="size-4" />
          </span>
          <span className="display-tight truncate font-semibold text-base text-foreground group-data-[collapsible=icon]:hidden">
            Cogwheel
          </span>
        </NavLink>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Navigation</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {PRIMARY_NAV.map((item) => (
                <NavRow item={item} key={item.to} onNavigate={closeOnMobile} />
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
        {/* Directly under the five nav rows rather than pinned to the bottom.
            On a 900px window that left roughly 600px of empty sidebar between
            the two, and put the one thing worth glancing at — whether the
            household is protected — as far from the eye as the chrome allows.

            Two facts, both of which hold wherever you are in the product and
            neither of which is a count. The 24-hour query and blocked totals
            used to sit here too, and on Overview they restated the two tiles
            eight inches to the right — the same numbers, a second time, in a
            place that cannot act on them. They belong on the page that is
            about them. */}
        <SidebarGroup className="group-data-[collapsible=icon]:hidden">
          <SidebarGroupLabel>Right now</SidebarGroupLabel>
          <SidebarGroupContent className="space-y-2 px-2 py-1">
            {showProtection ? (
              <p className="flex items-center gap-2 text-foreground text-sm">
                <Status size="sm" variant={statusVariant} />
                <span className="font-medium">{state.label}</span>
              </p>
            ) : null}
            <p className="tabular flex items-center gap-2 text-muted-foreground text-sm">
              <ListIcon aria-hidden className="size-3.5 shrink-0" />
              {pluralize(data.overview.lists.enabled, "enabled list")}
            </p>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="gap-3 border-sidebar-border border-t group-data-[collapsible=icon]:hidden">
        <PauseControl />

        <ThemeToggle />
      </SidebarFooter>
    </Sidebar>
  );
}
