import { NavLink, useLocation } from "react-router-dom";
import { ActivityIcon, CogIcon, ListIcon } from "lucide-react";
import { PRIMARY_NAV, type NavItem } from "@/lib/nav";
import { formatCount, pluralize } from "@/lib/format";
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

  const closeOnMobile = () => {
    if (isMobile) setOpenMobile(false);
  };

  // "Unreachable" means we have never had an answer, not that one poll missed;
  // a single failed poll is the StaleBanner's job, not the status line's.
  const offline = Boolean(error) && lastUpdatedAt === null;
  const state = protectionState(data.overview.protection.paused_until, offline);
  const day = data.overview.last_24h;

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
          className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-sidebar-accent"
          onClick={closeOnMobile}
          to="/"
        >
          <span className="flex size-7 shrink-0 items-center justify-center rounded-md border border-sidebar-border bg-sidebar-primary text-sidebar-primary-foreground">
            <CogIcon aria-hidden className="size-4" />
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
      </SidebarContent>

      <SidebarFooter className="gap-3 border-sidebar-border border-t group-data-[collapsible=icon]:hidden">
        <div className="space-y-1.5 px-1">
          <p className="flex items-center gap-2 text-foreground text-xs">
            <Status size="sm" variant={statusVariant} />
            <span className="font-medium">{state.label}</span>
          </p>
          <p className="tabular flex items-center gap-2 text-muted-foreground text-xs">
            <ActivityIcon aria-hidden className="size-3.5" />
            {pluralize(day.queries, "query", "queries")} · {formatCount(day.blocked)} blocked (24 h)
          </p>
          <p className="tabular flex items-center gap-2 text-muted-foreground text-xs">
            <ListIcon aria-hidden className="size-3.5" />
            {pluralize(data.overview.lists.enabled, "enabled list")}
          </p>
        </div>

        <PauseControl />

        <ThemeToggle />
      </SidebarFooter>
    </Sidebar>
  );
}
