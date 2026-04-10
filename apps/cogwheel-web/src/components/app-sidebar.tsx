import { useLocation, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import {
  LayoutDashboard,
  Shield,
  Laptop,
  BrainCircuit,
  Settings,
  ChevronLeft,
  Moon,
  Sun,
} from "lucide-react";
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
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { Badge } from "@/components/ui/badge";
import { useCogwheel } from "@/contexts/cogwheel-context";

const navItems = [
  { path: "/", label: "Overview", icon: LayoutDashboard },
  { path: "/profiles", label: "Block Profiles", icon: Shield },
  { path: "/devices", label: "Devices", icon: Laptop },
  { path: "/grease-ai", label: "Grease-AI", icon: BrainCircuit },
  { path: "/settings", label: "Settings", icon: Settings },
];

export function AppSidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { state: sidebarState } = useSidebar();
  const { dashboard, state, error } = useCogwheel();
  const collapsed = sidebarState === "collapsed";

  const [isDark, setIsDark] = useState(() =>
    document.documentElement.classList.contains("dark"),
  );

  useEffect(() => {
    const saved = localStorage.getItem("cogwheel-theme");
    if (saved === "dark") {
      document.documentElement.classList.add("dark");
      setIsDark(true);
    }
  }, []);

  function toggleDarkMode() {
    const next = !isDark;
    setIsDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("cogwheel-theme", next ? "dark" : "light");
  }

  const protectionLabel =
    state === "loading"
      ? "Loading"
      : error
        ? "Offline"
        : dashboard.protection_status === "Paused"
          ? "Paused"
          : dashboard.runtime_health.degraded
            ? "Degraded"
            : "Protected";

  const protectionTone =
    protectionLabel === "Protected"
      ? "bg-primary/10 text-primary"
      : protectionLabel === "Loading"
        ? "bg-secondary text-secondary-foreground"
        : "bg-accent/10 text-accent";

  return (
    <Sidebar variant="inset" collapsible="icon">
      <SidebarHeader>
        <div className="flex items-center gap-3 px-2 py-1">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-border bg-muted text-lg">
            <img
              src="/cogwheel.png"
              alt=""
              className="size-6 rounded"
              onError={(e) => {
                (e.target as HTMLImageElement).style.display = "none";
                (e.target as HTMLImageElement).parentElement!.textContent = "\u2699\uFE0F";
              }}
            />
          </div>
          {!collapsed && (
            <div className="flex flex-col">
              <span className="font-display text-lg">
                Cogwheel
              </span>
              <span className="text-[10px] tracking-wider text-muted-foreground">DNS Control Plane</span>
            </div>
          )}
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Navigation</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => {
                const isActive = location.pathname === item.path;
                return (
                  <SidebarMenuItem key={item.path}>
                    <SidebarMenuButton
                      isActive={isActive}
                      onClick={() => navigate(item.path)}
                      tooltip={item.label}
                    >
                      <item.icon className="size-4" />
                      <span>{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <div className="flex items-center justify-between px-2 py-1">
          {!collapsed && (
            <Badge className={`${protectionTone}${protectionLabel === "Offline" || protectionLabel === "Degraded" ? " animate-pulse" : ""}`}>{protectionLabel}</Badge>
          )}
          <button
            onClick={toggleDarkMode}
            className="inline-flex size-8 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
          >
            {isDark ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </button>
          <SidebarTrigger>
            <ChevronLeft
              className={`size-4 transition-transform ${collapsed ? "rotate-180" : ""}`}
            />
          </SidebarTrigger>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
