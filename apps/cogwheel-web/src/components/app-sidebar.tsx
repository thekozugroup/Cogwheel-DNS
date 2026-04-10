import { useEffect, useState } from "react";
import {
  Shield,
  Activity,
  HardDrive,
  Moon,
  Sun,
  ChevronLeft,
  LayoutDashboard,
  Laptop,
  BrainCircuit,
  Settings,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { useCogwheel } from "@/contexts/cogwheel-context";

const navItems = [
  { key: "overview", label: "Overview", icon: LayoutDashboard },
  { key: "profiles", label: "Block Profiles", icon: Shield },
  { key: "devices", label: "Devices", icon: Laptop },
  { key: "grease-ai", label: "Grease-AI", icon: BrainCircuit },
  { key: "settings", label: "Settings", icon: Settings },
] as const;

export function AppSidebar() {
  const { state: sidebarState } = useSidebar();
  const { dashboard, state } = useCogwheel();
  const collapsed = sidebarState === "collapsed";

  const [isDark, setIsDark] = useState(() =>
    document.documentElement.classList.contains("dark"),
  );

  // activeTab is read from the dashboard's centered tabs visually,
  // but the sidebar highlights based on a simple local tracking
  const [activeTab, setActiveTab] = useState("overview");

  // Listen for tab changes from the dashboard via a custom event
  useEffect(() => {
    function handleTabChange(e: Event) {
      const detail = (e as CustomEvent<string>).detail;
      if (detail) setActiveTab(detail);
    }
    window.addEventListener("cogwheel:tab-change", handleTabChange);
    return () =>
      window.removeEventListener("cogwheel:tab-change", handleTabChange);
  }, []);

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
      : state === "error"
        ? "Offline"
        : dashboard.protection_status === "Paused"
          ? "Paused"
          : dashboard.runtime_health.degraded
            ? "Degraded"
            : "Protected";

  const protectionDot =
    protectionLabel === "Protected"
      ? "bg-emerald-400"
      : protectionLabel === "Loading"
        ? "bg-muted-foreground"
        : "bg-destructive";

  return (
    <Sidebar variant="inset" collapsible="icon">
      <SidebarHeader>
        <div className="flex items-center gap-3 px-2 py-1">
          <div className="flex size-9 shrink-0 items-center justify-center rounded-xl border border-amber-500/20 bg-amber-500/10 text-lg">
            <img
              src="/cogwheel.png"
              alt=""
              className="size-6 rounded"
              onError={(e) => {
                (e.target as HTMLImageElement).style.display = "none";
                (e.target as HTMLImageElement).parentElement!.textContent =
                  "\u2699\uFE0F";
              }}
            />
          </div>
          {!collapsed && (
            <span className="font-display text-lg">Cogwheel</span>
          )}
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel className="text-[10px] uppercase tracking-widest text-muted-foreground/60">
            Navigation
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <div className="space-y-0.5 px-1">
              {navItems.map((item) => {
                const isActive = activeTab === item.key;
                return (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => {
                      setActiveTab(item.key);
                      window.dispatchEvent(
                        new CustomEvent("cogwheel:sidebar-nav", {
                          detail: item.key,
                        }),
                      );
                    }}
                    className={`flex w-full items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm transition-colors ${
                      isActive
                        ? "bg-secondary/70 text-foreground"
                        : "text-muted-foreground hover:bg-secondary/30 hover:text-foreground"
                    }`}
                  >
                    <item.icon className="size-4 shrink-0" />
                    {!collapsed && <span>{item.label}</span>}
                  </button>
                );
              })}
            </div>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="px-4 py-3 space-y-1.5">
        {/* Protection status */}
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground/70">
          <Shield className="h-3 w-3 shrink-0 text-muted-foreground/40" />
          {!collapsed && (
            <span className="flex items-center gap-1.5">
              <span
                className={`inline-block h-1.5 w-1.5 rounded-full ${protectionDot}`}
              />
              {protectionLabel}
            </span>
          )}
        </div>

        {/* Query count */}
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground/70">
          <Activity className="h-3 w-3 shrink-0 text-muted-foreground/40" />
          {!collapsed && (
            <span className="tabular-nums">
              {dashboard.runtime_health.snapshot.queries_total.toLocaleString()}{" "}
              queries
            </span>
          )}
        </div>

        {/* Blocklist count */}
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground/70">
          <HardDrive className="h-3 w-3 shrink-0 text-muted-foreground/40" />
          {!collapsed && (
            <span className="tabular-nums">
              {dashboard.enabled_source_count.toLocaleString()} blocklists
            </span>
          )}
        </div>

        {/* Dark mode toggle + collapse trigger */}
        <div className="flex items-center justify-between pt-1">
          <button
            onClick={toggleDarkMode}
            className="inline-flex size-7 items-center justify-center rounded-lg text-muted-foreground/70 transition-colors hover:bg-muted hover:text-foreground"
            aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
          >
            {isDark ? (
              <Sun className="size-3.5" />
            ) : (
              <Moon className="size-3.5" />
            )}
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
