import { useEffect, useState } from "react";
import {
  Shield,
  Activity,
  HardDrive,
  Cog,
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
  SidebarHeader,
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
  const { dashboard, state } = useCogwheel();
  const { isMobile, setOpenMobile } = useSidebar();

  const [activeTab, setActiveTab] = useState("overview");

  useEffect(() => {
    function handleTabChange(e: Event) {
      const detail = (e as CustomEvent<string>).detail;
      if (detail) setActiveTab(detail);
    }
    window.addEventListener("cogwheel:tab-change", handleTabChange);
    return () =>
      window.removeEventListener("cogwheel:tab-change", handleTabChange);
  }, []);

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
    <Sidebar className="border-r border-sidebar-border">
      <SidebarHeader className="p-4">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
            <Cog className="h-4.5 w-4.5 text-primary" />
          </div>
          <h1 className="font-display text-xl font-normal tracking-tight">
            Cogwheel
          </h1>
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <div className="flex items-center justify-between px-4 py-1">
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground/60 font-medium">
              Navigation
            </span>
          </div>

          <SidebarGroupContent>
            <div className="px-2">
              {navItems.map((item) => {
                const isActive = activeTab === item.key;
                return (
                  <button
                    key={item.key}
                    type="button"
                    aria-label={item.label}
                    aria-pressed={isActive}
                    onClick={() => {
                      setActiveTab(item.key);
                      window.dispatchEvent(
                        new CustomEvent("cogwheel:sidebar-nav", {
                          detail: item.key,
                        }),
                      );
                      if (isMobile) setOpenMobile(false);
                    }}
                    className={`group relative flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left transition-colors mb-0.5 ${
                      isActive
                        ? "bg-secondary/70"
                        : "hover:bg-secondary/30"
                    }`}
                  >
                    {/* Active indicator bar */}
                    {isActive && (
                      <span className="absolute left-0 top-1/2 -translate-y-1/2 h-4 w-[3px] rounded-r-sm bg-primary" />
                    )}
                    <item.icon
                      className={`h-4 w-4 shrink-0 ${
                        isActive
                          ? "text-foreground"
                          : "text-muted-foreground/60"
                      }`}
                    />
                    <span
                      className={`text-sm ${
                        isActive
                          ? "text-foreground font-medium"
                          : "text-foreground/80"
                      }`}
                    >
                      {item.label}
                    </span>
                  </button>
                );
              })}
            </div>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="px-4 py-3 space-y-1.5">
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground/70">
          <Shield className="h-3 w-3 shrink-0 text-muted-foreground/40" />
          <span className="flex items-center gap-1.5">
            <span
              className={`inline-block h-1.5 w-1.5 rounded-full ${protectionDot}`}
            />
            {protectionLabel}
          </span>
        </div>

        <div className="flex items-center gap-2 text-[11px] text-muted-foreground/70">
          <Activity className="h-3 w-3 shrink-0 text-muted-foreground/40" />
          <span className="tabular-nums">
            {dashboard.runtime_health.snapshot.queries_total.toLocaleString()}{" "}
            queries
          </span>
        </div>

        <div className="flex items-center gap-2 text-[11px] text-muted-foreground/70">
          <HardDrive className="h-3 w-3 shrink-0 text-muted-foreground/40" />
          <span className="tabular-nums">
            {dashboard.enabled_source_count.toLocaleString()} blocklists
          </span>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
