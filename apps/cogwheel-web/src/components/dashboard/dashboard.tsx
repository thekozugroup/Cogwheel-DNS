import { useState, useEffect } from "react";
import { RotateCw, Pause, Play } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ThemeToggle } from "@/components/theme-toggle";
import { useCogwheel } from "@/contexts/cogwheel-context";
import { OverviewTab } from "./overview-tab";
import { ProfilesTab } from "./profiles-tab";
import { DevicesTab } from "./devices-tab";
import { GreaseAiTab } from "./grease-ai-tab";
import { SettingsTab } from "./settings-tab";

type TabKey = "overview" | "profiles" | "devices" | "grease-ai" | "settings";

const TABS: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "profiles", label: "Profiles" },
  { key: "devices", label: "Devices" },
  { key: "grease-ai", label: "Grease-AI" },
  { key: "settings", label: "Settings" },
];

export function Dashboard() {
  const [activeTab, setActiveTabState] = useState<TabKey>("overview");

  function setActiveTab(tab: TabKey) {
    setActiveTabState(tab);
    // Notify sidebar of tab change
    window.dispatchEvent(
      new CustomEvent("cogwheel:tab-change", { detail: tab }),
    );
  }

  // Listen for sidebar navigation events
  useEffect(() => {
    function handleSidebarNav(e: Event) {
      const detail = (e as CustomEvent<string>).detail;
      if (detail) setActiveTabState(detail as TabKey);
    }
    window.addEventListener("cogwheel:sidebar-nav", handleSidebarNav);
    return () =>
      window.removeEventListener("cogwheel:sidebar-nav", handleSidebarNav);
  }, []);

  const {
    refreshLiveData,
    dashboard,
    busyAction,
    handlePauseRuntime,
    handleResumeRuntime,
  } = useCogwheel();

  const isPaused = dashboard.protection_status === "Paused";

  function handleRefresh() {
    void refreshLiveData();
  }

  return (
    <div className="flex h-full flex-col">
      {/* Header with centered tabs + action buttons */}
      <header className="relative flex shrink-0 items-center border-b border-border px-4 md:px-6 py-2">
        {/* Centered tabs */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <nav
            className="flex items-center gap-1 rounded-lg bg-muted/50 p-0.5 pointer-events-auto"
            role="tablist"
          >
            {TABS.map((tab) => (
              <button
                key={tab.key}
                role="tab"
                aria-selected={activeTab === tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`rounded-md px-3 py-1 text-xs font-medium transition-all ${
                  activeTab === tab.key
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Action buttons on right */}
        <div className="relative z-10 flex items-center gap-2">
          <ThemeToggle />
          <Button
            size="sm"
            variant="secondary"
            className="gap-1.5 text-xs"
            onClick={handleRefresh}
          >
            <RotateCw className="h-3 w-3" /> Refresh
          </Button>
          <Button
            size="sm"
            variant={isPaused ? "default" : "outline"}
            className="gap-1.5 text-xs"
            onClick={() =>
              isPaused
                ? void handleResumeRuntime()
                : void handlePauseRuntime(10)
            }
            disabled={
              busyAction === "pause-runtime" || busyAction === "resume-runtime"
            }
          >
            {isPaused ? (
              <>
                <Play className="h-3 w-3" /> Resume
              </>
            ) : (
              <>
                <Pause className="h-3 w-3" /> Pause
              </>
            )}
          </Button>
        </div>
      </header>

      {/* Tab content */}
      <ScrollArea className="min-h-0 flex-1 overflow-hidden">
        <div key={activeTab} className="animate-fade-in">
          {activeTab === "overview" && <OverviewTab />}
          {activeTab === "profiles" && <ProfilesTab />}
          {activeTab === "devices" && <DevicesTab />}
          {activeTab === "grease-ai" && <GreaseAiTab />}
          {activeTab === "settings" && <SettingsTab />}
        </div>
      </ScrollArea>
    </div>
  );
}
