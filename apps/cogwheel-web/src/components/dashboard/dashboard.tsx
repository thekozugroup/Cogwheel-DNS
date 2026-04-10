import { useState, useEffect } from "react";
import { RotateCw, Pause, Play } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardFooter,
  CardHeader,
} from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
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
    state,
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
      <header className="flex shrink-0 flex-col gap-2 border-b border-border px-4 md:px-6 py-2 md:relative md:flex-row md:items-center">
        {/* Centered tabs -- scrollable on mobile, absolutely centered on md+ */}
        <div className="overflow-x-auto -mx-4 px-4 md:mx-0 md:px-0 md:absolute md:inset-0 md:flex md:items-center md:justify-center md:pointer-events-none">
          <nav
            className="flex items-center gap-1 rounded-lg bg-muted/50 p-0.5 md:pointer-events-auto"
            role="tablist"
          >
            {TABS.map((tab) => (
              <button
                key={tab.key}
                role="tab"
                aria-selected={activeTab === tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`whitespace-nowrap rounded-md px-3 py-1 text-xs font-medium transition-all ${
                  activeTab === tab.key
                    ? "bg-background text-foreground shadow-sm ring-1 ring-foreground/5"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Spacer -- hidden on mobile where layout is stacked */}
        <div className="hidden md:block md:flex-1" />

        {/* Action buttons on right */}
        <div className="relative z-10 flex items-center gap-2">
          <ThemeToggle />
          <Button
            size="sm"
            variant="ghost"
            className="gap-1.5 text-xs text-muted-foreground hover:text-foreground"
            onClick={handleRefresh}
          >
            <RotateCw className="h-3 w-3" /> <span className="hidden sm:inline">Refresh</span>
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
                <Play className="h-3 w-3" /> <span className="hidden sm:inline">Resume</span>
              </>
            ) : (
              <>
                <Pause className="h-3 w-3" /> <span className="hidden sm:inline">Pause</span>
              </>
            )}
          </Button>
        </div>
      </header>

      {/* Tab content */}
      <ScrollArea className="min-h-0 flex-1 overflow-hidden">
        {state === "loading" ? (
          <div className="p-4 md:p-6 space-y-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
              {[1, 2, 3, 4].map((i) => (
                <Card key={i}>
                  <CardHeader>
                    <Skeleton className="h-4 w-24" />
                    <Skeleton className="h-8 w-16 mt-2" />
                  </CardHeader>
                  <CardFooter className="flex-col items-start gap-2">
                    <Skeleton className="h-3 w-32" />
                    <Skeleton className="h-3 w-20" />
                  </CardFooter>
                </Card>
              ))}
            </div>
            <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
              {[1, 2].map((i) => (
                <Card key={i}>
                  <CardHeader>
                    <Skeleton className="h-5 w-40" />
                    <Skeleton className="h-3 w-56 mt-1" />
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {[1, 2, 3].map((j) => (
                        <Skeleton key={j} className="h-4 w-full" />
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        ) : (
          <div key={activeTab} className="animate-fade-in">
            {activeTab === "overview" && <OverviewTab />}
            {activeTab === "profiles" && <ProfilesTab />}
            {activeTab === "devices" && <DevicesTab />}
            {activeTab === "grease-ai" && <GreaseAiTab />}
            {activeTab === "settings" && <SettingsTab />}
          </div>
        )}
      </ScrollArea>
    </div>
  );
}
