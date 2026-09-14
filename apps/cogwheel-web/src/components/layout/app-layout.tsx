import React from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { RotateCwIcon, WifiOffIcon } from "lucide-react";
import { useCogwheel } from "@/data/context";
import { PRIMARY_NAV } from "@/lib/nav";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { Toaster } from "@/components/ui/toast";
import { AppSidebar } from "@/components/layout/app-sidebar";

/** True when the event target is a place a bare keystroke means something else. */
function isTextEntry(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

/** ⌘/Ctrl + digit jumps between screens; a bare `/` focuses the screen's search field. */
function Shortcuts() {
  const navigate = useNavigate();

  React.useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const modifier = event.metaKey || event.ctrlKey;

      if (modifier) {
        const destination = PRIMARY_NAV.find((item) => item.digit === event.key);
        if (destination) {
          event.preventDefault();
          navigate(destination.to);
        }
        return;
      }

      if (isTextEntry(event.target)) return;

      if (event.key === "/") {
        const search = document.querySelector<HTMLInputElement>('[data-screen-search="true"]');
        if (search) {
          event.preventDefault();
          search.focus();
        }
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [navigate]);

  return null;
}

/** Persistent banner so a poll outage degrades the page instead of blanking it. */
function StaleBanner() {
  const { stale, error, lastUpdatedAt, reload, phase } = useCogwheel();
  if (!stale || phase !== "ready") return null;

  return (
    <div
      className="flex flex-wrap items-center gap-x-3 gap-y-1 border-warning/40 border-b bg-warning/10 px-4 py-2 sm:px-6"
      role="status"
    >
      <WifiOffIcon aria-hidden className="size-4 shrink-0 text-warning-foreground" />
      <p className="min-w-0 flex-1 text-foreground text-xs">
        <span className="font-medium">Showing last-known data.</span>{" "}
        {lastUpdatedAt ? `Last successful update ${formatRelative(Math.floor(lastUpdatedAt / 1000))}.` : null}{" "}
        {error ? <span className="text-muted-foreground">{error}</span> : null}
      </p>
      <Button onClick={() => void reload()} size="sm" variant="outline">
        <RotateCwIcon aria-hidden />
        Retry
      </Button>
    </div>
  );
}

export function AppLayout() {
  const location = useLocation();
  const mainRef = React.useRef<HTMLDivElement>(null);

  // Route changes must reset the scroll position; the scroll container is the
  // inset, not the document, so the browser will not do it for us.
  React.useEffect(() => {
    mainRef.current?.scrollTo({ top: 0 });
  }, [location.pathname]);

  return (
    <SidebarProvider>
      {/* First in DOM order, so the first Tab reaches it. Rendered inside the
          inset it would sit behind the whole sidebar — six focus stops past the
          point at which it would have been of any use. */}
      <a
        className={cn(
          "sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50",
          "focus:rounded-lg focus:border focus:border-border focus:bg-card focus:px-3 focus:py-2 focus:text-sm",
        )}
        href="#main"
      >
        Skip to content
      </a>

      <AppSidebar />
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-20 flex h-12 shrink-0 items-center gap-2 border-border border-b bg-background/95 px-4 backdrop-blur sm:px-6">
          <SidebarTrigger aria-label="Toggle sidebar" />
          <span className="text-muted-foreground text-xs md:hidden">Cogwheel</span>
        </header>

        <StaleBanner />

        <div className="min-h-0 flex-1 overflow-y-auto" id="main" ref={mainRef}>
          <Outlet />
        </div>
      </SidebarInset>

      <Shortcuts />
      <Toaster />
    </SidebarProvider>
  );
}
