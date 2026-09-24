import React from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { RotateCwIcon, WifiOffIcon } from "lucide-react";
import { useCogwheelActions, useCogwheelStatus, useLastUpdatedAt, useSnapshot } from "@/data/context";
import { emptyOverview } from "@/lib/constants";
import { PRIMARY_NAV, isScreenShortcut } from "@/lib/nav";
import { formatRelative } from "@/lib/format";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { SidebarInset, SidebarProvider, SidebarTrigger, useSidebar } from "@/components/ui/sidebar";
import { Toaster } from "@/components/ui/toast";
import { AppSidebar } from "@/components/layout/app-sidebar";
import { Mark } from "@/components/layout/mark";
import { ProtectionChip } from "@/components/layout/protection";
import { useProtectionSummary } from "@/components/layout/protection-state";

/** True when the event target is a place a bare keystroke means something else. */
function isTextEntry(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

/**
 * ⌘ + digit jumps between screens on a Mac (lib/nav.ts says why only there);
 * a bare `/` focuses the screen's search field everywhere.
 */
function Shortcuts() {
  const navigate = useNavigate();

  React.useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (isScreenShortcut(event)) {
        const destination = PRIMARY_NAV.find((item) => item.digit === event.key);
        if (destination) {
          event.preventDefault();
          navigate(destination.to);
        }
        return;
      }

      if (event.metaKey || event.ctrlKey || event.altKey || isTextEntry(event.target)) return;

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

/**
 * Persistent banner so a poll outage degrades the page instead of blanking it.
 *
 * The live region is always mounted and the banner is put into it, so its
 * arrival is announced; it is the one notice of an outage (there used to be a
 * toast as well, saying the same thing and then leaving while the outage
 * stayed).
 */
function StaleBanner() {
  const { stale, phase } = useCogwheelStatus();
  // The body is the only reader of the poll clock, and it is mounted only while
  // the data is stale: a healthy poll then renders no component at all.
  return <div role="status">{stale && phase === "ready" ? <StaleBannerBody /> : null}</div>;
}

function StaleBannerBody() {
  const { error } = useCogwheelStatus();
  const { reload } = useCogwheelActions();
  const lastUpdatedAt = useLastUpdatedAt();
  // Nothing has ever loaded, from the network or the cache: there is no
  // last-known data to be showing, and saying so was the first thing a person
  // read on an appliance that had never answered.
  const never = useSnapshot("overview") === emptyOverview;

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-warning/40 border-t bg-warning/10 px-[16px] py-2 sm:px-gutter">
      <WifiOffIcon aria-hidden className="size-4 shrink-0 text-warning-foreground" />
      {/* All of it in --foreground. The error used to be --muted-foreground,
          4.49:1 on the yellow tint — the one sentence that says what went
          wrong, a hair under the floor. Weight separates the two parts. */}
      <p className="min-w-0 flex-1 text-foreground text-sm">
        <span className="font-medium">{never ? "Cogwheel is not answering." : "Showing last-known data."}</span>{" "}
        {!never && lastUpdatedAt ? `Last successful update ${formatRelative(Math.floor(lastUpdatedAt / 1000))}.` : null}{" "}
        {error ? <span>{error}</span> : null}
      </p>
      <Button onClick={() => void reload()} size="sm" variant="outline">
        <RotateCwIcon aria-hidden />
        Retry
      </Button>
    </div>
  );
}

/**
 * The top bar. On a phone it is the only chrome the product has; with the
 * sidebar collapsed to the rail it is the only place with room for words. So
 * this is where a paused or unreachable appliance says so when the sidebar
 * cannot — see ProtectionChip.
 */
function TopBar() {
  const { isMobile } = useSidebar();
  const { state } = useProtectionSummary();
  // At 375px the trigger, the mark, the wordmark and "Paused · 12:31 left ·
  // Resume" do not fit on one line. The chip is the one that has to.
  const chipShown = isMobile && state.tone !== "good";

  return (
    <header className="sticky top-0 z-20 shrink-0 border-border border-b bg-background/95 backdrop-blur">
      <div className="flex h-12 items-center gap-2 px-[16px] sm:px-gutter">
        <SidebarTrigger />
        {/* The wordmark was 12px muted grey here, which read as a breadcrumb
            rather than as the thing you are looking at. */}
        <span className="flex min-w-0 items-center gap-2 md:hidden">
          <Mark className="size-4 shrink-0 text-foreground" />
          <span className={cn("display-tight font-semibold text-foreground text-sm", chipShown && "max-sm:sr-only")}>
            Cogwheel
          </span>
        </span>
        <span className="ms-auto flex min-w-0 items-center">
          <ProtectionChip />
        </span>
      </div>
      <StaleBanner />
    </header>
  );
}

export function AppLayout() {
  const location = useLocation();
  const mainRef = React.useRef<HTMLElement>(null);

  // Route changes must reset the scroll position; the scroll container is
  // <main>, not the document, so the browser will not do it for us.
  React.useEffect(() => {
    mainRef.current?.scrollTo({ top: 0 });
  }, [location.pathname]);

  return (
    <SidebarProvider>
      {/* First in DOM order, so the first Tab reaches it. Rendered inside the
          inset it would sit behind the whole sidebar — six focus stops past the
          point at which it would have been of any use.

          It moves focus itself rather than trusting the fragment: <main> is a
          scroll container inside the page, not the document, and a target that
          cannot take focus leaves the next Tab starting from the top again. */}
      <a
        className={cn(
          "sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50",
          "focus:rounded-lg focus:border focus:border-border focus:bg-card focus:px-3 focus:py-2 focus:text-sm",
        )}
        href="#main"
        onClick={(event) => {
          event.preventDefault();
          mainRef.current?.focus();
        }}
      >
        Skip to content
      </a>

      <AppSidebar />
      <SidebarInset>
        <TopBar />

        {/* tabIndex -1: focusable by the skip link, not a Tab stop. No ring: it
            is the whole page, and the next Tab lands on its first control. */}
        <main className="min-h-0 flex-1 overflow-y-auto focus-visible:outline-none" id="main" ref={mainRef} tabIndex={-1}>
          <Outlet />
        </main>
      </SidebarInset>

      <Shortcuts />
      <Toaster />
    </SidebarProvider>
  );
}
