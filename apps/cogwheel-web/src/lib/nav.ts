import { ActivityIcon, LaptopIcon, LayoutDashboardIcon, ListIcon, SettingsIcon } from "lucide-react";
import type React from "react";

export type NavItem = {
  to: string;
  label: string;
  /** The digit ⌘ combines with on a Mac; `undefined` means no numeric shortcut. */
  digit?: string;
  icon: React.ElementType;
};

export const PRIMARY_NAV: NavItem[] = [
  { to: "/", label: "Overview", digit: "1", icon: LayoutDashboardIcon },
  { to: "/activity", label: "Activity", digit: "2", icon: ActivityIcon },
  { to: "/devices", label: "Devices", digit: "3", icon: LaptopIcon },
  { to: "/lists", label: "Lists", digit: "4", icon: ListIcon },
  { to: "/settings", label: "Settings", digit: "5", icon: SettingsIcon },
];

/**
 * Whether this is an Apple platform, where the command key exists.
 *
 * The hint used to be a literal "⌘1" on every platform, so Windows, Linux and
 * Android showed a key their keyboards do not have. `userAgentData.platform`
 * where the browser offers it, `navigator.platform` where it does not.
 */
export const IS_APPLE: boolean = (() => {
  if (typeof navigator === "undefined") return false;
  const hinted = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform;
  return /mac|iphone|ipad|ipod/i.test(hinted || navigator.platform || "");
})();

/**
 * Screen jumps are bound on macOS only, as ⌘1–⌘5.
 *
 * Off the Mac the only modifier+digit chords are the browser's: Ctrl+1–8
 * selects a tab in Chrome, Edge and Firefox on Windows, Linux and ChromeOS, and
 * Alt+1–8 does the same in Linux browsers, while Ctrl+Alt is AltGr — a
 * character key — on most European layouts. A page that binds any of them
 * takes away the way a keyboard user leaves it for another tab. There the five
 * screens are the first stops after the skip link instead.
 *
 * ⌘1–⌘5 is the same tab shortcut on a Mac and the product takes it anyway,
 * because DESIGN.md §6 documents it; that trade-off is the owner's call and is
 * flagged in the handoff rather than changed here.
 */
export const SCREEN_SHORTCUTS_BOUND = IS_APPLE;

/** True when a keydown is this platform's screen-jump chord. */
export function isScreenShortcut(event: KeyboardEvent): boolean {
  return SCREEN_SHORTCUTS_BOUND && event.metaKey && !event.ctrlKey && !event.altKey && !event.shiftKey;
}

/** The hint to print beside a nav row, or `undefined` where nothing is bound. */
export function shortcutHint(item: NavItem): string | undefined {
  return SCREEN_SHORTCUTS_BOUND && item.digit ? `⌘${item.digit}` : undefined;
}
