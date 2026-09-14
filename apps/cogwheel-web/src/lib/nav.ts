import { ActivityIcon, LaptopIcon, LayoutDashboardIcon, ListIcon, SettingsIcon } from "lucide-react";
import type React from "react";

export type NavItem = {
  to: string;
  label: string;
  /** Shown in the sidebar. */
  shortcut?: string;
  /** The digit ⌘/Ctrl combines with; `undefined` means no numeric shortcut. */
  digit?: string;
  icon: React.ElementType;
};

export const PRIMARY_NAV: NavItem[] = [
  {
    to: "/",
    label: "Overview",
    shortcut: "⌘1",
    digit: "1",
    icon: LayoutDashboardIcon,
  },
  {
    to: "/activity",
    label: "Activity",
    shortcut: "⌘2",
    digit: "2",
    icon: ActivityIcon,
  },
  {
    to: "/devices",
    label: "Devices",
    shortcut: "⌘3",
    digit: "3",
    icon: LaptopIcon,
  },
  {
    to: "/lists",
    label: "Lists",
    shortcut: "⌘4",
    digit: "4",
    icon: ListIcon,
  },
  {
    to: "/settings",
    label: "Settings",
    shortcut: "⌘5",
    digit: "5",
    icon: SettingsIcon,
  },
];
