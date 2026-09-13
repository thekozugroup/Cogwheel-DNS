import { ActivityIcon, LaptopIcon, LayoutDashboardIcon, SettingsIcon, ShieldIcon } from "lucide-react";
import type React from "react";

export type NavItem = {
  to: string;
  label: string;
  /** Shown in the sidebar. */
  shortcut?: string;
  /** The digit ⌘/Ctrl combines with; `undefined` means no numeric shortcut. */
  digit?: string;
  icon: React.ElementType;
  description: string;
};

export const PRIMARY_NAV: NavItem[] = [
  {
    to: "/",
    label: "Overview",
    shortcut: "⌘1",
    digit: "1",
    icon: LayoutDashboardIcon,
    description: "Protection state, traffic and connection instructions",
  },
  {
    to: "/activity",
    label: "Activity",
    shortcut: "⌘2",
    digit: "2",
    icon: ActivityIcon,
    description: "Live query stream",
  },
  {
    to: "/devices",
    label: "Devices",
    shortcut: "⌘3",
    digit: "3",
    icon: LaptopIcon,
    description: "Named devices and per-device policy",
  },
  {
    to: "/protection",
    label: "Protection",
    shortcut: "⌘4",
    digit: "4",
    icon: ShieldIcon,
    description: "Blocklists and block profiles",
  },
  {
    to: "/settings",
    label: "Settings",
    shortcut: "⌘5",
    digit: "5",
    icon: SettingsIcon,
    description: "What the appliance stores, and where the rest is configured",
  },
];

export const ALL_NAV = PRIMARY_NAV;
