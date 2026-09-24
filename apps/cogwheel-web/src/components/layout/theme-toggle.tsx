import { MonitorIcon, MoonIcon, SunIcon } from "lucide-react";
import { SegmentGroup, SegmentGroupItem, SegmentGroupItemText } from "@/components/ui/segment-group";
import { useTheme, type ThemePreference } from "@/hooks/use-theme";

const OPTIONS: { value: ThemePreference; label: string; icon: React.ElementType }[] = [
  { value: "light", label: "Light", icon: SunIcon },
  { value: "dark", label: "Dark", icon: MoonIcon },
  { value: "system", label: "System", icon: MonitorIcon },
];

export function ThemeToggle({ compact = false }: { compact?: boolean }) {
  const { preference, setPreference } = useTheme();

  return (
    <SegmentGroup
      aria-label="Colour theme"
      className="rounded-lg border p-0.5"
      onValueChange={(details) => {
        if (details.value) setPreference(details.value as ThemePreference);
      }}
      value={preference}
    >
      {OPTIONS.map((option) => (
        <SegmentGroupItem
          className="flex-1 px-2 py-1"
          key={option.value}
          value={option.value}
        >
          <SegmentGroupItemText className="flex items-center gap-2 text-xs">
            <option.icon aria-hidden className="size-3.5" />
            {compact ? <span className="sr-only">{option.label}</span> : option.label}
          </SegmentGroupItemText>
        </SegmentGroupItem>
      ))}
    </SegmentGroup>
  );
}
