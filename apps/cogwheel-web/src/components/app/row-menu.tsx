import { MoreHorizontalIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Menu, MenuContent, MenuItem, MenuTrigger } from "@/components/ui/menu";

export type RowAction = { value: string; label: string; destructive?: boolean; disabled?: boolean };

/**
 * The "⋯" menu that hangs off a table row. Built from a flat list rather than
 * children so the Overview and Activity rows, which offer overlapping sets of
 * the same verbs, cannot drift apart.
 */
export function RowMenu({
  label,
  actions,
  onSelect,
}: {
  /** Accessible name, e.g. "Actions for ads.example.com". */
  label: string;
  actions: RowAction[];
  onSelect: (value: string) => void;
}) {
  return (
    <Menu onSelect={(details) => onSelect(details.value)}>
      <MenuTrigger asChild>
        <Button aria-label={label} size="icon-sm" variant="ghost">
          <MoreHorizontalIcon aria-hidden />
        </Button>
      </MenuTrigger>
      <MenuContent className="min-w-52">
        {actions.map((action) => (
          <MenuItem
            disabled={action.disabled}
            key={action.value}
            value={action.value}
            variant={action.destructive ? "destructive" : "default"}
          >
            {action.label}
          </MenuItem>
        ))}
      </MenuContent>
    </Menu>
  );
}
