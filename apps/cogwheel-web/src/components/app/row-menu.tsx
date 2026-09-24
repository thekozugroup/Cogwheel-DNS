import React from "react";
import { MoreHorizontalIcon } from "lucide-react";
import { IconButton } from "@/components/ui/icon-button";
import { Menu, MenuContent, MenuItem, MenuItemGroup, MenuItemGroupLabel, MenuSeparator } from "@/components/ui/menu";

export type RowAction = {
  value: string;
  label: string;
  destructive?: boolean;
  disabled?: boolean;
  /**
   * The scope the verb acts on, e.g. "For everyone" or "On Sam's iPhone".
   * Consecutive actions with the same group sit together, named for
   * assistive technology, and a rule separates one group from the next.
   */
  group?: string;
};

/** Consecutive actions that share a group, in order. */
function runs(actions: RowAction[]): { group?: string; actions: RowAction[] }[] {
  const out: { group?: string; actions: RowAction[] }[] = [];
  for (const action of actions) {
    const last = out.at(-1);
    if (last && last.group === action.group) last.actions.push(action);
    else out.push({ group: action.group, actions: [action] });
  }
  return out;
}

/**
 * The "⋯" menu that hangs off a table row. Built from a flat list rather than
 * children so the Overview and Activity rows, which offer overlapping sets of
 * the same verbs, cannot drift apart.
 *
 * Until it is opened this is one plain button. The Ark menu — a state machine,
 * its positioner and its item registry — is mounted on open and dropped on
 * close; every row used to carry a live instance, which on a 200-row Activity
 * log was 200 menus to show the one a person clicked. The trigger is the same
 * DOM node throughout (the menu finds it through `ids.trigger`), so opening
 * never remounts it, focus goes back to it on close, and it keeps the
 * `data-slot="button"` the 44px touch rule reads.
 *
 * Keyboard: Enter, Space and ArrowDown open with the first item highlighted,
 * ArrowUp with the last, per the menu-button pattern; a mouse click opens with
 * nothing highlighted.
 */
export function RowMenu({
  label,
  actions,
  onSelect,
  icon: Icon = MoreHorizontalIcon,
  tooltip,
  tooltipPlacement,
}: {
  /** Accessible name, e.g. "Actions for ads.example.com". Also the tooltip. */
  label: string;
  actions: RowAction[];
  onSelect: (value: string) => void;
  /** The trigger glyph. Defaults to "⋯". */
  icon?: React.ElementType;
  /** Tooltip text when it should differ from the name. */
  tooltip?: string;
  tooltipPlacement?: "top" | "bottom" | "left" | "right";
}) {
  const id = React.useId();
  const triggerId = `row-menu-${id}`;
  const contentId = `${triggerId}-content`;
  const [open, setOpen] = React.useState(false);
  const [highlight, setHighlight] = React.useState<"first" | "last" | null>(null);

  const enabled = actions.filter((action) => !action.disabled);
  const initial =
    highlight === "first" ? enabled[0]?.value : highlight === "last" ? enabled.at(-1)?.value : undefined;

  const close = React.useCallback(() => {
    setOpen(false);
    setHighlight(null);
    // Ark returns focus to the trigger when the menu closes itself, but not
    // when it is unmounted mid-close. Only reclaim focus that went nowhere: a
    // click on another control is somewhere the person chose to go.
    requestAnimationFrame(() => {
      const active = document.activeElement;
      if (!active || active === document.body) document.getElementById(triggerId)?.focus({ preventScroll: true });
    });
  }, [triggerId]);

  return (
    <>
      <IconButton
        aria-controls={open ? contentId : undefined}
        aria-expanded={open}
        aria-haspopup="menu"
        data-state={open ? "open" : "closed"}
        id={triggerId}
        label={label}
        onClick={(event) => {
          if (open) {
            close();
            return;
          }
          // `detail` is 0 for a click synthesised from Enter or Space.
          setHighlight(event.detail === 0 ? "first" : null);
          setOpen(true);
        }}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            setHighlight(event.key === "ArrowDown" ? "first" : "last");
            setOpen(true);
          }
        }}
        tooltip={tooltip}
        tooltipPlacement={tooltipPlacement}
      >
        <Icon aria-hidden />
      </IconButton>

      {open ? (
        <Menu
          defaultHighlightedValue={initial}
          ids={{ trigger: triggerId, content: contentId }}
          onOpenChange={(details) => {
            if (!details.open) close();
          }}
          onSelect={(details) => onSelect(details.value)}
          open
        >
          <MenuContent className="min-w-52">
            {runs(actions).map((run, index) => {
              const items = run.actions.map((action) => (
                <MenuItem
                  disabled={action.disabled}
                  key={action.value}
                  value={action.value}
                  variant={action.destructive ? "destructive" : "default"}
                >
                  {action.label}
                </MenuItem>
              ));
              const key = run.actions[0].value;
              return (
                <React.Fragment key={key}>
                  {index > 0 ? <MenuSeparator /> : null}
                  {run.group ? (
                    <MenuItemGroup>
                      <MenuItemGroupLabel>{run.group}</MenuItemGroupLabel>
                      {items}
                    </MenuItemGroup>
                  ) : (
                    items
                  )}
                </React.Fragment>
              );
            })}
          </MenuContent>
        </Menu>
      ) : null}
    </>
  );
}
