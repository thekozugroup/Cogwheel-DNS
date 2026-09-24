import React from "react";

/** A row's "⋯" trigger inside a list, as opposed to any other button in it. */
export const ROW_TRIGGER = '[data-row-actions] [aria-haspopup="menu"]';

/**
 * One tab stop for a list of row menus, not one per row.
 *
 * The first row's trigger is in the tab order and the arrow keys, Page Up/Down,
 * Home and End move between rows; Enter and Space still open the menu. On
 * Activity that was fifty stops before "Show 50 more", and on Overview twenty
 * before the address to copy. RowMenu has no tabIndex of its own — the list is
 * what knows which rows exist — so the stops are set here, on the triggers the
 * region holds, whenever its rows change.
 *
 * Wrap each row's RowMenu in an element carrying `data-row-actions`. Returns
 * handlers for the region, plus `leave` to forget the current row, so the next
 * visit starts on the first — in a live log, the newest.
 */
export function useRovingMenus(regionRef: React.RefObject<HTMLElement | null>) {
  const current = React.useRef<HTMLElement | null>(null);

  const sync = React.useCallback(() => {
    const region = regionRef.current;
    if (!region) return;
    const triggers = region.querySelectorAll<HTMLElement>(ROW_TRIGGER);
    let active = current.current;
    if (!active || !active.isConnected || !region.contains(active)) active = triggers[0] ?? null;
    for (const trigger of triggers) {
      const tabIndex = trigger === active ? 0 : -1;
      if (trigger.tabIndex !== tabIndex) trigger.tabIndex = tabIndex;
    }
  }, [regionRef]);

  React.useEffect(() => {
    const region = regionRef.current;
    if (!region) return;
    sync();
    const observer = new MutationObserver(sync);
    observer.observe(region, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, [regionRef, sync]);

  const onKeyDownCapture = React.useCallback(
    (event: React.KeyboardEvent<HTMLElement>) => {
      const region = regionRef.current;
      const target = event.target as HTMLElement;
      if (!region || !region.contains(target) || !target.matches(ROW_TRIGGER)) return;
      if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;

      const triggers = Array.from(region.querySelectorAll<HTMLElement>(ROW_TRIGGER));
      const index = triggers.indexOf(target);
      const last = triggers.length - 1;
      const step: Record<string, number> = {
        ArrowDown: index + 1,
        ArrowUp: index - 1,
        PageDown: index + 10,
        PageUp: index - 10,
        Home: 0,
        End: last,
      };
      if (!(event.key in step)) return;

      // Captured before RowMenu's own handler, which would open the menu on
      // ArrowDown/ArrowUp. Enter and Space still open it.
      event.preventDefault();
      event.stopPropagation();
      const next = triggers[Math.max(0, Math.min(last, step[event.key]))];
      if (!next || next === target) return;
      current.current = next;
      sync();
      // The wrapper carries whatever scroll margin keeps it clear of a sticky
      // header, so the row lands below it rather than under it.
      next.closest("[data-row-actions]")?.scrollIntoView({ block: "nearest" });
      next.focus({ preventScroll: true });
    },
    [regionRef, sync],
  );

  /** Call from the region's onFocus: a trigger that took focus becomes the stop. */
  const noteFocus = React.useCallback(
    (target: EventTarget) => {
      const region = regionRef.current;
      if (target instanceof HTMLElement && region?.contains(target) && target.matches(ROW_TRIGGER)) {
        current.current = target;
        sync();
      }
    },
    [regionRef, sync],
  );

  const leave = React.useCallback(() => {
    current.current = null;
    sync();
  }, [sync]);

  return { onKeyDownCapture, noteFocus, leave };
}
