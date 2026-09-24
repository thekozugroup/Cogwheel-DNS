import React from "react";
import { ListIcon, PlusIcon, RotateCwIcon } from "lucide-react";
import { api, type ListSource } from "@/lib/api";
import { devicesOnlyOnList, listErrorSentence, listKindLabel, onlyListSentence } from "@/lib/derive";
import { emptyLists } from "@/lib/constants";
import { formatCount, formatRelative, pluralize, truncateUrl } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useCogwheelActions, useCogwheelStatus, useSnapshot } from "@/data/context";
import { Button } from "@/components/ui/button";
import { IconButton } from "@/components/ui/icon-button";
import { Badge } from "@/components/ui/badge";
import { Status } from "@/components/ui/status";
import { Switch } from "@/components/ui/switch";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, NarrowRow, type Column } from "@/components/app/data-table";
import { RowMenu } from "@/components/app/row-menu";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { AddList } from "./lists/add-list";
import { CheckDomain } from "./lists/check-domain";
import { RulesCard } from "./lists/rules";

type Pending = { kind: "delete" | "disable"; list: ListSource };
type DialogCopy = { title: string; description: string; consequence?: string; confirmLabel: string };

export function ListsScreen() {
  const catalogue = useSnapshot("lists");
  const { devices } = useSnapshot("devices");
  const { phase, error, busy } = useCogwheelStatus();
  const { mutate, reload } = useCogwheelActions();
  // The dialog's copy is fixed when it opens. Worked out on every render, it
  // changed under the spinner — the optimistic disable and the refetch after
  // a delete both move the numbers it is made from — and it went blank while
  // the dialog animated closed.
  const [pending, setPending] = React.useState<(Pending & { copy: DialogCopy }) | null>(null);
  const [confirming, setConfirming] = React.useState(false);
  const deleted = React.useRef(false);

  // After a delete, the row — and the "⋯" the dialog hands focus back to —
  // is gone. Once the dialog has finished closing, focus that went nowhere
  // lands on the card's own button instead of the page body.
  React.useEffect(() => {
    if (confirming || !deleted.current) return;
    deleted.current = false;
    const timer = window.setTimeout(() => {
      const current = document.activeElement;
      // Still inside the dialog as it animates out counts as nowhere: the
      // dialog is about to unmount and take that focus with it.
      if (!current || current === document.body || current.closest('[role="alertdialog"]')) {
        addButton.current?.focus();
      }
    }, 300);
    return () => window.clearTimeout(timer);
  }, [confirming]);
  const [adding, setAdding] = React.useState(false);
  const addButton = React.useRef<HTMLButtonElement>(null);

  // Ordered by name, case-insensitively, with anything broken first. The
  // server returns them in `sources.id` order, which is a UUID: arbitrary, and
  // it reshuffles every time a list is added. A list that failed to download
  // is the one row on this page that wants acting on, so it sorts to the top.
  const lists = React.useMemo(
    () =>
      [...catalogue.lists].sort((left, right) => {
        const broken = Number(Boolean(right.last_error)) - Number(Boolean(left.last_error));
        if (broken !== 0) return broken;
        return left.name.localeCompare(right.name, undefined, { sensitivity: "base" });
      }),
    [catalogue.lists],
  );
  const enabled = React.useMemo(
    () => new Set(catalogue.lists.filter((list) => list.enabled).map((list) => list.id)),
    [catalogue.lists],
  );

  /**
   * What stops being filtered if this list stops applying: the devices that
   * use it and nothing else, or — when it is the last list on — everyone.
   * Null when nothing a person would notice changes beyond the list itself.
   */
  const fallout = (list: ListSource): string | null => {
    if (!list.enabled) return null;
    if (enabled.size === 1) {
      return "It is the only list switched on. No list will block anything, for any device, until another is added or enabled.";
    }
    const stranded = devicesOnlyOnList(list.id, devices, enabled);
    return stranded.length > 0 ? onlyListSentence(stranded.map((device) => device.name)) : null;
  };

  const setEnabled = (list: ListSource, next: boolean) =>
    mutate({
      key: `list-toggle-${list.id}`,
      action: () => api.updateList(list.id, { enabled: next }),
      successTitle: next ? "List enabled" : "List disabled",
      successDetail: list.name,
      failureTitle: next ? "Could not enable the list" : "Could not disable the list",
      // The switch flips at once and snaps back if the server rejects it.
      optimistic: {
        lists: {
          ...catalogue,
          lists: catalogue.lists.map((entry) => (entry.id === list.id ? { ...entry, enabled: next } : entry)),
        },
      },
    });

  // Turning a list off is instant unless something depends on it; then the
  // devices that would be left unfiltered are named first.
  const ask = (kind: Pending["kind"], list: ListSource) => {
    setPending({ kind, list, copy: dialogCopy({ kind, list }, fallout(list)) });
    setConfirming(true);
  };

  const toggle = (list: ListSource, next: boolean) => {
    if (!next && fallout(list)) ask("disable", list);
    else void setEnabled(list, next);
  };

  const refresh = (list?: ListSource) =>
    mutate({
      key: list ? `list-refresh-${list.id}` : "list-refresh-all",
      action: () => api.refreshLists(list?.id),
      successTitle: "Refreshed",
      successDetail: (results) =>
        results.map((result) => `${result.name}: ${result.outcome}`).join(" · ") || "Nothing to do.",
      failureTitle: "Could not refresh",
    });

  const remove = (list: ListSource) =>
    mutate({
      key: `list-delete-${list.id}`,
      action: () => api.deleteList(list.id),
      successTitle: "List deleted",
      successDetail: list.name,
      failureTitle: `Could not delete ${list.name}`,
    });

  const refreshingAll = busy === "list-refresh-all";
  const isRefreshing = (row: ListSource) => refreshingAll || busy === `list-refresh-${row.id}`;

  const openAdd = (open: boolean) => {
    setAdding(open);
    if (!open) requestAnimationFrame(() => addButton.current?.focus());
  };
  const addToggle = (
    <Button
      aria-controls="add-list"
      aria-expanded={adding}
      onClick={() => openAdd(!adding)}
      ref={addButton}
      variant="outline"
    >
      <PlusIcon aria-hidden />
      Add a list
    </Button>
  );

  // While "Disable …?" is open the switch shows off: it follows the hand that
  // moved it, and Cancel visibly puts it back. Holding it on while the dialog
  // asked also left the hidden checkbox a screen reader reads saying "off".
  const enabledSwitch = (row: ListSource) => (
    <Switch
      aria-label={`Enable ${row.name}`}
      checked={row.enabled && !(confirming && pending?.kind === "disable" && pending.list.id === row.id)}
      disabled={busy === `list-toggle-${row.id}`}
      onCheckedChange={(details) => toggle(row, details.checked)}
    />
  );

  const updated = (row: ListSource) =>
    isRefreshing(row) ? "Refreshing…" : row.last_ok_at ? formatRelative(row.last_ok_at) : "Never";

  const columns: Column<ListSource>[] = [
    {
      key: "name",
      header: "Name",
      wrap: true,
      // Name, address, and — only when there is one — what went wrong, as two
      // plain lines under the address. A pill is for a word or two.
      render: (row) => (
        <div className="min-w-0">
          <span className="block truncate text-foreground">{row.name}</span>
          <span className="block truncate font-mono text-muted-foreground text-xs" title={row.url}>
            {truncateUrl(row.url, 60)}
          </span>
          {row.last_error ? (
            <span className="mt-2 block">
              <span className="flex items-center gap-2 font-medium text-foreground text-sm">
                <Status size="sm" variant="destructive" />
                Download failed
              </span>
              <span className="block text-muted-foreground text-sm">{listErrorSentence(row.last_error)}</span>
            </span>
          ) : row.note ? (
            <span className="mt-1 block text-muted-foreground text-sm">{row.note}</span>
          ) : null}
        </div>
      ),
    },
    {
      key: "kind",
      header: "Format",
      hideBelow: "2xl",
      render: (row) => <Badge variant="outline">{listKindLabel(row.kind)}</Badge>,
    },
    { key: "enabled", header: "Enabled", render: enabledSwitch },
    {
      key: "rules",
      header: "Rules loaded",
      align: "end",
      // Dimmed while a fetch is in flight: the figure is from the last fetch
      // and is about to change.
      render: (row) => (
        <span className={cn("tabular", isRefreshing(row) && "text-muted-foreground opacity-64")}>
          {formatCount(row.rule_count)}
        </span>
      ),
    },
    {
      key: "updated",
      header: "Last updated",
      align: "end",
      hideBelow: "lg",
      render: (row) => <span className="text-muted-foreground text-xs">{updated(row)}</span>,
    },
    {
      key: "actions",
      header: "Actions",
      hideHeader: true,
      align: "end",
      // Refresh stays a button — it is the verb this row exists for, and it
      // carries the spinner. Delete sits behind "⋯", a deliberate second step.
      render: (row) => (
        <span className="flex items-center justify-end gap-2">
          {/* Not while every list is being refreshed: the server takes one
              refresh at a time and answered the second with a 429. */}
          <IconButton
            disabled={refreshingAll}
            isLoading={busy === `list-refresh-${row.id}`}
            label={`Refresh ${row.name}`}
            onClick={() => void refresh(row)}
          >
            <RotateCwIcon aria-hidden />
          </IconButton>
          <RowMenu
            actions={[{ value: "delete", label: "Delete list…", destructive: true }]}
            label={`Actions for ${row.name}`}
            onSelect={() => ask("delete", row)}
          />
        </span>
      ),
    },
  ];

  // The phone row: the name, its switch and "⋯" on the first line; format,
  // rules and freshness on the second; a failure, when there is one, in words
  // under that. Refresh moves into the menu — at 375px there is room for one
  // icon button beside a switch, and the menu is the one that holds two verbs.
  const narrowRow = (row: ListSource) => (
    <NarrowRow
      actions={
        <>
          {enabledSwitch(row)}
          <RowMenu
            actions={[
              { value: "refresh", label: "Refresh now", disabled: isRefreshing(row) },
              { value: "delete", label: "Delete list…", destructive: true },
            ]}
            label={`Actions for ${row.name}`}
            onSelect={(value) => {
              if (value === "refresh") void refresh(row);
              else ask("delete", row);
            }}
          />
        </>
      }
      detail={
        <>
          <span className="block">
            {listKindLabel(row.kind)} · <span className="tabular">{pluralize(row.rule_count, "rule")}</span> ·{" "}
            {isRefreshing(row) ? "Refreshing…" : row.last_ok_at ? `updated ${formatRelative(row.last_ok_at)}` : "never downloaded"}
          </span>
          {row.last_error ? (
            <span className="mt-1 block">
              <span className="font-medium text-foreground">Download failed.</span>{" "}
              {listErrorSentence(row.last_error)}
            </span>
          ) : row.note ? (
            <span className="mt-1 block">{row.note}</span>
          ) : null}
        </>
      }
      lead={row.last_error ? <Status size="sm" variant="destructive" /> : null}
      title={row.name}
    />
  );

  return (
    <PageShell>
      <PageHeader
        actions={
          <Button
            isLoading={refreshingAll}
            onClick={() => void refresh()}
            title="Re-download every subscribed blocklist now. Takes up to a minute."
            variant="outline"
          >
            <RotateCwIcon aria-hidden />
            Refresh all
          </Button>
        }
        description="What gets blocked for the whole household, and the exceptions on top of it."
        title="Lists"
      />

      <PageSections>
        {/* The page leads with the lists, not with a blank form to add one.
            Subscribing happens once or twice a year; looking at what is
            subscribed happens every time this page is opened. */}
        <SectionCard
          actions={addToggle}
          busy={refreshingAll}
          description={
            refreshingAll ? (
              `Checking ${pluralize(lists.length, "list")}…`
            ) : catalogue === emptyLists ? undefined : (
              // Not before the lists have loaded once: "0 of 0 enabled · 0
              // rules loaded" was a count of nothing, beside an error saying
              // the lists could not be read.
              <ListsSummary lists={lists} />
            )
          }
          title="Subscribed lists"
        >
          <DataTable
            card={narrowRow}
            columns={columns}
            empty={{
              icon: ListIcon,
              title: "No lists yet",
              description: "Nothing is blocked by a list until one is added. Light is the gentlest start.",
              action: adding ? undefined : (
                <Button aria-controls="add-list" aria-expanded={adding} onClick={() => openAdd(true)} variant="outline">
                  <PlusIcon aria-hidden />
                  Add a list
                </Button>
              ),
            }}
            error={error}
            errorTitle="Could not load your lists"
            loading={phase === "loading"}
            onRetry={() => void reload()}
            rowKey={(row) => row.id}
            rows={lists}
            stackBelow="xl"
          />
        </SectionCard>

        {adding ? (
          <AddList lists={lists} onDone={() => openAdd(false)} presets={catalogue.presets} />
        ) : null}

        <RulesCard />

        <CheckDomain />
      </PageSections>

      <ConfirmDialog
        confirmLabel={pending?.copy.confirmLabel ?? ""}
        consequence={pending?.copy.consequence}
        description={pending?.copy.description ?? ""}
        tone={pending?.kind === "delete" ? "bad" : "warn"}
        onConfirm={async () => {
          if (!pending) return;
          if (pending.kind === "delete") {
            if (await remove(pending.list)) deleted.current = true;
          } else await setEnabled(pending.list, false);
        }}
        onOpenChange={setConfirming}
        open={confirming}
        title={pending?.copy.title ?? ""}
      />
    </PageShell>
  );
}

/**
 * The delete and disable confirmations. Both name the list, and both put what
 * the appliance will be doing afterwards in the consequence line — which is
 * where a device that used this list and nothing else is named.
 */
function dialogCopy({ kind, list }: Pending, fallout: string | null): DialogCopy {
  if (kind === "disable") {
    return {
      title: `Disable "${list.name}"?`,
      description: "Its rules stop applying until it is enabled again. Nothing is deleted.",
      consequence: fallout ?? undefined,
      confirmLabel: "Disable list",
    };
  }
  const stops = list.enabled
    ? `Its ${pluralize(list.rule_count, "rule")} stop applying at once.`
    : "It is already disabled, so nothing is filtered differently.";
  return {
    title: `Delete "${list.name}"?`,
    description: list.enabled
      ? "Its downloaded copy is deleted too. To stop using it for now, disable it instead."
      : "Its downloaded copy is deleted too.",
    consequence: fallout ? `${stops} ${fallout}` : stops,
    confirmLabel: "Delete list",
  };
}

/**
 * The card's summary line. Its own component because the rule total comes
 * from the overview, which is polled every five seconds: read here, a poll
 * re-renders one line instead of the page.
 */
function ListsSummary({ lists }: { lists: ListSource[] }) {
  const { lists: totals } = useSnapshot("overview");
  const on = lists.filter((list) => list.enabled).length;
  return (
    <>
      {formatCount(on)} of {formatCount(lists.length)} enabled ·{" "}
      <span className="tabular">{pluralize(totals.rules_loaded, "rule")}</span> loaded.
    </>
  );
}
