import React from "react";
import { useSearchParams } from "react-router-dom";
import { LaptopIcon, PlusIcon } from "lucide-react";
import type { Device, DeviceList } from "@/lib/api";
import { chosenEnabledLists, usesNoLists } from "@/lib/derive";
import { formatCount, formatRelative, pluralize } from "@/lib/format";
import { useCogwheelActions, useCogwheelStatus, useSnapshot } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, NarrowRow, type Column } from "@/components/app/data-table";
import { DeviceEditor } from "./devices/editor";

type UnnamedClient = DeviceList["unnamed_clients"][number];

/**
 * How a device is filtering, in one word and in a phrase. Two of the three
 * states are warnings: filtering switched off, and filtering on with no list
 * behind it — "Choose lists" with nothing ticked, or with only lists that have
 * since been switched off or deleted. The second used to read "● On · 0 of 2"
 * with the same neutral dot as a fully filtered device.
 */
function filteringState(device: Device, enabled: ReadonlySet<string>) {
  if (!device.filtering) return { warn: true, word: "Off", phrase: "Filtering off" };
  if (usesNoLists(device, enabled)) return { warn: true, word: "No lists", phrase: "No lists" };
  return { warn: false, word: "On", phrase: "Filtering on" };
}

function listsSummary(device: Device, enabled: ReadonlySet<string>): string {
  if (device.all_lists) return "All";
  const chosen = chosenEnabledLists(device, enabled).length;
  return chosen === 0 ? "None" : `${formatCount(chosen)} of ${formatCount(enabled.size)}`;
}

/** Finds a button by its accessible name, for handing focus back to a row. */
function focusButtonNamed(name: string): boolean {
  const match = [...document.querySelectorAll<HTMLButtonElement>("button[aria-label]")].find(
    (button) => button.getAttribute("aria-label") === name,
  );
  match?.focus();
  return Boolean(match);
}

export function DevicesScreen() {
  const { devices, unnamed_clients: unnamed } = useSnapshot("devices");
  const catalogue = useSnapshot("lists");
  const { phase, error } = useCogwheelStatus();
  const { reload } = useCogwheelActions();
  const [params, setParams] = useSearchParams();
  // A plain "Add device" has no URL of its own; an edit (?device=) and naming
  // an address from Activity or Unnamed devices (?ip=) do, so a link can drop
  // someone straight into the form.
  const [adding, setAdding] = React.useState(false);
  const addButton = React.useRef<HTMLButtonElement>(null);

  const enabled = React.useMemo(
    () => new Set(catalogue.lists.filter((list) => list.enabled).map((list) => list.id)),
    [catalogue.lists],
  );

  const selectedId = params.get("device");
  const prefilledIp = params.get("ip");
  const editing = selectedId ? (devices.find((device) => device.id === selectedId) ?? null) : null;
  const addingIp = selectedId ? null : (prefilledIp ?? (adding ? "" : null));
  const formOpen = editing !== null || addingIp !== null;

  const open = (target: { device?: Device; ip?: string } | null) => {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.delete("device");
        next.delete("ip");
        if (target?.device) next.set("device", target.device.id);
        else if (target?.ip) next.set("ip", target.ip);
        return next;
      },
      { replace: true },
    );
    setAdding(target !== null && !target.device && !target.ip);
  };

  /** Closes the form and puts focus back where the person came from. */
  const close = (returnTo?: string) => {
    open(null);
    requestAnimationFrame(() => {
      if (returnTo && focusButtonNamed(returnTo)) return;
      addButton.current?.focus();
    });
  };

  const columns: Column<Device>[] = [
    { key: "name", header: "Name", render: (row) => row.name },
    {
      key: "ip",
      header: "IP",
      render: (row) => <span className="font-mono text-sm">{row.ip_address}</span>,
    },
    {
      key: "filtering",
      header: "Filtering",
      // A dot and a word in every row, the default dot for the state every
      // device is meant to be in and the warning dot for the two that are not.
      render: (row) => {
        const state = filteringState(row, enabled);
        return (
          <span className="inline-flex items-center gap-2 text-sm">
            <Status size="sm" variant={state.warn ? "warning" : "default"} />
            <span className={state.warn ? "font-medium text-foreground" : "text-muted-foreground"}>
              {state.word}
            </span>
          </span>
        );
      },
    },
    { key: "lists", header: "Lists", hideBelow: "lg", render: (row) => listsSummary(row, enabled) },
    {
      key: "rules",
      header: "Rules",
      align: "end",
      hideBelow: "xl",
      render: (row) => <span className="tabular">{formatCount(row.rules.length)}</span>,
    },
    {
      key: "traffic",
      header: "Queries / Blocked",
      align: "end",
      render: (row) => (
        <span className="tabular">
          {formatCount(row.queries_24h)} / {formatCount(row.blocked_24h)}
        </span>
      ),
    },
    {
      key: "seen",
      header: "Last seen",
      align: "end",
      // Measured with the name at its 8rem floor: the fixed columns and Lists
      // need 478px, Rules brings that to 526 and this column to 626. At "lg"
      // it arrived before there was room and scrolled the card sideways.
      hideBelow: "2xl",
      render: (row) => <span className="text-muted-foreground text-xs">{formatRelative(row.last_seen_at)}</span>,
    },
  ];

  // Name and address identify the row; the state, lists, rules and counts are
  // what you came to read. The title is the row's one button.
  const narrowRow = (row: Device) => {
    const state = filteringState(row, enabled);
    return (
      <NarrowRow
        // Two lines, each whole: how it filters, then what it did. As one
        // wrapping run the break fell wherever it fell, and a line ended on a
        // separator — "Filtering on · All lists · 1 rule ·".
        detail={
          <>
            <span className="flex flex-wrap items-center gap-x-2">
              <span className="inline-flex items-center gap-1.5">
                <Status size="sm" variant={state.warn ? "warning" : "default"} />
                <span className={state.warn ? "font-medium text-foreground" : undefined}>{state.phrase}</span>
              </span>
              {state.warn ? null : (
                <>
                  <span aria-hidden>·</span>
                  <span>{row.all_lists ? "All lists" : `${listsSummary(row, enabled)} lists`}</span>
                </>
              )}
              {row.rules.length > 0 ? (
                <>
                  <span aria-hidden>·</span>
                  <span>{pluralize(row.rules.length, "rule")}</span>
                </>
              ) : null}
            </span>
            <span className="tabular block">
              {formatCount(row.queries_24h)} queries, {formatCount(row.blocked_24h)} blocked
            </span>
          </>
        }
        meta={row.ip_address}
        metaClassName="font-mono"
        onOpen={() => open({ device: row })}
        openLabel={`Edit ${row.name}`}
        title={row.name}
      />
    );
  };

  const unnamedColumns: Column<UnnamedClient>[] = [
    {
      key: "ip",
      header: "Address",
      render: (row) => <span className="font-mono text-sm">{row.ip}</span>,
    },
    {
      key: "traffic",
      header: "Queries / Blocked",
      align: "end",
      render: (row) => (
        <span className="tabular">
          {formatCount(row.queries_24h)} / {formatCount(row.blocked_24h)}
        </span>
      ),
    },
    {
      key: "seen",
      header: "Last seen",
      align: "end",
      hideBelow: "lg",
      render: (row) => <span className="text-muted-foreground text-xs">{formatRelative(row.last_seen_at)}</span>,
    },
    {
      key: "actions",
      header: "Actions",
      hideHeader: true,
      align: "end",
      stackHeader: true,
      render: (row) => <NameButton ip={row.ip} onName={() => open({ ip: row.ip })} />,
    },
  ];

  return (
    <PageShell>
      <PageHeader
        description="Give the addresses on your network names, then decide what each one filters."
        title="Devices"
      />

      <PageSections>
        <SectionCard
          actions={
            <Button
              aria-controls="device-form"
              aria-expanded={addingIp !== null}
              onClick={() => (addingIp !== null ? close() : open({}))}
              ref={addButton}
              variant="outline"
            >
              <PlusIcon aria-hidden />
              Add device
            </Button>
          }
          title="Named devices"
        >
          {/* Full width, so the table gets the page's own column. Measured
              minimum content widths: 406px for the four columns below @lg,
              541px for the six at @lg, 589px for all seven at @xl — so a
              desktop draws every column and a phone's container falls
              through to the two-line row. */}
          <DataTable
            card={narrowRow}
            columns={columns}
            empty={{
              icon: LaptopIcon,
              title: "No devices named yet",
              description:
                "Name the ones the household will recognise first — the TV, the kids' tablets, the work laptop.",
              action: (
                <Button aria-controls="device-form" aria-expanded={addingIp !== null} onClick={() => open({})} variant="outline">
                  <PlusIcon aria-hidden />
                  Add device
                </Button>
              ),
            }}
            error={error}
            errorTitle="Could not load your devices"
            loading={phase === "loading"}
            onRetry={() => void reload()}
            onRowClick={(row) => open({ device: row })}
            rowActionLabel={(row) => `Edit ${row.name}`}
            rowKey={(row) => row.id}
            rows={devices}
            stackBelow="md"
          />
        </SectionCard>

        {formOpen ? (
          <DeviceEditor
            // Keyed by target: opening another device, or another address to
            // name, starts from that device's saved state rather than carrying
            // half-made changes across.
            device={editing}
            devices={devices}
            enabled={enabled}
            ip={addingIp ?? ""}
            key={editing ? `edit-${editing.id}` : `add-${addingIp}`}
            lists={catalogue.lists}
            onClose={close}
            onCreated={(id) =>
              setParams(
                (current) => {
                  const next = new URLSearchParams(current);
                  next.delete("ip");
                  next.set("device", id);
                  return next;
                },
                { replace: true },
              )
            }
          />
        ) : null}

        <SectionCard
          description="Addresses seen in the last 24 hours that have no name yet."
          title="Unnamed devices"
        >
          <DataTable
            card={(row) => (
              // The button rides on the first line, beside the address, so the
              // counts get the row's full width instead of a 130px column
              // that broke them over three lines.
              <NarrowRow
                detail={
                  <span className="tabular">
                    {formatCount(row.queries_24h)} queries, {formatCount(row.blocked_24h)} blocked ·{" "}
                    {formatRelative(row.last_seen_at)}
                  </span>
                }
                meta={<NameButton ip={row.ip} onName={() => open({ ip: row.ip })} />}
                title={row.ip}
                titleClassName="font-mono"
              />
            )}
            columns={unnamedColumns}
            empty={{
              icon: LaptopIcon,
              title: "Nothing unnamed",
              description: "Every address seen in the last 24 hours already has a name.",
            }}
            error={error}
            errorTitle="Could not load the addresses seen"
            loading={phase === "loading"}
            onRetry={() => void reload()}
            rowKey={(row) => row.ip}
            rows={unnamed}
            stackBelow="md"
          />
        </SectionCard>
      </PageSections>
    </PageShell>
  );
}

function NameButton({ ip, onName }: { ip: string; onName: () => void }) {
  return (
    <Button aria-label={`Name this device, ${ip}`} onClick={onName} size="sm" variant="outline">
      Name this device
    </Button>
  );
}
