import React from "react";
import { useSearchParams } from "react-router-dom";
import { LaptopIcon, PlusIcon, Trash2Icon, XIcon } from "lucide-react";
import { api, type Device, type DeviceInput, type RuleAction } from "@/lib/api";
import { isIpAddress, isRuleDomain, normalizeDomain } from "@/lib/derive";
import { formatCount, formatRelative } from "@/lib/format";
import { notify } from "@/lib/toast";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Status } from "@/components/ui/status";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, type Column } from "@/components/app/data-table";
import { SelectField } from "@/components/app/select-field";
import { TextField } from "@/components/app/text-field";
import { StatusPill } from "@/components/app/status-indicator";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { EmptyState } from "@/components/app/states";

type Draft = {
  id: string | null;
  name: string;
  ip_address: string;
  filtering: boolean;
  all_lists: boolean;
  lists: string[];
};

const BLANK: Draft = { id: null, name: "", ip_address: "", filtering: true, all_lists: true, lists: [] };

const toDraft = (device: Device): Draft => ({
  id: device.id,
  name: device.name,
  ip_address: device.ip_address,
  filtering: device.filtering,
  all_lists: device.all_lists,
  lists: device.lists,
});

export function DevicesScreen() {
  const { data, phase, error, busy, mutate, reload } = useCogwheel();
  const [params, setParams] = useSearchParams();
  const [draft, setDraft] = React.useState<Draft>(BLANK);
  // The form is opened on purpose — by "Add device", by clicking a row, or by
  // arriving with ?device= / ?ip= from Activity. It is not what the page opens
  // on: a page called Devices should lead with the devices.
  const [adding, setAdding] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);
  const [ruleDomain, setRuleDomain] = React.useState("");
  const [ruleAction, setRuleAction] = React.useState<RuleAction>("block");

  const devices = data.devices.devices;
  const enabledLists = data.lists.lists.filter((list) => list.enabled);
  const selectedId = params.get("device");
  const prefilledIp = params.get("ip");

  // The URL owns which device is being edited (and which unnamed IP is being
  // named), so a link from Activity can drop someone straight into the form.
  // The prefill is applied once per address: a later refetch must not wipe a
  // half-typed name.
  const prefilled = React.useRef<string | null>(null);
  React.useEffect(() => {
    if (selectedId) {
      const match = devices.find((device) => device.id === selectedId);
      if (match) setDraft(toDraft(match));
      return;
    }
    if (prefilledIp && prefilled.current !== prefilledIp) {
      prefilled.current = prefilledIp;
      setDraft({ ...BLANK, ip_address: prefilledIp });
      setAdding(true);
    }
  }, [devices, prefilledIp, selectedId]);

  const select = (device: Device | null, ip?: string) => {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.delete("device");
        next.delete("ip");
        if (device) next.set("device", device.id);
        else if (ip) next.set("ip", ip);
        return next;
      },
      { replace: true },
    );
    setDraft(device ? toDraft(device) : { ...BLANK, ip_address: ip ?? "" });
    setAdding(Boolean(device) || Boolean(ip));
  };

  const editing = devices.find((device) => device.id === draft.id) ?? null;
  const started = draft.id !== null || draft.name !== "" || draft.ip_address !== "";
  const formOpen = adding || draft.id !== null;

  // Opened from Unnamed clients, which sits below the form, so the form has to
  // come to the reader rather than appear off the top of their screen.
  React.useEffect(() => {
    if (!formOpen) return;
    document.getElementById("device-form")?.scrollIntoView({ block: "nearest" });
  }, [formOpen]);
  const ipError = draft.ip_address && !isIpAddress(draft.ip_address) ? "Not an IP address." : undefined;
  const valid = Boolean(draft.name.trim()) && isIpAddress(draft.ip_address);

  const save = async () => {
    const input: DeviceInput = {
      name: draft.name.trim(),
      ip_address: draft.ip_address.trim(),
      filtering: draft.filtering,
      all_lists: draft.all_lists,
      lists: draft.all_lists ? [] : draft.lists,
    };

    const result = await mutate({
      key: "device-save",
      action: () => (draft.id ? api.updateDevice(draft.id, input) : api.createDevice(input)),
      successTitle: draft.id ? "Device updated" : "Device added",
      successDetail: (device) => `${device.name} at ${device.ip_address}.`,
      failureTitle: draft.id ? "Could not update the device" : "Could not add the device",
    });

    if (result && !draft.id) select(null);
  };

  const remove = async () => {
    const id = draft.id;
    if (!id) return;
    const result = await mutate({
      key: "device-delete",
      action: () => api.deleteDevice(id),
      successTitle: "Device deleted",
      successDetail: "Its rules and list choices went with it.",
      failureTitle: "Could not delete the device",
    });
    if (result) select(null);
  };

  const addRule = async () => {
    const domain = normalizeDomain(ruleDomain);
    if (!isRuleDomain(domain)) {
      notify.error("That is not a domain", "Use something like ads.example.com — no scheme, no path.");
      return;
    }
    const result = await mutate({
      key: "device-rule-add",
      action: () => api.createRule({ domain, action: ruleAction, device_id: draft.id ?? undefined }),
      successTitle: ruleAction === "allow" ? "Allow rule saved" : "Block rule saved",
      successDetail: `${domain} on ${draft.name || "this device"}.`,
      failureTitle: "Could not save the rule",
    });
    if (result) setRuleDomain("");
  };

  const deleteRule = (id: number, domain: string) =>
    mutate({
      key: `device-rule-${id}`,
      action: () => api.deleteRule(id),
      successTitle: "Rule removed",
      successDetail: domain,
      failureTitle: "Could not remove the rule",
    });

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
      // One shape for both states: a dot and a word, which is DESIGN.md's rule
      // and what makes the column scannable. The tone is what differs — the
      // default dot for the state every device is supposed to be in, the
      // warning dot for the one that is bypassing the filter. A pill on one
      // row and bare text on the others put two component types in one column
      // and gave the ordinary state no status affordance at all; a column of
      // green pills would have been the opposite mistake, burying the one row
      // worth finding under five that need nothing.
      render: (row) => (
        <span className="inline-flex items-center gap-2 text-sm">
          <Status size="sm" variant={row.filtering ? "default" : "warning"} />
          <span className={row.filtering ? "text-muted-foreground" : "font-medium text-foreground"}>
            {row.filtering ? "On" : "Off"}
          </span>
        </span>
      ),
    },
    {
      key: "lists",
      header: "Lists",
      hideBelow: "lg",
      render: (row) =>
        row.all_lists ? "All" : `${formatCount(row.lists.length)} of ${formatCount(enabledLists.length)}`,
    },
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
      hideBelow: "lg",
      render: (row) => (
        <span className="text-muted-foreground text-xs">{formatRelative(row.last_seen_at)}</span>
      ),
    },
  ];

  // The same two-line shape Activity uses, for the same reason. The generic
  // stacked card printed seven label/value rows per device at roughly 220px
  // each, inside a bordered card nested in the bordered Devices section card —
  // a border around a border, and six devices to a phone screen and a half.
  // Name and address identify the row; the state and the counts are what you
  // came to read. The divider between rows is the only rule needed.
  const narrowRow = (row: Device) => (
    <button
      className="flex w-full items-start gap-3 py-3 text-left"
      onClick={() => select(row)}
      type="button"
    >
      <span className="min-w-0 flex-1">
        <span className="flex items-baseline gap-2">
          <span className="min-w-0 flex-1 truncate font-medium text-foreground text-sm">{row.name}</span>
          <span className="shrink-0 font-mono text-muted-foreground text-xs">{row.ip_address}</span>
        </span>
        <span className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-muted-foreground text-xs">
          <span className="inline-flex items-center gap-1.5">
            <Status size="sm" variant={row.filtering ? "default" : "warning"} />
            <span className={row.filtering ? undefined : "font-medium text-foreground"}>
              {row.filtering ? "Filtering on" : "Filtering off"}
            </span>
          </span>
          <span aria-hidden>·</span>
          <span>
            {row.all_lists ? "All lists" : `${formatCount(row.lists.length)} of ${formatCount(enabledLists.length)} lists`}
          </span>
          <span aria-hidden>·</span>
          <span className="tabular">
            {formatCount(row.queries_24h)} queries, {formatCount(row.blocked_24h)} blocked
          </span>
        </span>
      </span>
    </button>
  );

  return (
    <PageShell>
      <PageHeader
        actions={
          // All this button can do is empty the form, so it is only drawn when
          // there is something in it, and says which of the two emptyings it is.
          // Adding a device is the form's own footer button, a few pixels below.
          started ? (
            <Button onClick={() => select(null)} variant="outline">
              <XIcon aria-hidden />
              {draft.id ? "Cancel edit" : "Clear form"}
            </Button>
          ) : null
        }
        description="Give the addresses on your network names, then decide what each one filters."
        title="Devices"
      />

      <PageSections>
        <SectionCard
          actions={
            formOpen ? null : (
              <Button onClick={() => setAdding(true)} variant="outline">
                <PlusIcon aria-hidden />
                Add device
              </Button>
            )
          }
          title={`Devices (${formatCount(devices.length)})`}
        >
          {/* Full width, so the table gets the page's own column rather than the
              544px half of a two-column grid it used to sit in. Measured
              minimum content widths: 406px for the four columns below @lg,
              541px for the six at @lg, 589px for all seven at @xl — so a
              desktop draws every column and a phone's container falls
              through to cards. */}
          <DataTable
            columns={columns}
            empty={{
              icon: LaptopIcon,
              title: "No devices named yet",
              description:
                "Name the ones the household will recognise first — the TV, the kids' tablets, the work laptop.",
              action: (
                <Button onClick={() => setAdding(true)} variant="outline">
                  <PlusIcon aria-hidden />
                  Add device
                </Button>
              ),
            }}
            error={error}
            loading={phase === "loading"}
            onRetry={() => void reload()}
            onRowClick={(row) => select(row)}
            card={narrowRow}
            rowActionLabel={(row) => `Edit ${row.name}`}
            rowKey={(row) => row.id}
            rows={devices}
            stackBelow="md"
          />
        </SectionCard>

        {formOpen ? (
          <SectionCard
            id="device-form"
            footer={
              <div className="flex flex-wrap items-center gap-2">
                <Button disabled={!valid} isLoading={busy === "device-save"} onClick={() => void save()}>
                  {draft.id ? "Save" : "Add device"}
                </Button>
                {draft.id ? (
                  <>
                    <Button onClick={() => select(null)} variant="ghost">
                      Cancel
                    </Button>
                    <Button className="ms-auto" onClick={() => setDeleting(true)} variant="destructive">
                      <Trash2Icon aria-hidden />
                      Delete device
                    </Button>
                  </>
                ) : null}
              </div>
            }
            title={draft.id ? `Edit ${editing?.name ?? draft.name}` : "Add device"}
          >
            <div className="space-y-5">
              {/* Capped by what they hold. A device name is a few words and an
                  IP is fifteen characters; neither is 1,000px wide, and a field
                  stretched to the card's full width reads as though it wants a
                  paragraph. */}
              <TextField
                className="max-w-md"
                label="Name"
                onChange={(value) => setDraft((current) => ({ ...current, name: value }))}
                placeholder="Kitchen iPad"
                value={draft.name}
              />
              <TextField
                className="max-w-xs"
                error={ipError}
                hint="The address this device gets from your router."
                label="IP address"
                onChange={(value) => setDraft((current) => ({ ...current, ip_address: value }))}
                placeholder="192.168.1.42"
                value={draft.ip_address}
              />

              <div className="flex max-w-md items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="font-medium text-foreground text-sm">Filtering</p>
                  <p className="text-muted-foreground text-sm">
                    Off: this device resolves everything and is still logged.
                  </p>
                </div>
                <Switch
                  aria-label="Filtering"
                  checked={draft.filtering}
                  onCheckedChange={(details) =>
                    setDraft((current) => ({ ...current, filtering: details.checked }))
                  }
                />
              </div>

              <fieldset className="space-y-2">
                <legend className="font-medium text-foreground text-sm">Lists</legend>
                <Radio
                  checked={draft.all_lists}
                  label="Use all household lists"
                  name="device-lists"
                  onSelect={() => setDraft((current) => ({ ...current, all_lists: true }))}
                />
                <Radio
                  checked={!draft.all_lists}
                  label="Choose lists"
                  name="device-lists"
                  onSelect={() => setDraft((current) => ({ ...current, all_lists: false }))}
                />

                {draft.all_lists ? null : (
                  <div className="space-y-2 ps-6">
                    {enabledLists.length === 0 ? (
                      <p className="text-muted-foreground text-sm">No lists are enabled yet.</p>
                    ) : (
                      enabledLists.map((list) => (
                        <label className="flex items-center gap-2 text-sm" key={list.id}>
                          <input
                            checked={draft.lists.includes(list.id)}
                            className="size-4 accent-foreground"
                            onChange={(event) =>
                              setDraft((current) => ({
                                ...current,
                                lists: event.target.checked
                                  ? [...current.lists, list.id]
                                  : current.lists.filter((id) => id !== list.id),
                              }))
                            }
                            type="checkbox"
                          />
                          {list.name}
                        </label>
                      ))
                    )}
                    <p className="text-muted-foreground text-sm">
                      With nothing ticked this device uses no lists at all. Household and device rules
                      still apply.
                    </p>
                  </div>
                )}
              </fieldset>

              {/* Only once the device exists. A rule needs a device id, so in Add mode this
                  was a live-looking form that could not be used, explained by a line of
                  text underneath it; not drawing it says the same thing and cannot be
                  typed into. */}
              {editing === null ? null : (
                <div className="space-y-3">
                  <p className="font-medium text-foreground text-sm">Rules for this device</p>
                  <div className="flex flex-wrap items-end gap-3">
                    <TextField
                      className="max-w-md flex-1 basis-64"
                      label="Domain"
                      onChange={setRuleDomain}
                      placeholder="ads.example.com"
                      value={ruleDomain}
                    />
                    <SelectField
                      className="w-32"
                      label="Action"
                      onChange={(value) => setRuleAction(value as RuleAction)}
                      options={[
                        { value: "block", label: "Block" },
                        { value: "allow", label: "Allow" },
                      ]}
                      value={ruleAction}
                    />
                    <Button
                      disabled={!ruleDomain.trim()}
                      isLoading={busy === "device-rule-add"}
                      onClick={() => void addRule()}
                      variant="outline"
                    >
                      Add
                    </Button>
                  </div>

                  {editing && editing.rules.length > 0 ? (
                    <ul className="divide-y divide-border">
                      {editing.rules.map((rule) => (
                        <li className="flex items-center gap-3 py-2" key={rule.id}>
                          <span className="min-w-0 flex-1 truncate font-mono text-sm">{rule.domain}</span>
                          <StatusPill
                            label={rule.action === "allow" ? "Allow" : "Block"}
                            tone={rule.action === "allow" ? "good" : "bad"}
                          />
                          <Button
                            aria-label={`Remove ${rule.domain}`}
                            onClick={() => void deleteRule(rule.id, rule.domain)}
                            size="icon-md"
                            variant="ghost"
                          >
                            <Trash2Icon aria-hidden />
                          </Button>
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              )}
            </div>
          </SectionCard>
        ) : null}

        <SectionCard
          description="Addresses that have resolved through Cogwheel but have no name yet."
          title="Unnamed clients"
        >
          {data.devices.unnamed_clients.length === 0 ? (
            <EmptyState
              description="Every address seen in the last 24 hours already has a name."
              icon={LaptopIcon}
              title="Nothing unnamed"
            />
          ) : (
            <ul className="divide-y divide-border">
              {data.devices.unnamed_clients.map((client) => (
                <li className="flex flex-wrap items-center gap-3 py-2" key={client.ip}>
                  <span className="min-w-0 flex-1 font-mono text-sm">{client.ip}</span>
                  <span className="tabular text-muted-foreground text-xs">
                    {formatCount(client.queries_24h)} / {formatCount(client.blocked_24h)} ·{" "}
                    {formatRelative(client.last_seen_at)}
                  </span>
                  <Button onClick={() => select(null, client.ip)} size="sm" variant="outline">
                    Name this device
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>
      </PageSections>

      <ConfirmDialog
        confirmLabel="Delete device"
        consequence="Its rules and list choices are deleted too. Traffic from that address falls back to the household policy."
        description={`${editing?.name ?? "This device"} will no longer be named or filtered separately.`}
        destructive
        onConfirm={remove}
        onOpenChange={setDeleting}
        open={deleting}
        title="Delete this device?"
      />
    </PageShell>
  );
}

/** Native radio: the app has no radio primitive, and this is two options. */
function Radio({
  checked,
  label,
  name,
  onSelect,
}: {
  checked: boolean;
  label: string;
  name: string;
  onSelect: () => void;
}) {
  return (
    <label className="flex items-center gap-2 text-sm">
      <input
        checked={checked}
        className="size-4 accent-foreground"
        name={name}
        onChange={onSelect}
        type="radio"
      />
      {label}
    </label>
  );
}
