import React from "react";
import { useSearchParams } from "react-router-dom";
import { LaptopIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { api, type Device, type DeviceInput, type RuleAction } from "@/lib/api";
import { isIpAddress, isRuleDomain, normalizeDomain } from "@/lib/derive";
import { formatCount, formatRelative } from "@/lib/format";
import { notify } from "@/lib/toast";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
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
  };

  const editing = devices.find((device) => device.id === draft.id) ?? null;
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
    { key: "name", header: "Name", render: (row) => row.name, sortValue: (row) => row.name },
    {
      key: "ip",
      header: "IP",
      render: (row) => <span className="font-mono text-xs">{row.ip_address}</span>,
      sortValue: (row) => row.ip_address,
    },
    {
      key: "filtering",
      header: "Filtering",
      render: (row) =>
        row.filtering ? <StatusPill label="On" tone="good" /> : <StatusPill label="Off" tone="warn" />,
      sortValue: (row) => (row.filtering ? 1 : 0),
    },
    {
      key: "lists",
      header: "Lists",
      hideBelow: "xl",
      render: (row) =>
        row.all_lists ? "All" : `${formatCount(row.lists.length)} of ${formatCount(enabledLists.length)}`,
    },
    {
      key: "rules",
      header: "Rules",
      align: "end",
      hideBelow: "xl",
      render: (row) => <span className="tabular">{formatCount(row.rules.length)}</span>,
      sortValue: (row) => row.rules.length,
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
      sortValue: (row) => row.queries_24h,
    },
    {
      key: "seen",
      header: "Last seen",
      align: "end",
      hideBelow: "2xl",
      render: (row) => (
        <span className="text-muted-foreground text-xs">{formatRelative(row.last_seen_at)}</span>
      ),
      sortValue: (row) => row.last_seen_at ?? 0,
    },
  ];

  return (
    <PageShell>
      <PageHeader
        actions={
          <Button onClick={() => select(null)} variant="outline">
            <PlusIcon aria-hidden />
            Add device
          </Button>
        }
        description="Give the addresses on your network names, then decide what each one filters."
        title="Devices"
      />

      <PageSections>
        <div className="grid gap-6 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <SectionCard
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
              <TextField
                label="Name"
                onChange={(value) => setDraft((current) => ({ ...current, name: value }))}
                placeholder="Kitchen iPad"
                value={draft.name}
              />
              <TextField
                error={ipError}
                hint="The address this device gets from your router."
                label="IP address"
                onChange={(value) => setDraft((current) => ({ ...current, ip_address: value }))}
                placeholder="192.168.1.42"
                value={draft.ip_address}
              />

              <div className="flex items-start justify-between gap-4">
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

              <div className="space-y-3">
                <p className="font-medium text-foreground text-sm">Rules for this device</p>
                {draft.id ? null : (
                  <p className="text-muted-foreground text-sm">Add the device first, then its rules.</p>
                )}

                <div className="flex flex-wrap items-end gap-2">
                  <TextField
                    className="min-w-48 flex-1"
                    disabled={!draft.id}
                    label="Domain"
                    onChange={setRuleDomain}
                    placeholder="ads.example.com"
                    value={ruleDomain}
                  />
                  <SelectField
                    className="w-32"
                    disabled={!draft.id}
                    label="Action"
                    onChange={(value) => setRuleAction(value as RuleAction)}
                    options={[
                      { value: "block", label: "Block" },
                      { value: "allow", label: "Allow" },
                    ]}
                    value={ruleAction}
                  />
                  <Button
                    disabled={!draft.id || !ruleDomain.trim()}
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
                      <li className="flex items-center gap-3 py-1.5" key={rule.id}>
                        <span className="min-w-0 flex-1 truncate font-mono text-xs">{rule.domain}</span>
                        <StatusPill
                          label={rule.action === "allow" ? "Allow" : "Block"}
                          tone={rule.action === "allow" ? "good" : "bad"}
                        />
                        <Button
                          aria-label={`Remove ${rule.domain}`}
                          onClick={() => void deleteRule(rule.id, rule.domain)}
                          size="icon-sm"
                          variant="ghost"
                        >
                          <Trash2Icon aria-hidden />
                        </Button>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            </div>
          </SectionCard>

          <div className="flex flex-col gap-6">
            <SectionCard title={`Devices (${formatCount(devices.length)})`}>
              <DataTable
                columns={columns}
                empty={{
                  icon: LaptopIcon,
                  title: "No devices named yet",
                  description:
                    "Name the ones the household will recognise first — the TV, the kids' tablets, the work laptop.",
                }}
                error={error}
                loading={phase === "loading"}
                onRetry={() => void reload()}
                onRowClick={(row) => select(row)}
                rowActionLabel={(row) => `Edit ${row.name}`}
                rowKey={(row) => row.id}
                rows={devices}
                stackBelow="xl"
              />
            </SectionCard>

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
          </div>
        </div>
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
