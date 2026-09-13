import React from "react";
import { useSearchParams } from "react-router-dom";
import { LaptopIcon, PlusIcon } from "lucide-react";
import { api, type DeviceRecord } from "@/lib/api";
import { splitDomainList } from "@/lib/derive";
import { formatCount } from "@/lib/format";
import { notify } from "@/lib/toast";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, type Column } from "@/components/app/data-table";
import { SelectField } from "@/components/app/select-field";
import { TextField } from "@/components/app/text-field";
import { FieldRow } from "@/components/app/form-field";
import { StatusPill } from "@/components/app/status-indicator";
import { NoticeBanner } from "@/components/app/states";

type Draft = {
  id?: string;
  name: string;
  ip_address: string;
  policy_mode: DeviceRecord["policy_mode"];
  blocklist_profile_override: string;
  protection_override: DeviceRecord["protection_override"];
  allowed_domains: string;
};

const BLANK: Draft = {
  name: "",
  ip_address: "",
  policy_mode: "global",
  blocklist_profile_override: "",
  protection_override: "inherit",
  allowed_domains: "",
};

function toDraft(device: DeviceRecord): Draft {
  return {
    id: device.id,
    name: device.name,
    ip_address: device.ip_address,
    policy_mode: device.policy_mode,
    blocklist_profile_override: device.blocklist_profile_override ?? "",
    protection_override: device.protection_override,
    allowed_domains: device.allowed_domains.join(", "),
  };
}

export function DevicesScreen() {
  const { data, phase, error, busy, mutate, reload } = useCogwheel();
  const [params, setParams] = useSearchParams();
  const [draft, setDraft] = React.useState<Draft>(BLANK);
  const [search, setSearch] = React.useState("");

  const devices = data.settings.devices;
  const selectedId = params.get("device");

  // The URL owns which device is being edited, so a link can drop someone
  // straight into the right form.
  React.useEffect(() => {
    if (!selectedId) return;
    const match = devices.find((device) => device.id === selectedId);
    if (match) setDraft(toDraft(match));
  }, [devices, selectedId]);

  const select = (device: DeviceRecord | null) => {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (device) next.set("device", device.id);
        else next.delete("device");
        return next;
      },
      { replace: true },
    );
    setDraft(device ? toDraft(device) : BLANK);
  };

  const custom = draft.policy_mode === "custom";

  const filtered = React.useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return devices;
    return devices.filter(
      (device) =>
        device.name.toLowerCase().includes(needle) || device.ip_address.toLowerCase().includes(needle),
    );
  }, [devices, search]);

  const save = async () => {
    if (!draft.name.trim() || !draft.ip_address.trim()) {
      notify.error("Name and address required", "A device needs both a friendly name and an IP address.");
      return;
    }

    // The server forces the per-device fields back to their defaults whenever
    // the mode is not custom; mirror that so the form never disagrees with
    // what was actually stored.
    const payload = {
      ...(draft.id ? { id: draft.id } : {}),
      name: draft.name.trim(),
      ip_address: draft.ip_address.trim(),
      policy_mode: draft.policy_mode,
      blocklist_profile_override: custom ? draft.blocklist_profile_override || null : null,
      protection_override: custom ? draft.protection_override : ("inherit" as const),
      allowed_domains: custom ? splitDomainList(draft.allowed_domains) : [],
    };

    const result = await mutate({
      key: "device-submit",
      action: () => api.upsertDevice(payload),
      successTitle: draft.id ? "Device updated" : "Device added",
      successDetail: (device) => `${device.name} is now tracked in the control plane.`,
      failureTitle: draft.id ? "Could not update device" : "Could not add device",
    });

    if (result) select(null);
  };

  const columns: Column<DeviceRecord>[] = [
    { key: "name", header: "Name", render: (row) => row.name, sortValue: (row) => row.name },
    {
      key: "ip",
      header: "IP address",
      render: (row) => <span className="font-mono text-xs">{row.ip_address}</span>,
      sortValue: (row) => row.ip_address,
    },
    {
      key: "policy",
      header: "Policy",
      hideBelow: "md",
      render: (row) => (
        <Badge variant={row.policy_mode === "custom" ? "default" : "secondary"}>
          {row.policy_mode === "custom" ? "Custom" : "Household default"}
        </Badge>
      ),
      sortValue: (row) => row.policy_mode,
    },
    {
      key: "profile",
      header: "Profile",
      hideOnStack: true,
      hideBelow: "2xl",
      render: (row) => row.blocklist_profile_override ?? "Default",
    },
    {
      key: "protection",
      header: "Protection",
      render: (row) =>
        row.protection_override === "bypass" ? (
          <StatusPill label="Bypassing filters" tone="warn" />
        ) : (
          <StatusPill label="Filtered" tone="good" />
        ),
    },
    {
      key: "allowed",
      header: "Allowed domains",
      align: "end",
      hideOnStack: true,
      hideBelow: "2xl",
      render: (row) => <span className="tabular">{formatCount(row.allowed_domains.length)}</span>,
      sortValue: (row) => row.allowed_domains.length,
    },
  ];

  return (
    <PageShell>
      <PageHeader
        actions={
          <Button onClick={() => select(null)} variant="outline">
            <PlusIcon aria-hidden />
            New device
          </Button>
        }
        description="Name the devices on the network so events, exceptions and per-device policy read in plain language."
        title="Devices"
      />

      <PageSections>
        {devices.some((device) => device.protection_override === "bypass") ? (
          <NoticeBanner
            detail="Those devices resolve unfiltered. Their traffic is still counted, but nothing is blocked for them."
            title="Some devices bypass filtering"
            tone="warn"
          />
        ) : null}

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)]">
          <SectionCard
            description={
              custom
                ? "Custom devices ignore the household default and use exactly what you set here."
                : "This device follows the household default until you switch it to a custom assignment."
            }
            footer={
              <>
                {draft.id ? (
                  <Button onClick={() => select(null)} variant="ghost">
                    Cancel
                  </Button>
                ) : null}
                <Button
                  disabled={!draft.name.trim() || !draft.ip_address.trim()}
                  isLoading={busy === "device-submit"}
                  onClick={() => void save()}
                >
                  {draft.id ? "Save device" : "Add device"}
                </Button>
              </>
            }
            title={draft.id ? `Edit ${draft.name || "device"}` : "Add device"}
          >
            <div className="space-y-4">
              <FieldRow>
                <TextField
                  label="Device name"
                  onChange={(value) => setDraft((current) => ({ ...current, name: value }))}
                  placeholder="Kitchen iPad"
                  value={draft.name}
                />
                <TextField
                  hint="Saved even if unparseable, but only valid addresses affect DNS."
                  label="IP address"
                  onChange={(value) => setDraft((current) => ({ ...current, ip_address: value }))}
                  placeholder="192.168.1.42"
                  value={draft.ip_address}
                />
              </FieldRow>

              <FieldRow>
                <SelectField
                  label="Policy mode"
                  onChange={(value) =>
                    setDraft((current) => ({
                      ...current,
                      policy_mode: value as DeviceRecord["policy_mode"],
                    }))
                  }
                  options={[
                    { value: "global", label: "Household default" },
                    { value: "custom", label: "Custom assignment" },
                  ]}
                  value={draft.policy_mode}
                />
                <SelectField
                  disabled={!custom}
                  hint="Block profiles are stored but not yet consulted by the DNS pipeline."
                  label="Profile override"
                  onChange={(value) =>
                    setDraft((current) => ({ ...current, blocklist_profile_override: value }))
                  }
                  options={data.settings.block_profiles.map((profile) => ({
                    value: profile.name,
                    label: `${profile.emoji || "◌"} ${profile.name}`,
                  }))}
                  placeholder="No override"
                  value={draft.blocklist_profile_override}
                />
              </FieldRow>

              <FieldRow>
                <SelectField
                  disabled={!custom}
                  label="Protection"
                  onChange={(value) =>
                    setDraft((current) => ({
                      ...current,
                      protection_override: value as DeviceRecord["protection_override"],
                    }))
                  }
                  options={[
                    { value: "inherit", label: "Keep blocking on" },
                    { value: "bypass", label: "Bypass blocking" },
                  ]}
                  value={draft.protection_override}
                />
                <TextField
                  disabled={!custom}
                  hint="Comma-separated. Always reachable from this device."
                  label="Allowed domains"
                  onChange={(value) => setDraft((current) => ({ ...current, allowed_domains: value }))}
                  placeholder="school.site, printer.local"
                  value={draft.allowed_domains}
                />
              </FieldRow>
            </div>
          </SectionCard>

          <SectionCard
            description="Named devices tracked by the control plane."
            title={`Devices (${formatCount(devices.length)})`}
          >
            <TextField
              className="mb-4"
              label="Search"
              onChange={setSearch}
              placeholder="Name or address"
              searchTarget
              value={search}
            />
            <DataTable
              columns={columns}
              empty={{
                icon: LaptopIcon,
                title: search ? "No devices match that search" : "No devices named yet",
                description: search
                  ? "Clear the search to see every tracked device."
                  : "Start with the devices the household will recognise fastest — the TV, the kids' tablets, the work laptop.",
              }}
              error={error}
              loading={phase === "loading"}
              onRetry={() => void reload()}
              onRowClick={(row) => select(row)}
              rowActionLabel={(row) => `Edit ${row.name}`}
              rowKey={(row) => row.id}
              rows={filtered}
            />
          </SectionCard>
        </div>
      </PageSections>
    </PageShell>
  );
}
