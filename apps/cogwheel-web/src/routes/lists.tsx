import React from "react";
import { ListIcon, RotateCwIcon, ScaleIcon, Trash2Icon } from "lucide-react";
import { api, type ListKind, type ListSource, type RuleAction } from "@/lib/api";
import { LIST_KINDS, checkSentence, isRuleDomain, normalizeDomain } from "@/lib/derive";
import { formatCount, formatRelative, truncateMiddle } from "@/lib/format";
import { notify } from "@/lib/toast";
import { PRESETS } from "@/lib/presets";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, type Column } from "@/components/app/data-table";
import { SelectField } from "@/components/app/select-field";
import { TextField } from "@/components/app/text-field";
import { FieldRow } from "@/components/app/form-field";
import { StatusPill } from "@/components/app/status-indicator";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { EmptyState, NoticeBanner } from "@/components/app/states";

export function ListsScreen() {
  const { data, phase, error, busy, mutate, reload } = useCogwheel();
  const [pendingDelete, setPendingDelete] = React.useState<ListSource | null>(null);

  const lists = data.lists.lists;
  // The server returns the same catalogue; the bundled copy only covers the
  // window before the first response lands.
  const presets = data.lists.presets.length > 0 ? data.lists.presets : PRESETS;

  const setEnabled = (list: ListSource, enabled: boolean) =>
    mutate({
      key: `list-toggle-${list.id}`,
      action: () => api.updateList(list.id, { enabled }),
      successTitle: enabled ? "List enabled" : "List disabled",
      successDetail: list.name,
      failureTitle: enabled ? "Could not enable the list" : "Could not disable the list",
      // The switch flips at once and snaps back if the server rejects it.
      optimistic: {
        lists: {
          ...data.lists,
          lists: lists.map((entry) => (entry.id === list.id ? { ...entry, enabled } : entry)),
        },
      },
    });

  const refresh = (list?: ListSource) =>
    mutate({
      key: list ? `list-refresh-${list.id}` : "list-refresh-all",
      action: () => api.refreshLists(list?.id),
      successTitle: "Refreshed",
      successDetail: (results) =>
        results.map((result) => `${result.name}: ${result.outcome}`).join(" · ") || "Nothing to do.",
      failureTitle: "Could not refresh",
    });

  const remove = async (list: ListSource) => {
    await mutate({
      key: `list-delete-${list.id}`,
      action: () => api.deleteList(list.id),
      successTitle: "List deleted",
      successDetail: list.name,
      failureTitle: "Could not delete the list",
    });
  };

  const columns: Column<ListSource>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="min-w-0">
          <span className="block truncate text-foreground">{row.name}</span>
          <span className="block truncate font-mono text-muted-foreground text-xs" title={row.url}>
            {truncateMiddle(row.url, 44)}
          </span>
        </span>
      ),
      sortValue: (row) => row.name,
    },
    {
      key: "kind",
      header: "Format",
      hideBelow: "xl",
      render: (row) => <Badge variant="outline">{row.kind}</Badge>,
      sortValue: (row) => row.kind,
    },
    {
      key: "enabled",
      header: "Enabled",
      render: (row) => (
        <Switch
          aria-label={`Enable ${row.name}`}
          checked={row.enabled}
          disabled={busy === `list-toggle-${row.id}`}
          onCheckedChange={(details) => void setEnabled(row, details.checked)}
        />
      ),
      sortValue: (row) => (row.enabled ? 1 : 0),
    },
    {
      key: "rules",
      header: "Rules loaded",
      align: "end",
      render: (row) => <span className="tabular">{formatCount(row.rule_count)}</span>,
      sortValue: (row) => row.rule_count,
    },
    {
      key: "updated",
      header: "Last updated",
      align: "end",
      hideBelow: "2xl",
      render: (row) => (
        <span className="text-muted-foreground text-xs">{formatRelative(row.last_ok_at)}</span>
      ),
      sortValue: (row) => row.last_ok_at ?? 0,
    },
    {
      key: "status",
      header: "Status",
      render: (row) => {
        if (row.last_error) return <StatusPill label={row.last_error} tone="warn" />;
        if (row.note) return <span className="text-muted-foreground text-xs">{row.note}</span>;
        if (row.due) return <span className="text-muted-foreground text-xs">due</span>;
        return <StatusPill label="OK" tone="good" />;
      },
    },
    {
      key: "actions",
      header: "",
      align: "end",
      hideOnStack: true,
      render: (row) => (
        <span className="flex items-center justify-end gap-1">
          <Button
            aria-label={`Refresh ${row.name}`}
            isLoading={busy === `list-refresh-${row.id}`}
            onClick={() => void refresh(row)}
            size="icon-sm"
            variant="ghost"
          >
            <RotateCwIcon aria-hidden />
          </Button>
          <Button
            aria-label={`Delete ${row.name}`}
            onClick={() => setPendingDelete(row)}
            size="icon-sm"
            variant="ghost"
          >
            <Trash2Icon aria-hidden />
          </Button>
        </span>
      ),
    },
  ];

  return (
    <PageShell>
      <PageHeader
        actions={
          <Button
            isLoading={busy === "list-refresh-all"}
            onClick={() => void refresh()}
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
        <AddList presets={presets} />

        <SectionCard
          description={`${formatCount(lists.filter((list) => list.enabled).length)} of ${formatCount(
            lists.length,
          )} enabled · ${formatCount(data.overview.lists.rules_loaded)} rules loaded.`}
          title="Lists"
        >
          <DataTable
            columns={columns}
            empty={{
              icon: ListIcon,
              title: "No lists yet",
              description: "Pick a preset above — oisd small is a good first subscription.",
            }}
            error={error}
            loading={phase === "loading"}
            onRetry={() => void reload()}
            rowKey={(row) => row.id}
            rows={lists}
            stackBelow="xl"
          />
        </SectionCard>

        <HouseholdRules />

        <CheckDomain />
      </PageSections>

      <ConfirmDialog
        confirmLabel="Delete list"
        consequence="Its cached copy is removed from disk and the filters are rebuilt without it."
        description={`${pendingDelete?.name ?? "This list"} stops being used immediately.`}
        destructive
        onConfirm={async () => {
          if (pendingDelete) await remove(pendingDelete);
        }}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
        open={pendingDelete !== null}
        title="Delete this list?"
      />
    </PageShell>
  );
}

/* -------------------------------------------------------------------------- */

function AddList({ presets }: { presets: { name: string; url: string; kind: ListKind }[] }) {
  const { busy, mutate } = useCogwheel();
  const [preset, setPreset] = React.useState("");
  const [name, setName] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [kind, setKind] = React.useState<ListKind>("adblock");
  const [enabled, setEnabled] = React.useState(true);

  const choosePreset = (value: string) => {
    setPreset(value);
    const match = presets.find((entry) => entry.name === value);
    if (!match) return;
    setName(match.name);
    setUrl(match.url);
    setKind(match.kind);
  };

  const add = async () => {
    if (!name.trim() || !url.trim()) {
      notify.error("Name and URL required", "Pick a preset, or type both fields.");
      return;
    }
    const result = await mutate({
      key: "list-add",
      action: () => api.createList({ name: name.trim(), url: url.trim(), kind, enabled }),
      successTitle: (created) =>
        created.outcome === "updated" ? "List added" : `List added (${created.outcome})`,
      successDetail: (created) => created.note ?? `${formatCount(created.list.rule_count)} rules loaded.`,
      failureTitle: "Could not add the list",
    });
    if (result) {
      setPreset("");
      setName("");
      setUrl("");
    }
  };

  return (
    <SectionCard
      description="Subscribe to a public blocklist. Presets are the ones DNSNet ships with."
      footer={
        <Button isLoading={busy === "list-add"} onClick={() => void add()}>
          Add list
        </Button>
      }
      title="Add a list"
    >
      <div className="space-y-4">
        <SelectField
          hint="Fills the three fields below. Or leave it blank and type your own."
          label="Preset"
          onChange={choosePreset}
          options={presets.map((entry) => ({ value: entry.name, label: entry.name }))}
          placeholder="Choose a preset…"
          value={preset}
        />

        <FieldRow>
          <TextField label="Name" onChange={setName} placeholder="oisd small" value={name} />
          <TextField label="URL" onChange={setUrl} placeholder="https://small.oisd.nl" value={url} />
        </FieldRow>

        <FieldRow>
          <SelectField
            hint="How the file is written. Guessing wrong loads zero rules."
            label="Format"
            onChange={(value) => setKind(value as ListKind)}
            options={LIST_KINDS}
            value={kind}
          />
          <span className="flex items-center gap-3 self-end pb-2 text-sm">
            <Switch
              aria-label="Enabled"
              checked={enabled}
              onCheckedChange={(details) => setEnabled(details.checked)}
            />
            Enabled
          </span>
        </FieldRow>
      </div>
    </SectionCard>
  );
}

function HouseholdRules() {
  const { data, busy, mutate } = useCogwheel();
  const [domain, setDomain] = React.useState("");
  const [action, setAction] = React.useState<RuleAction>("block");

  const rules = data.rules.filter((rule) => rule.device_id === null);

  const add = async () => {
    const normalized = normalizeDomain(domain);
    if (!isRuleDomain(normalized)) {
      notify.error("That is not a domain", "Use something like ads.example.com — no scheme, no path.");
      return;
    }
    const result = await mutate({
      key: "household-rule-add",
      action: () => api.createRule({ domain: normalized, action }),
      successTitle: action === "allow" ? "Allowed for everyone" : "Blocked for everyone",
      successDetail: normalized,
      failureTitle: "Could not save the rule",
    });
    if (result) setDomain("");
  };

  return (
    <SectionCard
      description="Your own decisions. They beat every list, for every device."
      footer={
        <p className="text-muted-foreground text-sm">
          Allow beats block. A domain covers its subdomains.
        </p>
      }
      title="Household rules"
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-end gap-2">
          <TextField
            className="min-w-48 flex-1"
            label="Domain"
            onChange={setDomain}
            placeholder="ads.example.com"
            value={domain}
          />
          <SelectField
            className="w-32"
            label="Action"
            onChange={(value) => setAction(value as RuleAction)}
            options={[
              { value: "block", label: "Block" },
              { value: "allow", label: "Allow" },
            ]}
            value={action}
          />
          <Button
            disabled={!domain.trim()}
            isLoading={busy === "household-rule-add"}
            onClick={() => void add()}
            variant="outline"
          >
            Add
          </Button>
        </div>

        {rules.length === 0 ? (
          <EmptyState
            description="Add one when a list blocks something you need, or when you want a domain gone everywhere."
            icon={ScaleIcon}
            title="No household rules"
          />
        ) : (
          <ul className="divide-y divide-border">
            {rules.map((rule) => (
              <li className="flex items-center gap-3 py-1.5" key={rule.id}>
                <span className="min-w-0 flex-1 truncate font-mono text-xs">{rule.domain}</span>
                <StatusPill
                  label={rule.action === "allow" ? "Allow" : "Block"}
                  tone={rule.action === "allow" ? "good" : "bad"}
                />
                <Button
                  aria-label={`Remove ${rule.domain}`}
                  onClick={() =>
                    void mutate({
                      key: `household-rule-${rule.id}`,
                      action: () => api.deleteRule(rule.id),
                      successTitle: "Rule removed",
                      successDetail: rule.domain,
                      failureTitle: "Could not remove the rule",
                    })
                  }
                  size="icon-sm"
                  variant="ghost"
                >
                  <Trash2Icon aria-hidden />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </SectionCard>
  );
}

function CheckDomain() {
  const { data } = useCogwheel();
  const [domain, setDomain] = React.useState("");
  const [client, setClient] = React.useState("");
  const [answer, setAnswer] = React.useState<string | null>(null);
  const [checking, setChecking] = React.useState(false);

  const run = async () => {
    const normalized = normalizeDomain(domain);
    if (!normalized) return;
    setChecking(true);
    try {
      setAnswer(checkSentence(await api.check(normalized, client || undefined)));
    } catch {
      notify.error("Could not check that domain", "The control plane did not answer.");
    } finally {
      setChecking(false);
    }
  };

  return (
    <SectionCard
      description="Ask what would happen right now, without waiting for the device to try."
      title="Check a domain"
    >
      <div className="space-y-4">
        <div className="flex flex-wrap items-end gap-2">
          <TextField
            className="min-w-48 flex-1"
            label="Domain"
            onChange={setDomain}
            placeholder="ads.example.com"
            value={domain}
          />
          <SelectField
            className="w-56"
            label="As device"
            onChange={setClient}
            options={data.devices.devices.map((device) => ({
              value: device.ip_address,
              label: device.name,
            }))}
            placeholder="The household"
            value={client}
          />
          <Button disabled={!domain.trim()} isLoading={checking} onClick={() => void run()} variant="outline">
            Check
          </Button>
        </div>

        {answer ? <NoticeBanner title={answer} tone="neutral" /> : null}
      </div>
    </SectionCard>
  );
}
