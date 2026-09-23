import React from "react";
import { ListIcon, PlusIcon, RotateCwIcon, ScaleIcon, Trash2Icon, XIcon } from "lucide-react";
import { api, type ListKind, type ListSource, type RuleAction } from "@/lib/api";
import {
  LIST_KINDS,
  LIST_KIND_HINT,
  checkSentence,
  isRuleDomain,
  listErrorSentence,
  listKindLabel,
  normalizeDomain,
} from "@/lib/derive";
import { formatCount, formatRelative, pluralize, truncateUrl } from "@/lib/format";
import { notify } from "@/lib/toast";
import { cn } from "@/lib/utils";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Status } from "@/components/ui/status";
import { Switch } from "@/components/ui/switch";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, type Column } from "@/components/app/data-table";
import { SelectField } from "@/components/app/select-field";
import { TextField } from "@/components/app/text-field";
import { FieldRow } from "@/components/app/form-field";
import { RowMenu } from "@/components/app/row-menu";
import { StatusPill } from "@/components/app/status-indicator";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { EmptyState, NoticeBanner } from "@/components/app/states";

export function ListsScreen() {
  const { data, phase, error, busy, mutate, reload } = useCogwheel();
  const [pendingDelete, setPendingDelete] = React.useState<ListSource | null>(null);

  const [adding, setAdding] = React.useState(false);

  // Ordered by name, case-insensitively, with anything broken first. The
  // server returns them in `sources.id` order, which is a UUID: arbitrary, and
  // it reshuffles every time a list is added, so nobody can learn where a list
  // lives. A list that failed to download is the one row on this page that
  // wants acting on, so it sorts to the top whatever it is called.
  const lists = React.useMemo(
    () =>
      [...data.lists.lists].sort((left, right) => {
        const broken = Number(Boolean(right.last_error)) - Number(Boolean(left.last_error));
        if (broken !== 0) return broken;
        return left.name.localeCompare(right.name, undefined, { sensitivity: "base" });
      }),
    [data.lists.lists],
  );
  // The catalogue comes from `GET /api/v1/lists` and nowhere else. A second copy
  // in the bundle would be the same eleven entries maintained twice, and the
  // provider's cached snapshot already covers the window before the first
  // response lands on every load but the very first.
  const presets = data.lists.presets;

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

  const refreshingAll = busy === "list-refresh-all";
  const isRefreshing = (row: ListSource) => refreshingAll || busy === `list-refresh-${row.id}`;

  const columns: Column<ListSource>[] = [
    {
      key: "name",
      header: "Name",
      wrap: true,
      // Name, address, and — only when there is one — what went wrong, as two
      // plain lines under the address. A pill is for a word or two; a sentence
      // inside a 24px rounded-full box overflowed it and printed across the row
      // above at 375px, because the stacked card forces `overflow: visible`.
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
              <span className="block text-muted-foreground text-sm">
                {listErrorSentence(row.last_error)}
              </span>
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
    },
    {
      key: "rules",
      header: "Rules loaded",
      align: "end",
      // Dimmed while a fetch is in flight, because the figure beside it is the
      // count from the *last* fetch and is about to change.
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
      // When a list was last refreshed is the second most useful fact in this
      // table; it should not be the first column the layout sheds.
      hideBelow: "lg",
      render: (row) => (
        <span className="text-muted-foreground text-xs">
          {isRefreshing(row) ? "Refreshing…" : formatRelative(row.last_ok_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      align: "end",
      stackHeader: true,
      // Refresh stays a button — it is the verb this row exists for, and it
      // carries the spinner. Delete moves behind the same "⋯" menu Activity and
      // Overview use, so the irreversible action takes a deliberate second step
      // instead of sitting 4px from the one people press every week.
      render: (row) => (
        <span className="flex items-center justify-end gap-2">
          <Button
            aria-label={`Refresh ${row.name}`}
            isLoading={busy === `list-refresh-${row.id}`}
            onClick={() => void refresh(row)}
            size="icon-md"
            variant="ghost"
          >
            <RotateCwIcon aria-hidden />
          </Button>
          <RowMenu
            actions={[{ value: "delete", label: "Delete list…", destructive: true }]}
            label={`Actions for ${row.name}`}
            onSelect={() => setPendingDelete(row)}
          />
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
          actions={
            <Button onClick={() => setAdding((current) => !current)} variant="outline">
              {adding ? <XIcon aria-hidden /> : <PlusIcon aria-hidden />}
              {adding ? "Cancel" : "Add a list"}
            </Button>
          }
          busy={refreshingAll}
          description={
            refreshingAll
              ? `Checking ${pluralize(lists.length, "list")}…`
              : `${formatCount(lists.filter((list) => list.enabled).length)} of ${formatCount(
                  lists.length,
                )} enabled · ${pluralize(data.overview.lists.rules_loaded, "rule")} loaded.`
          }
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

        {adding ? <AddList onDone={() => setAdding(false)} presets={presets} /> : null}

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

function AddList({
  presets,
  onDone,
}: {
  presets: { name: string; url: string; kind: ListKind }[];
  onDone: () => void;
}) {
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
      successDetail: (created) => created.note ?? `${pluralize(created.list.rule_count, "rule")} loaded.`,
      failureTitle: "Could not add the list",
    });
    if (result) {
      setPreset("");
      setName("");
      setUrl("");
      onDone();
    }
  };

  return (
    <SectionCard
      description="Subscribe to a public blocklist. Presets are the lists Cogwheel ships with."
      footer={
        <div className="flex flex-wrap items-center gap-2">
          <Button isLoading={busy === "list-add"} onClick={() => void add()}>
            Add list
          </Button>
          <Button onClick={onDone} variant="ghost">
            Cancel
          </Button>
        </div>
      }
      title="Add a list"
    >
      <div className="space-y-4">
        <SelectField
          hint="Fills the three fields below. Or leave it blank and type your own."
          label="Preset"
          onChange={choosePreset}
          options={presets.map((entry) => ({ value: entry.name, label: entry.name }))}
          placeholder={presets.length > 0 ? "Choose a preset…" : "Loading presets…"}
          value={preset}
        />

        <FieldRow>
          <TextField label="Name" onChange={setName} placeholder="oisd small" value={name} />
          <TextField label="URL" onChange={setUrl} placeholder="https://small.oisd.nl" value={url} />
        </FieldRow>

        <FieldRow>
          <SelectField
            hint={`How the file is written — guessing wrong loads zero rules. ${LIST_KIND_HINT}`}
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
        <div className="flex flex-wrap items-end gap-3">
          <TextField
            className="max-w-md flex-1 basis-64"
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
              <li className="flex items-center gap-3 py-2" key={rule.id}>
                <span className="min-w-0 flex-1 truncate font-mono text-sm">{rule.domain}</span>
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
                  size="icon-md"
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

  const normalized = normalizeDomain(domain);
  // The same shape `POST /rules` enforces, and the same shape the server now
  // applies to `GET /check`. Checking the button here keeps the refusal next to
  // the field being typed in rather than in a banner under it.
  const checkable = isRuleDomain(normalized);

  const run = async () => {
    if (!checkable) return;
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
        <div className="flex flex-wrap items-end gap-3">
          <TextField
            className="max-w-md flex-1 basis-64"
            hint={domain.trim() && !checkable ? "That is not a domain name." : undefined}
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
          <Button disabled={!checkable} isLoading={checking} onClick={() => void run()} variant="outline">
            Check
          </Button>
        </div>

        {answer ? <NoticeBanner title={answer} tone="neutral" /> : null}
      </div>
    </SectionCard>
  );
}
