import React from "react";
import { useSearchParams } from "react-router-dom";
import { HardDriveIcon, PlusIcon, RotateCwIcon, ShieldIcon, Trash2Icon, XIcon } from "lucide-react";
import { api, type BlockProfileListRecord, type BlockProfileRecord, type SourceRecord } from "@/lib/api";
import { MUTUALLY_EXCLUSIVE_PRESETS, emptyBlockProfileDraft, oisdProfileOptions } from "@/lib/constants";
import { slugify, splitDomainList } from "@/lib/derive";
import { formatCount, formatRelative, truncateMiddle } from "@/lib/format";
import { notify } from "@/lib/toast";
import { cn } from "@/lib/utils";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { DataTable, type Column } from "@/components/app/data-table";
import { SelectField } from "@/components/app/select-field";
import { TextField } from "@/components/app/text-field";
import { FieldRow } from "@/components/app/form-field";
import { StatusPill } from "@/components/app/status-indicator";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { AsyncRegion, EmptyState } from "@/components/app/states";

const TABS = ["blocklists", "profiles"] as const;
type TabId = (typeof TABS)[number];

export function ProtectionScreen() {
  const { busy, mutate } = useCogwheel();
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") ?? "blocklists") as TabId;

  return (
    <PageShell>
      <PageHeader
        actions={
          <Button
            isLoading={busy === "refresh-sources"}
            onClick={() =>
              void mutate({
                key: "refresh-sources",
                action: () => api.refreshSources(),
                successTitle: "Sources refreshed",
                successDetail: (result) => result.notes[0] ?? `Outcome: ${result.outcome}.`,
                failureTitle: "Could not refresh sources",
              })
            }
            variant="outline"
          >
            <RotateCwIcon aria-hidden />
            Refresh sources
          </Button>
        }
        description="What gets blocked, and from which lists."
        title="Protection"
      />

      <Tabs
        onValueChange={(details) =>
          setParams(
            (current) => {
              const next = new URLSearchParams(current);
              next.set("tab", details.value);
              return next;
            },
            { replace: true },
          )
        }
        value={TABS.includes(tab) ? tab : "blocklists"}
      >
        <TabsList className="mb-6">
          <TabsTrigger value="blocklists">Blocklists</TabsTrigger>
          <TabsTrigger value="profiles">Block profiles</TabsTrigger>
        </TabsList>

        <TabsContent value="blocklists">
          <BlocklistsPane />
        </TabsContent>
        <TabsContent value="profiles">
          <ProfilesPane />
        </TabsContent>
      </Tabs>
    </PageShell>
  );
}

/* -------------------------------------------------------------------------- */

function BlocklistsPane() {
  const { data, phase, error, busy, mutate, reload } = useCogwheel();
  const [name, setName] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [profile, setProfile] = React.useState("custom");
  const [strictness, setStrictness] = React.useState("balanced");
  const [interval, setInterval] = React.useState("60");
  const [search, setSearch] = React.useState("");
  const [pendingDelete, setPendingDelete] = React.useState<SourceRecord | null>(null);

  const statusById = React.useMemo(
    () => new Map(data.settings.blocklist_statuses.map((status) => [status.id, status])),
    [data.settings.blocklist_statuses],
  );

  const filtered = React.useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return data.settings.blocklists;
    return data.settings.blocklists.filter(
      (source) =>
        source.name.toLowerCase().includes(needle) || source.url.toLowerCase().includes(needle),
    );
  }, [data.settings.blocklists, search]);

  const add = () => {
    if (!name.trim() || !url.trim()) {
      notify.error("Name and URL required", "A blocklist needs both a label and a source URL.");
      return;
    }
    void mutate({
      key: "create-blocklist",
      action: () =>
        api.upsertBlocklist({
          name: name.trim(),
          url: url.trim(),
          kind: "domains",
          enabled: true,
          refresh_interval_minutes: Number.parseInt(interval, 10) || 60,
          profile,
          verification_strictness: strictness,
        }),
      successTitle: "Blocklist added",
      successDetail: (result) => result.notes[0] ?? "The source was saved and the ruleset rebuilt.",
      failureTitle: "Could not add blocklist",
    }).then((result) => {
      if (result) {
        setName("");
        setUrl("");
      }
    });
  };

  const toggle = (source: SourceRecord, enabled: boolean) =>
    mutate({
      key: `blocklist-toggle-${source.id}`,
      action: () => api.setBlocklistEnabled(source.id, enabled),
      successTitle: enabled ? "Blocklist enabled" : "Blocklist disabled",
      successDetail: `${source.name} — ruleset refresh requested.`,
      failureTitle: enabled ? "Could not enable blocklist" : "Could not disable blocklist",
      // The switch flips immediately and snaps back if the server rejects it.
      optimistic: {
        settings: {
          ...data.settings,
          blocklists: data.settings.blocklists.map((entry) =>
            entry.id === source.id ? { ...entry, enabled } : entry,
          ),
        },
      },
    });

  const columns: Column<SourceRecord>[] = [
    { key: "name", header: "Name", render: (row) => row.name, sortValue: (row) => row.name },
    {
      key: "url",
      header: "Source",
      hideOnStack: true,
      render: (row) => (
        <span className="font-mono text-muted-foreground text-xs" title={row.url}>
          {truncateMiddle(row.url, 36)}
        </span>
      ),
    },
    {
      key: "profile",
      header: "Profile",
      hideOnStack: true,
      render: (row) => <Badge variant="outline">{row.profile}</Badge>,
      sortValue: (row) => row.profile,
    },
    {
      key: "refresh",
      header: "Refresh",
      hideOnStack: true,
      render: (row) => {
        const status = statusById.get(row.id);
        return (
          <span className="text-muted-foreground text-xs">
            every {row.refresh_interval_minutes}m
            {status?.last_refresh_attempt_at ? ` · last ${formatRelative(status.last_refresh_attempt_at)}` : ""}
            {status?.due_for_refresh ? " · due" : ""}
          </span>
        );
      },
    },
    {
      key: "status",
      header: "Status",
      render: (row) =>
        row.enabled ? <StatusPill label="Enabled" tone="good" /> : <StatusPill label="Disabled" tone="idle" />,
      sortValue: (row) => (row.enabled ? 1 : 0),
    },
    {
      key: "actions",
      header: "Actions",
      align: "end",
      render: (row) => (
        <span className="flex justify-end gap-1.5">
          <Button
            isLoading={busy === `blocklist-toggle-${row.id}`}
            onClick={(event) => {
              event.stopPropagation();
              void toggle(row, !row.enabled);
            }}
            size="sm"
            variant="outline"
          >
            {row.enabled ? "Disable" : "Enable"}
          </Button>
          <Button
            aria-label={`Delete ${row.name}`}
            onClick={(event) => {
              event.stopPropagation();
              setPendingDelete(row);
            }}
            size="icon-sm"
            title={`Delete ${row.name}`}
            variant="ghost"
          >
            <Trash2Icon aria-hidden />
          </Button>
        </span>
      ),
    },
  ];

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        description="Any domain, hosts or adblock-format list reachable from the appliance. `data:` URLs are accepted for small inline lists."
        footer={
          <Button
            disabled={!name.trim() || !url.trim()}
            isLoading={busy === "create-blocklist"}
            onClick={add}
          >
            <PlusIcon aria-hidden />
            Add blocklist
          </Button>
        }
        title="Add a blocklist"
      >
        <div className="space-y-4">
          <FieldRow>
            <TextField label="Name" onChange={setName} placeholder="OISD Big" value={name} />
            <TextField
              label="Source URL"
              onChange={setUrl}
              placeholder="https://big.oisd.nl"
              value={url}
            />
          </FieldRow>
          <div className="grid gap-6 sm:grid-cols-3">
            <SelectField
              label="Profile"
              onChange={setProfile}
              options={[
                { value: "custom", label: "Custom" },
                { value: "essential", label: "Essential" },
                { value: "balanced", label: "Balanced" },
                { value: "aggressive", label: "Aggressive" },
              ]}
              value={profile}
            />
            <SelectField
              hint="How strictly the fetched list is verified before activation."
              label="Strictness"
              onChange={setStrictness}
              options={[
                { value: "strict", label: "Strict" },
                { value: "balanced", label: "Balanced" },
                { value: "relaxed", label: "Relaxed" },
              ]}
              value={strictness}
            />
            <TextField
              inputMode="numeric"
              label="Refresh interval (minutes)"
              onChange={setInterval}
              placeholder="60"
              value={interval}
            />
          </div>
        </div>
      </SectionCard>

      <SectionCard
        description={`${formatCount(data.settings.blocklists.filter((source) => source.enabled).length)} of ${formatCount(data.settings.blocklists.length)} sources enabled.`}
        title="Configured sources"
      >
        <TextField
          className="mb-4"
          label="Search"
          onChange={setSearch}
          placeholder="Name or URL"
          searchTarget
          value={search}
        />
        <DataTable
          columns={columns}
          stackBelow="3xl"
          empty={{
            icon: HardDriveIcon,
            title: search ? "No sources match that search" : "No blocklists configured",
            description: search
              ? "Clear the search to see every configured source."
              : "Add at least one source so the ruleset has something to build from.",
          }}
          error={error}
          loading={phase === "loading"}
          onRetry={() => void reload()}
          rowKey={(row) => row.id}
          rows={filtered}
        />
      </SectionCard>

      <ConfirmDialog
        confirmLabel="Delete blocklist"
        consequence="The ruleset is rebuilt immediately, so any domains only this list covered stop being blocked."
        description={`"${pendingDelete?.name ?? ""}" will be removed from this appliance permanently.`}
        destructive
        onConfirm={async () => {
          if (!pendingDelete) return;
          const target = pendingDelete;
          await mutate({
            key: `blocklist-delete-${target.id}`,
            action: () => api.deleteBlocklist(target.id),
            successTitle: "Blocklist deleted",
            successDetail: `${target.name} was removed and the ruleset rebuilt.`,
            failureTitle: "Could not delete blocklist",
          });
        }}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
        open={pendingDelete !== null}
        title={`Delete ${pendingDelete?.name ?? "blocklist"}?`}
      />

    </div>
  );
}

/* -------------------------------------------------------------------------- */

function ProfilesPane() {
  const { data, phase, error, busy, mutate, reload } = useCogwheel();
  const profiles = data.settings.block_profiles;

  const [draft, setDraft] = React.useState<BlockProfileRecord>(emptyBlockProfileDraft);
  const [allowlistText, setAllowlistText] = React.useState("");
  const [creating, setCreating] = React.useState(true);
  const [customName, setCustomName] = React.useState("");
  const [customUrl, setCustomUrl] = React.useState("");
  const [pendingDelete, setPendingDelete] = React.useState<BlockProfileRecord | null>(null);

  // Match the old behaviour: land on the first profile so the editor is never
  // blank when saved profiles exist.
  React.useEffect(() => {
    if (!creating || draft.id) return;
    const first = profiles[0];
    if (first) {
      setDraft(first);
      setAllowlistText(first.allowlists.join(", "));
      setCreating(false);
    }
  }, [creating, draft.id, profiles]);

  const selectProfile = (profile: BlockProfileRecord) => {
    setDraft(profile);
    setAllowlistText(profile.allowlists.join(", "));
    setCreating(false);
  };

  const startNew = () => {
    setDraft(emptyBlockProfileDraft);
    setAllowlistText("");
    setCustomName("");
    setCustomUrl("");
    setCreating(true);
  };

  const togglePreset = (preset: BlockProfileListRecord) => {
    setDraft((current) => {
      const present = current.blocklists.some((entry) => entry.id === preset.id);
      const excluded = MUTUALLY_EXCLUSIVE_PRESETS[preset.id];
      const next = present
        ? current.blocklists.filter((entry) => entry.id !== preset.id)
        : [...current.blocklists.filter((entry) => entry.id !== excluded), preset];
      return { ...current, blocklists: next.sort((left, right) => left.name.localeCompare(right.name)) };
    });
  };

  const addCustomList = () => {
    if (!customName.trim() || !customUrl.trim()) {
      notify.error("List details required", "Enter both a list name and a GitHub URL before adding it.");
      return;
    }
    if (!/github\.com|raw\.githubusercontent\.com/.test(customUrl)) {
      notify.error("GitHub URL required", "Manual lists should point at a GitHub or raw GitHub blocklist URL.");
      return;
    }

    const id = slugify(customName) || `custom-${Date.now()}`;
    const entry: BlockProfileListRecord = {
      id,
      name: customName.trim(),
      url: customUrl.trim(),
      kind: "custom",
      family: "custom",
    };

    setDraft((current) => ({
      ...current,
      blocklists: [...current.blocklists.filter((existing) => existing.url !== entry.url), entry].sort(
        (left, right) => left.name.localeCompare(right.name),
      ),
    }));
    setCustomName("");
    setCustomUrl("");
    notify.success("List added to the draft", "Save the profile to persist it.");
  };

  const save = () => {
    if (!draft.name.trim()) {
      notify.error("Name required", "Give the profile a name your household will recognise.");
      return;
    }
    void mutate({
      key: "block-profile-save",
      action: () =>
        api.upsertBlockProfile({
          ...(creating ? {} : { id: draft.id }),
          emoji: draft.emoji,
          name: draft.name.trim(),
          description: draft.description,
          blocklists: draft.blocklists,
          allowlists: splitDomainList(allowlistText),
        }),
      successTitle: "Block profile saved",
      successDetail: `${draft.name.trim()} is ready for device assignment.`,
      failureTitle: "Could not save block profile",
    }).then((updated) => {
      if (updated) setCreating(false);
    });
  };

  return (
    <div className="grid gap-6 xl:grid-cols-[minmax(0,360px)_minmax(0,1fr)]">
      <SectionCard
        actions={
          <Button onClick={startNew} size="sm" variant="outline">
            <PlusIcon aria-hidden />
            New
          </Button>
        }
        description="Reusable bundles of lists and exceptions for different devices and routines."
        title="Profiles"
      >
        {/* `data.settings` starts life as the empty default in the provider, so
            without these guards a cold load and a failed fetch both render as
            "this household has no profiles". */}
        <AsyncRegion
          empty={
            <EmptyState
              description="Create one to group the lists a device should use, plus the exceptions it needs."
              icon={ShieldIcon}
              title="No saved profiles yet"
            />
          }
          error={error}
          errorTitle="Could not load block profiles"
          isEmpty={profiles.length === 0}
          loading={phase === "loading"}
          onRetry={() => void reload()}
          skeleton="text"
          skeletonRows={3}
        >
          <ul className="flex flex-col gap-1.5">
            {profiles.map((profile) => {
              const active = !creating && profile.id === draft.id;
              return (
                <li key={profile.id}>
                  <button
                    className={cn(
                      "flex w-full items-start gap-2 rounded-lg border px-3 py-2 text-left",
                      "hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring focus-visible:outline-offset-2",
                      active ? "border-primary bg-muted" : "border-border",
                    )}
                    onClick={() => selectProfile(profile)}
                    type="button"
                  >
                    <span aria-hidden className="text-base leading-5">
                      {profile.emoji || "◌"}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium text-foreground text-sm">
                        {profile.name}
                      </span>
                      {profile.description ? (
                        <span className="block truncate text-muted-foreground text-xs">
                          {profile.description}
                        </span>
                      ) : null}
                    </span>
                    <Badge variant="secondary">{formatCount(profile.blocklists.length)} sources</Badge>
                  </button>
                </li>
              );
            })}
          </ul>
        </AsyncRegion>
      </SectionCard>

      <SectionCard
        description="Core and NSFW families are kept mutually exclusive automatically."
        footer={
          <>
            {!creating && draft.id ? (
              <Button onClick={() => setPendingDelete(draft)} variant="outline">
                <Trash2Icon aria-hidden />
                Delete
              </Button>
            ) : null}
            <Button disabled={!draft.name.trim()} isLoading={busy === "block-profile-save"} onClick={save}>
              Save profile
            </Button>
          </>
        }
        title={creating ? "New profile" : `Edit ${draft.name || "profile"}`}
      >
        <div className="space-y-6">
          <div className="grid gap-6 sm:grid-cols-[90px_minmax(0,1fr)]">
            <TextField
              label="Emoji"
              onChange={(value) => setDraft((current) => ({ ...current, emoji: value }))}
              placeholder="🧩"
              value={draft.emoji}
            />
            <TextField
              label="Profile name"
              onChange={(value) => setDraft((current) => ({ ...current, name: value }))}
              placeholder="Homework hours"
              value={draft.name}
            />
          </div>

          <TextField
            label="Description"
            onChange={(value) => setDraft((current) => ({ ...current, description: value }))}
            placeholder="Tighter filtering on school nights"
            value={draft.description}
          />

          <section>
            <h3 className="font-medium text-foreground text-sm">OISD presets</h3>
            <div className="mt-2 grid gap-6 sm:grid-cols-2">
              {oisdProfileOptions.map((preset) => {
                const selected = draft.blocklists.some((entry) => entry.id === preset.id);
                return (
                  <button
                    aria-pressed={selected}
                    className={cn(
                      "rounded-lg border px-3 py-2 text-left",
                      "hover:bg-muted focus-visible:outline-2 focus-visible:outline-ring focus-visible:outline-offset-2",
                      selected ? "border-primary bg-muted" : "border-border",
                    )}
                    key={preset.id}
                    onClick={() => togglePreset(preset)}
                    type="button"
                  >
                    <span className="flex items-center justify-between gap-2">
                      <span className="font-medium text-foreground text-sm">{preset.name}</span>
                      <Badge variant="outline">{preset.id.includes("small") ? "small" : "full"}</Badge>
                    </span>
                    <span className="mt-1 block text-muted-foreground text-xs">
                      {preset.family.startsWith("nsfw")
                        ? "Adult-content focused OISD feed."
                        : "General-purpose OISD protection feed."}
                    </span>
                  </button>
                );
              })}
            </div>
          </section>

          <section>
            <h3 className="font-medium text-foreground text-sm">Custom GitHub lists</h3>
            <div className="mt-2 grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)_auto] sm:items-end">
              <TextField label="List name" onChange={setCustomName} placeholder="Extra trackers" value={customName} />
              <TextField
                label="URL"
                onChange={setCustomUrl}
                placeholder="https://raw.githubusercontent.com/…"
                value={customUrl}
              />
              <Button className="sm:mb-0.5" onClick={addCustomList} variant="secondary">
                Add list
              </Button>
            </div>
          </section>

          <TextField
            hint="Comma-separated domains that stay reachable even when a selected list blocks them."
            label="Allowlist exceptions"
            onChange={setAllowlistText}
            placeholder="school.site, printer.local"
            value={allowlistText}
          />

          <section>
            <h3 className="font-medium text-foreground text-sm">Active sources in this profile</h3>
            {draft.blocklists.length === 0 ? (
              <EmptyState
                className="mt-2"
                description="Choose at least one OISD preset or add a custom GitHub list."
                icon={HardDriveIcon}
                title="No sources selected"
              />
            ) : (
              <ul className="mt-2 flex flex-col gap-1.5">
                {draft.blocklists.map((entry) => (
                  <li
                    className="flex items-center gap-3 rounded-lg border border-border px-3 py-2"
                    key={entry.id}
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium text-foreground text-sm">{entry.name}</span>
                      <span className="block truncate font-mono text-muted-foreground text-xs">
                        {truncateMiddle(entry.url, 40)}
                      </span>
                    </span>
                    <Badge variant="outline">{entry.kind}</Badge>
                    <Button
                      aria-label={`Remove ${entry.name}`}
                      onClick={() =>
                        setDraft((current) => ({
                          ...current,
                          blocklists: current.blocklists.filter((item) => item.id !== entry.id),
                        }))
                      }
                      size="icon-sm"
                      variant="ghost"
                    >
                      <XIcon aria-hidden />
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </SectionCard>

      <ConfirmDialog
        confirmLabel="Delete profile"
        consequence="Devices pointing at this profile fall back to the household default."
        description={`"${pendingDelete?.name ?? ""}" and its saved list selection will be removed.`}
        destructive
        onConfirm={async () => {
          if (!pendingDelete) return;
          const target = pendingDelete;
          const result = await mutate({
            key: "block-profile-delete",
            action: () => api.deleteBlockProfile(target.id),
            successTitle: "Block profile deleted",
            successDetail: `${target.name} was removed.`,
            failureTitle: "Could not delete block profile",
          });
          if (result) startNew();
        }}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
        open={pendingDelete !== null}
        title={`Delete ${pendingDelete?.name ?? "profile"}?`}
      />
    </div>
  );
}
