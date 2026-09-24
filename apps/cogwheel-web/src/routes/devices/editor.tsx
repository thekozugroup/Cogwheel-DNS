import React from "react";
import { Trash2Icon } from "lucide-react";
import { api, type Device, type DeviceInput, type ListSource, type RuleAction } from "@/lib/api";
import { chosenEnabledLists, domainProblem, isIpAddress, isRuleDomain, normalizeDomain } from "@/lib/derive";
import { formatCount, pluralize } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useCogwheelActions, useCogwheelStatus } from "@/data/context";
import { Button } from "@/components/ui/button";
import { IconButton } from "@/components/ui/icon-button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { SectionCard } from "@/components/app/section-card";
import { FormField } from "@/components/app/form-field";
import { StatusPill } from "@/components/app/status-indicator";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { DomainName } from "@/components/app/domain-name";
import { DomainField, RowButtonSlot, RuleActionField } from "@/routes/rule-fields";

type ListMode = "all" | "some" | "none";
type StagedRule = { domain: string; action: RuleAction };

type Draft = {
  name: string;
  ip_address: string;
  filtering: boolean;
  mode: ListMode;
  lists: string[];
  rules: StagedRule[];
};

function draftFrom(device: Device | null, ip: string, enabled: ReadonlySet<string>): Draft {
  if (!device) return { name: "", ip_address: ip, filtering: true, mode: "all", lists: [], rules: [] };
  return {
    name: device.name,
    ip_address: device.ip_address,
    filtering: device.filtering,
    // "No lists" is its own choice. A device that chose only lists which are
    // now off or gone opens on it, because that is what it is doing.
    mode: device.all_lists ? "all" : chosenEnabledLists(device, enabled).length > 0 ? "some" : "none",
    lists: device.lists,
    rules: device.rules.map(({ domain, action }) => ({ domain, action })),
  };
}

type RuleRow = StagedRule & { id?: number; change: "new" | "changed" | "removed" | null };

/**
 * The saved rules and the staged ones, as one list in a stable order: saved
 * rules where they were (a removed one struck through, with Undo), new ones
 * after them. Nothing moves when a rule is removed, so Undo is where the
 * trash button was.
 */
function ruleRows(saved: Device["rules"], staged: StagedRule[]): RuleRow[] {
  const rows: RuleRow[] = saved.map((rule) => {
    const now = staged.find((entry) => entry.domain === rule.domain);
    if (!now) return { ...rule, change: "removed" };
    return { ...rule, action: now.action, change: now.action === rule.action ? null : "changed" };
  });
  for (const entry of staged) {
    if (!saved.some((rule) => rule.domain === entry.domain)) rows.push({ ...entry, change: "new" });
  }
  return rows;
}

const CHANGE_WORD = { new: "New", changed: "Changed", removed: "Removed" } as const;

/**
 * Add, edit and delete. Everything in the form — name, address, filtering,
 * lists and the device's own rules — is saved together by Save and thrown
 * away together by Cancel. Rules used to be written the moment Add or the
 * trash button was pressed, inside a form whose Save and Cancel said nothing
 * was written until Save; Cancel then left them in place.
 */
export function DeviceEditor({
  device,
  devices,
  ip,
  lists,
  enabled,
  onClose,
  onCreated,
}: {
  device: Device | null;
  devices: Device[];
  ip: string;
  lists: ListSource[];
  enabled: ReadonlySet<string>;
  /** Close the form; focus goes back to the button with this name, if any. */
  onClose: (returnTo?: string) => void;
  /** A new device was created but not all of its rules were: edit it instead. */
  onCreated: (id: string) => void;
}) {
  const { busy } = useCogwheelStatus();
  const { mutate, reload } = useCogwheelActions();
  const [draft, setDraft] = React.useState<Draft>(() => draftFrom(device, ip, enabled));
  const [submitted, setSubmitted] = React.useState(false);
  const [ipTouched, setIpTouched] = React.useState(false);
  const [ruleDomain, setRuleDomain] = React.useState("");
  const [ruleAction, setRuleAction] = React.useState<RuleAction>("block");
  const [ruleError, setRuleError] = React.useState<string | undefined>();
  const [deleting, setDeleting] = React.useState(false);

  const formRef = React.useRef<HTMLFormElement>(null);
  const nameRef = React.useRef<HTMLInputElement>(null);
  const ipRef = React.useRef<HTMLInputElement>(null);
  const firstListRef = React.useRef<HTMLInputElement>(null);
  const ruleRef = React.useRef<HTMLInputElement>(null);
  const ids = {
    filtering: React.useId(),
    filteringHint: React.useId(),
    listsError: React.useId(),
    rules: React.useId(),
  };

  // By name, as the Lists page orders them; the wire order is by UUID.
  const enabledLists = lists
    .filter((list) => list.enabled)
    .sort((left, right) => left.name.localeCompare(right.name, undefined, { sensitivity: "base" }));
  const saving = busy === "device-save";
  const set = (patch: Partial<Draft>) => setDraft((current) => ({ ...current, ...patch }));

  // The form comes to the reader: it opens below the table, and from Unnamed
  // devices it opens above the row that was pressed. Adding goes straight to
  // the first field; editing puts focus on the form itself, so a keyboard
  // user lands in it without a phone raising its keyboard over the switches.
  const isEdit = device !== null;
  React.useEffect(() => {
    formRef.current?.scrollIntoView({ block: "nearest" });
    if (isEdit) formRef.current?.focus({ preventScroll: true });
    else nameRef.current?.focus({ preventScroll: true });
  }, [isEdit]);

  /* Validation. Shown once Save has been pressed; the address also once the
     field has been left, since "192.168.1." is not wrong while it is typed. */
  const takenBy = devices.find(
    (other) => other.id !== device?.id && other.ip_address === draft.ip_address.trim(),
  );
  const nameProblem = draft.name.trim() ? undefined : "Give the device a name, like Kitchen iPad.";
  const ipProblem = !draft.ip_address.trim()
    ? "Type the address this device uses, like 192.168.1.42."
    : !isIpAddress(draft.ip_address)
      ? "That is not an IP address. One looks like 192.168.1.42."
      : takenBy
        ? `${takenBy.name} already has this address.`
        : undefined;
  const chosen = chosenEnabledLists({ all_lists: false, lists: draft.lists }, enabled);
  const listsProblem =
    draft.mode === "some" && chosen.length === 0 ? "Tick at least one list, or choose No lists." : undefined;

  const nameError = submitted ? nameProblem : undefined;
  const ipError =
    submitted || (ipTouched && draft.ip_address.trim()) ? ipProblem : undefined;
  const listsError = submitted ? listsProblem : undefined;

  const saved = device?.rules ?? [];
  const rows = ruleRows(saved, draft.rules);

  const chooseMode = (mode: ListMode) =>
    setDraft((current) => ({
      ...current,
      mode,
      // Switching to "Choose lists" with nothing chosen starts from every
      // enabled list ticked. Starting from none made the easiest path — pick
      // the option, press Save — a device with no list filtering at all.
      lists:
        mode === "some" && chosenEnabledLists({ all_lists: false, lists: current.lists }, enabled).length === 0
          ? enabledLists.map((list) => list.id)
          : current.lists,
    }));

  const stageRule = () => {
    const domain = normalizeDomain(ruleDomain);
    const problem = domainProblem(ruleDomain, isRuleDomain(domain));
    if (problem) {
      setRuleError(problem);
      ruleRef.current?.focus();
      return;
    }
    setDraft((current) => {
      const existing = current.rules.findIndex((rule) => rule.domain === domain);
      const rules = [...current.rules];
      if (existing >= 0) rules[existing] = { domain, action: ruleAction };
      else rules.push({ domain, action: ruleAction });
      return { ...current, rules };
    });
    setRuleDomain("");
    setRuleError(undefined);
  };

  const unstageRule = (domain: string) =>
    set({ rules: draft.rules.filter((rule) => rule.domain !== domain) });

  const restoreRule = (rule: RuleRow) =>
    set({ rules: [...draft.rules, { domain: rule.domain, action: saved.find((s) => s.domain === rule.domain)?.action ?? rule.action }] });

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (saving) return;
    setSubmitted(true);
    setIpTouched(true);
    if (nameProblem) return nameRef.current?.focus();
    if (ipProblem) return ipRef.current?.focus();
    if (listsProblem) return firstListRef.current?.focus();

    const input: DeviceInput = {
      name: draft.name.trim(),
      ip_address: draft.ip_address.trim(),
      filtering: draft.filtering,
      all_lists: draft.mode === "all",
      lists: draft.mode === "some" ? draft.lists : [],
    };
    const removed = rows.filter((row) => row.change === "removed" && row.id !== undefined);
    const upserts = rows.filter((row) => row.change === "new" || row.change === "changed");
    const changes = [
      upserts.filter((row) => row.change === "new").length,
      upserts.filter((row) => row.change === "changed").length,
      removed.length,
    ];
    const summary = ruleSummary(changes[0], changes[1], changes[2]);
    const created = { id: null as string | null };

    const result = await mutate({
      key: "device-save",
      action: async () => {
        const stored = device ? await api.updateDevice(device.id, input) : await api.createDevice(input);
        created.id = stored.id;
        try {
          for (const rule of removed) {
            await api.deleteRule(rule.id as number).catch((cause: { status?: number }) => {
              // Already gone — removed from Activity or another tab — is done.
              if (cause?.status !== 404) throw cause;
            });
          }
          for (const rule of upserts) {
            await api.createRule({ domain: rule.domain, action: rule.action, device_id: stored.id });
          }
        } catch (cause) {
          const reason = cause instanceof Error ? cause.message : String(cause);
          throw new Error(`${stored.name} was saved, but not all of its rules were: ${reason}`);
        }
        return stored;
      },
      successTitle: device ? "Device updated" : "Device added",
      successDetail: (stored) => `${stored.name} at ${stored.ip_address}.${summary ? ` ${summary}` : ""}`,
      failureTitle: device ? `Could not save ${device.name}` : "Could not add the device",
    });

    if (result) {
      onClose(`Edit ${result.name}`);
      return;
    }
    // A failure part-way leaves the device saved and some rules not. Reload so
    // what is on screen is what is stored; a new device becomes an edit of the
    // one that now exists, so a second Save does not try to create it twice.
    await reload();
    if (!device && created.id) onCreated(created.id);
  };

  const remove = async () => {
    if (!device) return;
    const result = await mutate({
      key: "device-delete",
      action: () => api.deleteDevice(device.id),
      successTitle: "Device deleted",
      successDetail: `${device.name}. ${device.ip_address} now gets the household's lists and rules.`,
      failureTitle: `Could not delete ${device.name}`,
    });
    if (result) onClose();
  };

  const title = device ? `Edit ${device.name}` : "Add device";

  return (
    <form
      aria-label={title}
      className="scroll-mt-6 rounded-xl"
      id="device-form"
      noValidate
      onSubmit={(event) => void submit(event)}
      ref={formRef}
      tabIndex={-1}
    >
      <SectionCard
        footer={
          // Full width, so Delete device has room to be pushed to the far end
          // instead of sitting 8px from Cancel.
          <div className="flex w-full flex-wrap items-center gap-2">
            <Button isLoading={saving} type="submit">
              {device ? "Save" : "Add device"}
            </Button>
            <Button onClick={() => onClose(device ? `Edit ${device.name}` : undefined)} variant="ghost">
              Cancel
            </Button>
            {device ? (
              <Button className="ms-auto" onClick={() => setDeleting(true)} variant="destructive">
                <Trash2Icon aria-hidden />
                Delete device
              </Button>
            ) : null}
          </div>
        }
        title={title}
      >
        <div className="space-y-6">
          {/* Capped by what they hold. A device name is a few words and an IP
              is fifteen characters; neither is 1,000px wide. */}
          <FormField className="max-w-md" error={nameError} label="Name" required>
            <Input
              autoComplete="off"
              onChange={(event) => set({ name: event.target.value })}
              placeholder="Kitchen iPad"
              ref={nameRef}
              value={draft.name}
            />
          </FormField>
          <FormField
            className="max-w-xs"
            error={ipError}
            hint="The address this device gets from your router."
            label="IP address"
            required
          >
            <Input
              autoComplete="off"
              inputMode="decimal"
              onBlur={() => setIpTouched(true)}
              onChange={(event) => set({ ip_address: event.target.value })}
              placeholder="192.168.1.42"
              ref={ipRef}
              spellCheck={false}
              value={draft.ip_address}
            />
          </FormField>

          <div className="flex max-w-md items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="font-medium text-foreground text-sm" id={ids.filtering}>
                Filtering
              </p>
              <p className="text-muted-foreground text-sm" id={ids.filteringHint}>
                Off: this device resolves everything and is still logged.
              </p>
            </div>
            <Switch
              aria-describedby={ids.filteringHint}
              aria-labelledby={ids.filtering}
              checked={draft.filtering}
              onCheckedChange={(details) => set({ filtering: details.checked })}
            />
          </div>

          <fieldset aria-describedby={listsError ? ids.listsError : undefined} className="space-y-1">
            <legend className="mb-1 font-medium text-foreground text-sm">Lists</legend>
            <Radio
              checked={draft.mode === "all"}
              label="Use all household lists"
              name="device-lists"
              onSelect={() => chooseMode("all")}
            />
            <Radio
              checked={draft.mode === "some"}
              label="Choose lists"
              name="device-lists"
              onSelect={() => chooseMode("some")}
            />
            {draft.mode === "some" ? (
              <div className="space-y-1 ps-6">
                {enabledLists.length === 0 ? (
                  <p className="py-1 text-muted-foreground text-sm">No lists are enabled yet.</p>
                ) : (
                  enabledLists.map((list, index) => (
                    <label className="flex items-center gap-2 py-1 text-sm" key={list.id}>
                      <input
                        aria-invalid={listsError ? true : undefined}
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
                        ref={index === 0 ? firstListRef : undefined}
                        type="checkbox"
                      />
                      {list.name}
                    </label>
                  ))
                )}
              </div>
            ) : null}
            <Radio
              checked={draft.mode === "none"}
              detail="Only rules apply. Nothing on a list is blocked for this device."
              label="No lists"
              name="device-lists"
              onSelect={() => chooseMode("none")}
            />
            {listsError ? (
              <p className="pt-1 text-destructive-foreground text-sm" id={ids.listsError}>
                {listsError}
              </p>
            ) : null}
          </fieldset>

          <section aria-labelledby={ids.rules} className="space-y-3">
            <div>
              <h3 className="font-medium text-foreground text-sm" id={ids.rules}>
                Rules for this device
              </h3>
              <p className="text-muted-foreground text-sm">
                They come before every list and household rule. Saved with the device.
              </p>
            </div>
            <div className="flex flex-wrap items-start gap-x-3 gap-y-4">
              <DomainField
                className="max-w-md flex-1 basis-64"
                error={ruleError}
                inputRef={ruleRef}
                onChange={(value) => {
                  setRuleDomain(value);
                  if (ruleError) setRuleError(undefined);
                }}
                // Enter here adds the rule; it must not save the whole device.
                onKeyDown={(event) => {
                  if (event.key !== "Enter") return;
                  event.preventDefault();
                  stageRule();
                }}
                required={false}
                value={ruleDomain}
              />
              <RuleActionField onChange={setRuleAction} value={ruleAction} />
              <RowButtonSlot>
                <Button onClick={stageRule} variant="outline">
                  Add rule
                </Button>
              </RowButtonSlot>
            </div>

            {rows.length > 0 ? (
              <ul
                aria-label={`Rules for ${draft.name.trim() || "this device"}`}
                className="max-w-2xl divide-y divide-border"
              >
                {rows.map((rule) => (
                  <li className="flex min-h-11 items-center gap-3 py-1.5" key={rule.domain}>
                    <span
                      className={cn(
                        "min-w-0 flex-1 font-mono text-sm [overflow-wrap:anywhere]",
                        rule.change === "removed" && "text-muted-foreground line-through",
                      )}
                    >
                      <DomainName name={rule.domain} />
                    </span>
                    {rule.change ? (
                      <span className="shrink-0 text-muted-foreground text-xs">{CHANGE_WORD[rule.change]}</span>
                    ) : null}
                    {rule.change === "removed" ? (
                      <Button
                        aria-label={`Undo removing ${rule.domain}`}
                        onClick={() => restoreRule(rule)}
                        size="sm"
                        variant="ghost"
                      >
                        Undo
                      </Button>
                    ) : (
                      <>
                        <StatusPill
                          label={rule.action === "allow" ? "Allow" : "Block"}
                          tone={rule.action === "allow" ? "good" : "bad"}
                          verdict
                        />
                        <IconButton label={`Remove ${rule.domain}`} onClick={() => unstageRule(rule.domain)}>
                          <Trash2Icon aria-hidden />
                        </IconButton>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            ) : null}
          </section>
        </div>
      </SectionCard>

      {device ? (
        <ConfirmDialog
          confirmLabel="Delete device"
          consequence={
            device.filtering
              ? `${device.ip_address} gets the household's lists and rules instead of its own.`
              : `${device.ip_address} is filtered again, with the household's lists and rules.`
          }
          description={
            device.rules.length > 0
              ? `Its name, its settings and its ${pluralize(device.rules.length, "rule")} are deleted.`
              : "Its name and its settings are deleted."
          }
          tone="bad"
          onConfirm={remove}
          onOpenChange={setDeleting}
          open={deleting}
          title={`Delete "${device.name}"?`}
        />
      ) : null}
    </form>
  );
}

/** "1 rule added.", "2 rules added, 1 removed." — or nothing. */
function ruleSummary(added: number, changed: number, removed: number): string {
  const parts: string[] = [];
  const first = (count: number, verb: string) =>
    parts.length === 0 ? `${pluralize(count, "rule")} ${verb}` : `${formatCount(count)} ${verb}`;
  if (added > 0) parts.push(first(added, "added"));
  if (changed > 0) parts.push(first(changed, "changed"));
  if (removed > 0) parts.push(first(removed, "removed"));
  return parts.length > 0 ? `${parts.join(", ")}.` : "";
}

/** Native radio: the app has no radio primitive, and this is three options. */
function Radio({
  checked,
  label,
  detail,
  name,
  onSelect,
}: {
  checked: boolean;
  label: string;
  detail?: string;
  name: string;
  onSelect: () => void;
}) {
  return (
    <label className="flex items-start gap-2 py-1 text-sm">
      <input
        checked={checked}
        className="mt-0.5 size-4 shrink-0 accent-foreground"
        name={name}
        onChange={onSelect}
        type="radio"
      />
      <span className="min-w-0">
        <span className="block">{label}</span>
        {detail ? <span className="block text-muted-foreground">{detail}</span> : null}
      </span>
    </label>
  );
}
