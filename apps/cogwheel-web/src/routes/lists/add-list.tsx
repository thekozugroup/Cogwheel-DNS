import React from "react";
import { api, type ListKind, type ListSource } from "@/lib/api";
import { LIST_KINDS, LIST_KIND_HINT, listErrorSentence } from "@/lib/derive";
import { STRENGTH_TIERS, subscribedAs, tierPreset, type ListPreset, type Strength } from "@/lib/presets";
import { formatCount, pluralize } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useCogwheelActions, useCogwheelStatus } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { SectionCard } from "@/components/app/section-card";
import { SelectField } from "@/components/app/select-field";
import { FieldRow, FormField, GroupLabel } from "@/components/app/form-field";

type Choice = Strength | "more";

/**
 * Three choices by how much they block, and everything else one step away.
 * The picker used to be the server's eleven presets in a dropdown, named by
 * publisher, with no word on what separates them.
 */
export function AddList({
  presets,
  lists,
  onDone,
}: {
  presets: ListPreset[];
  lists: ListSource[];
  onDone: () => void;
}) {
  const { busy } = useCogwheelStatus();
  const { mutate } = useCogwheelActions();
  const formRef = React.useRef<HTMLFormElement>(null);
  const nameRef = React.useRef<HTMLInputElement>(null);
  const urlRef = React.useRef<HTMLInputElement>(null);
  const enabledLabel = React.useId();

  const tiers = STRENGTH_TIERS.map((tier) => {
    const preset = tierPreset(tier, presets);
    return { ...tier, preset, subscribed: subscribedAs(preset, lists) };
  });
  // Opens on the gentlest tier not already subscribed. A fresh install is
  // seeded with oisd small, so for most people that is Balanced.
  const [choice, setChoice] = React.useState<Choice>(
    () => tiers.find((tier) => !tier.subscribed)?.value ?? "more",
  );
  const [preset, setPreset] = React.useState("");
  const [name, setName] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [kind, setKind] = React.useState<ListKind>("adblock");
  const [enabled, setEnabled] = React.useState(true);
  const [submitted, setSubmitted] = React.useState(false);

  const adding = busy === "list-add";
  const tier = tiers.find((entry) => entry.value === choice);

  React.useEffect(() => {
    formRef.current?.scrollIntoView({ block: "nearest" });
  }, []);

  const choosePreset = (value: string) => {
    setPreset(value);
    const match = presets.find((entry) => entry.name === value);
    if (!match) return;
    setName(match.name);
    setUrl(match.url);
    setKind(match.kind);
  };

  // "More lists" is the one branch with fields to get wrong.
  const nameTaken = lists.find((list) => list.name.toLocaleLowerCase() === name.trim().toLocaleLowerCase());
  const urlTaken = lists.find((list) => list.url.trim() === url.trim());
  const nameProblem = !name.trim()
    ? "Give the list a name. It is what a blocked query is credited to."
    : nameTaken
      ? `There is already a list called ${nameTaken.name}.`
      : undefined;
  const urlProblem = !url.trim()
    ? "Paste the list's address. It starts with https://."
    : !isListUrl(url)
      ? "That is not a web address. It should start with https://."
      : urlTaken
        ? `This address is already subscribed, as ${urlTaken.name}.`
        : undefined;

  const target = choice === "more" ? null : tier?.preset;
  const submitLabel = target ? `Add ${target.name}` : "Add list";

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (adding) return;
    let input: { name: string; url: string; kind: ListKind; enabled: boolean };
    if (choice === "more") {
      setSubmitted(true);
      if (nameProblem) return nameRef.current?.focus();
      if (urlProblem) return urlRef.current?.focus();
      input = { name: name.trim(), url: url.trim(), kind, enabled };
    } else {
      if (!target || tier?.subscribed) return;
      input = { ...target, enabled: true };
    }

    const result = await mutate({
      key: "list-add",
      action: () => api.createList(input),
      successTitle: (created) =>
        created.outcome === "failed"
          ? `${created.list.name} added, but not downloaded`
          : created.outcome === "rejected"
            ? `${created.list.name} added, but it could not be read`
            : `${created.list.name} added`,
      successDetail: (created) =>
        created.outcome === "failed"
          ? listErrorSentence(created.list.last_error ?? created.note ?? "")
          : created.outcome === "rejected"
            ? "It downloaded, but no rules came out of it. Check its format."
            : (created.note ?? `${pluralize(created.list.rule_count, "rule")} loaded.`),
      failureTitle: `Could not add ${input.name}`,
    });
    if (result) onDone();
  };

  return (
    <form aria-label="Add a list" id="add-list" noValidate onSubmit={(event) => void submit(event)} ref={formRef}>
      <SectionCard
        busy={adding}
        description={
          adding ? `Downloading ${target?.name ?? name.trim()}…` : "Stronger lists block more, and break more sites."
        }
        footer={
          <div className="flex flex-wrap items-center gap-2">
            <Button isLoading={adding} type="submit">
              {submitLabel}
            </Button>
            <Button disabled={adding} onClick={onDone} variant="ghost">
              Cancel
            </Button>
          </div>
        }
        title="Add a list"
      >
        <fieldset>
          <legend className="sr-only">How much to block</legend>
          <div className="-mt-3 divide-y divide-border">
            {tiers.map((entry) => (
              <ChoiceRow
                checked={choice === entry.value}
                detail={entry.subscribed ? `${entry.preset.name} · subscribed` : entry.preset.name}
                disabled={Boolean(entry.subscribed)}
                key={entry.value}
                label={entry.label}
                onSelect={() => setChoice(entry.value)}
                value={entry.value}
                what={entry.tradeoff}
              />
            ))}
            <ChoiceRow
              checked={choice === "more"}
              detail={`${formatCount(presets.length)} presets`}
              label="More lists"
              onSelect={() => setChoice("more")}
              value="more"
              what="Any list Cogwheel knows, or your own by its address."
            />
          </div>
        </fieldset>

        {choice === "more" ? (
          <div className="space-y-6 ps-7 pt-3">
            <SelectField
              hint="Fills in the fields below. Or leave it, and type your own."
              label="Preset"
              onChange={choosePreset}
              options={presets.map((entry) => {
                const taken = subscribedAs(entry, lists);
                return {
                  value: entry.name,
                  label: taken ? `${entry.name} (subscribed)` : entry.name,
                  disabled: Boolean(taken),
                };
              })}
              placeholder={presets.length > 0 ? "Choose a preset…" : "Loading presets…"}
              value={preset}
            />
            <FieldRow>
              <FormField error={submitted ? nameProblem : undefined} label="Name" required>
                <Input
                  autoComplete="off"
                  onChange={(event) => setName(event.target.value)}
                  placeholder="My blocklist"
                  ref={nameRef}
                  value={name}
                />
              </FormField>
              <FormField error={submitted ? urlProblem : undefined} label="Address" required>
                <Input
                  autoCapitalize="none"
                  autoComplete="off"
                  inputMode="url"
                  onChange={(event) => setUrl(event.target.value)}
                  placeholder="https://example.com/list.txt"
                  ref={urlRef}
                  spellCheck={false}
                  type="url"
                  value={url}
                />
              </FormField>
            </FieldRow>
            <FieldRow>
              <SelectField
                hint={`How the file is written — guessing wrong loads zero rules. ${LIST_KIND_HINT}`}
                label="Format"
                onChange={(value) => setKind(value as ListKind)}
                options={LIST_KINDS}
                value={kind}
              />
              <div className="flex flex-col gap-2">
                <GroupLabel id={enabledLabel}>Enabled</GroupLabel>
                <div className="flex min-h-8 items-center">
                  <Switch
                    aria-labelledby={enabledLabel}
                    checked={enabled}
                    onCheckedChange={(details) => setEnabled(details.checked)}
                  />
                </div>
              </div>
            </FieldRow>
          </div>
        ) : null}
      </SectionCard>
    </form>
  );
}

function isListUrl(value: string): boolean {
  try {
    return ["http:", "https:", "data:"].includes(new URL(value.trim()).protocol);
  } catch {
    return false;
  }
}

/** One radio row: the choice, what it costs, and the list behind it. */
function ChoiceRow({
  value,
  label,
  what,
  detail,
  checked,
  disabled = false,
  onSelect,
}: {
  value: string;
  label: string;
  what: string;
  detail: string;
  checked: boolean;
  disabled?: boolean;
  onSelect: () => void;
}) {
  return (
    <label className={cn("flex items-start gap-3 py-3", disabled ? "cursor-default" : "cursor-pointer")}>
      <input
        checked={checked}
        className="mt-0.5 size-4 shrink-0 accent-foreground"
        disabled={disabled}
        name="list-strength"
        onChange={onSelect}
        type="radio"
        value={value}
      />
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-baseline justify-between gap-x-3">
          <span className={cn("font-medium text-sm", disabled ? "text-muted-foreground" : "text-foreground")}>
            {label}
          </span>
          <span className="text-muted-foreground text-xs">{detail}</span>
        </span>
        <span className="block text-muted-foreground text-sm">{what}</span>
      </span>
    </label>
  );
}
