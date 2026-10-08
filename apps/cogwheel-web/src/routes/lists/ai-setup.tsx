import React from "react";
import { RotateCwIcon } from "lucide-react";
import { api, errorMessage, type AiDailyLimit, type AiModelList, type AiPatch, type AiStatus } from "@/lib/api";
import { formatCents, formatEstimate, formatUsd } from "@/lib/format";
import { notify } from "@/lib/toast";
import { useCogwheelActions } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Status } from "@/components/ui/status";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { FormField, GroupLabel } from "@/components/app/form-field";
import { SelectField } from "@/components/app/select-field";

/*
 * Setting up AI review: the key, the model, the daily limit, a Test, and the
 * dialog that asks before names start leaving the house.
 *
 * The key lives in this form's own state and nowhere else — not the snapshot,
 * not localStorage, not an optimistic patch — and the field is emptied after
 * every save, whatever the answer. Nothing the server sends back contains it.
 */

const DAILY_LIMITS: readonly AiDailyLimit[] = [0.05, 0.1, 0.25, 1];

/** The server's shape check for a pasted key, so a typo is caught before the round trip. */
const KEY_SHAPE = /^[\x21-\x7e]{20,256}$/;

/** "Jev 1.13" from "TypeSafe: Jev 1.13". The picker is choosing a model; the maker is in its id. */
function shortModelName(name: string): string {
  const colon = name.indexOf(": ");
  return colon >= 0 ? name.slice(colon + 2) : name;
}

/** Midnight UTC, when the daily limit resets, on the reader's own clock. */
function resetTime(): string {
  const now = new Date();
  const midnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(midnight);
}

/** The Test's answer or why it failed. */
export type TestOutcome = { ok: boolean; sentence: string } | null;

/**
 * A dot and the server's sentence, in a region that is always mounted so the
 * answer is announced when it lands. Green only for a passed Test: the
 * sentence is the server's, and it says how sure the model was.
 */
export function TestLine({ outcome, className }: { outcome: TestOutcome; className?: string }) {
  return (
    <div aria-live="polite" className={className}>
      {outcome ? (
        <p className="flex items-start gap-2.5 text-foreground text-sm">
          <Status className="mt-1.5" size="sm" variant={outcome.ok ? "success" : "destructive"} />
          <span className="min-w-0 max-w-[56ch] break-words">{outcome.sentence}</span>
        </p>
      ) : null}
    </div>
  );
}

/** The one place a household agrees to names leaving the network. */
export function TurnOnDialog({
  open,
  onOpenChange,
  limitUsd,
  onConfirm,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  limitUsd: number;
  onConfirm: () => Promise<void>;
}) {
  return (
    <ConfirmDialog
      confirmLabel="Turn on"
      consequence={`Paid from your OpenRouter account, up to ${formatCents(limitUsd)} a day.`}
      description="From now on, the names of websites your household opens, and the domains they load, are sent to OpenRouter and the model's provider. The answers become the AI list on this page. Your own rules still beat it."
      onConfirm={onConfirm}
      onOpenChange={onOpenChange}
      open={open}
      title="Turn on AI review?"
      tone="warn"
    />
  );
}

/** "Remove…" and its dialog. Removing a secret is never refused, so this is offered even while unavailable. */
export function RemoveKey({ label = "Remove…", onRemoved }: { label?: string; onRemoved: (next: AiStatus) => void }) {
  const { mutate } = useCogwheelActions();
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)} variant="outline">
        {label}
      </Button>
      <ConfirmDialog
        confirmLabel="Remove key"
        description="AI review stops judging new names at once. Verdicts already made keep applying until you turn AI review off."
        onConfirm={async () => {
          const next = await mutate({
            key: "ai-key-remove",
            action: () => api.updateAi({ key: null }),
            successTitle: "OpenRouter key removed",
            failureTitle: "Could not remove the key",
          });
          if (next) onRemoved(next);
        }}
        onOpenChange={setOpen}
        open={open}
        title="Remove the OpenRouter key?"
      />
    </>
  );
}

type Field = "key" | "model" | "limit";
type Problems = Partial<Record<Field | "form", string>>;

/** Which field a refusal from PUT /ai belongs under, from the sentence the server sent. */
function fieldFor(message: string): Field | "form" {
  if (/daily limit/i.test(message)) return "limit";
  if (/model/i.test(message)) return "model";
  if (/OpenRouter key|that key|refused the key/i.test(message)) return "key";
  return "form";
}

/** What the saved key is good for, in words. Never any part of the key itself. */
function savedKeyLine(key: AiStatus["key"]): { text: string; warn: boolean } {
  if (key.limit_usd === null && key.checked_at === null) {
    return { text: "Saved key · credit limit not checked yet", warn: false };
  }
  if (key.limit_usd === null) return { text: "Saved key · this key has no credit limit.", warn: true };
  return {
    text: `Saved key · ${formatUsd(key.limit_remaining_usd)} of its ${formatUsd(key.limit_usd)} limit left`,
    warn: false,
  };
}

/**
 * The set-up form. `first` turns review on, through the dialog; `edit` saves
 * what changed and leaves the switch where it is.
 */
export function AiSetupForm({
  status,
  mode,
  onSaved,
  onStatus,
  onCancel,
  onTested,
}: {
  status: AiStatus;
  mode: "first" | "edit";
  /** A save went through: the new status, and the form can close. */
  onSaved: (next: AiStatus) => void;
  /** The status changed and the form stays open: the key was removed from inside it. */
  onStatus: (next: AiStatus) => void;
  onCancel: () => void;
  /** A Test is paid for and counted in today's spend, so the card re-reads its status after one. */
  onTested: () => void;
}) {
  const { reload } = useCogwheelActions();
  const headingId = React.useId();
  const keyRef = React.useRef<HTMLInputElement>(null);
  const modelRef = React.useRef<HTMLSelectElement>(null);
  const [key, setKey] = React.useState("");
  const [replacing, setReplacing] = React.useState(false);
  const [model, setModel] = React.useState(status.model?.id ?? "");
  const [limit, setLimit] = React.useState<AiDailyLimit>(
    () => DAILY_LIMITS.find((value) => Math.abs(value - status.daily_limit_usd) < 1e-9) ?? 0.1,
  );
  const [problems, setProblems] = React.useState<Problems>({});
  const [models, setModels] = React.useState<{ list: AiModelList | null; error: string | null }>({
    list: null,
    error: null,
  });
  const [attempt, setAttempt] = React.useState(0);
  const [testing, setTesting] = React.useState(false);
  const [outcome, setOutcome] = React.useState<TestOutcome>(null);
  const [saving, setSaving] = React.useState(false);
  const [confirming, setConfirming] = React.useState(false);

  React.useEffect(() => {
    const controller = new AbortController();
    api
      .aiModels({ signal: controller.signal })
      .then((list) => setModels({ list, error: null }))
      .catch((cause) => {
        if (cause instanceof DOMException && cause.name === "AbortError") return;
        setModels((current) => ({ list: current.list, error: errorMessage(cause) }));
      });
    return () => controller.abort();
  }, [attempt]);

  const source = status.key.source;
  const typingKey = source === "none" || (source === "saved" && replacing);
  const required = models.list?.zero_retention_required ?? status.zero_retention;
  const listed = [...(models.list?.models ?? [])].sort(
    (left, right) => (left.usd_per_thousand_names ?? Infinity) - (right.usd_per_thousand_names ?? Infinity),
  );
  const greyed = required && listed.some((entry) => entry.zero_retention === false);
  const chosen = listed.find((entry) => entry.id === model);
  // The saved model stays selectable when the listing failed or no longer has it.
  const saved = status.model && !listed.some((entry) => entry.id === status.model?.id) ? status.model : null;
  const perThousand =
    chosen?.usd_per_thousand_names ??
    (model === status.model?.id && status.model.prompt_usd_per_million !== null
      ? status.model.prompt_usd_per_million * 0.5
      : null);

  const check = (): Problems => {
    const found: Problems = {};
    const trimmed = key.trim();
    if (typingKey && mode === "first" && !trimmed) found.key = "Paste an OpenRouter key. It starts with sk-or-.";
    else if (trimmed && !KEY_SHAPE.test(trimmed)) found.key = "That does not look like an OpenRouter key.";
    if (!model) found.model = "Pick a model.";
    return found;
  };

  const focusFirst = (found: Problems, later = false) => {
    const target = found.key ? keyRef.current : found.model ? modelRef.current : null;
    // After a dialog, wait for it to hand focus back before taking it.
    if (later) window.setTimeout(() => target?.focus(), 300);
    else target?.focus();
  };

  const patch = (): AiPatch => {
    const trimmed = key.trim();
    const withKey = typingKey && trimmed ? { key: trimmed } : {};
    if (mode === "first") return { enabled: true, model, daily_limit_usd: limit, ...withKey };
    return {
      ...(model !== status.model?.id ? { model } : {}),
      ...(limit !== status.daily_limit_usd ? { daily_limit_usd: limit } : {}),
      ...withKey,
    };
  };

  const save = async (body: AiPatch, afterDialog: boolean) => {
    setSaving(true);
    setProblems({});
    try {
      const next = await api.updateAi(body);
      if (mode === "first") {
        notify.success("AI review is on", "New names are usually judged within a minute of a website first loading them.");
      } else {
        notify.success("AI review set-up saved");
      }
      onSaved(next);
      void reload();
    } catch (cause) {
      const message = errorMessage(cause);
      const field = fieldFor(message);
      // An environment key has no field here to put its sentence under.
      const found = { [field === "key" && source === "environment" ? "form" : field]: message };
      setProblems(found);
      focusFirst(found, afterDialog);
    } finally {
      // Whatever the answer: a refused key is not kept around to be sent again.
      setKey("");
      setSaving(false);
    }
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (saving) return;
    const found = check();
    setProblems(found);
    if (Object.keys(found).length > 0) return focusFirst(found);
    if (mode === "first") return setConfirming(true);
    const body = patch();
    if (Object.keys(body).length === 0) return onCancel();
    void save(body, false);
  };

  const test = async () => {
    if (testing) return;
    const found = check();
    delete found.key;
    if (key.trim() && !KEY_SHAPE.test(key.trim())) found.key = "That does not look like an OpenRouter key.";
    setProblems(found);
    if (Object.keys(found).length > 0) return focusFirst(found);
    setTesting(true);
    setOutcome(null);
    try {
      const staged = typingKey && key.trim() ? { model, key: key.trim() } : { model };
      const result = await api.testAi(staged);
      setOutcome({ ok: result.ok, sentence: result.sentence });
    } catch (cause) {
      setOutcome({ ok: false, sentence: errorMessage(cause) });
    } finally {
      setTesting(false);
      onTested();
      // The picker marks the models that passed or failed a Test.
      setAttempt((count) => count + 1);
    }
  };

  const keyLine = source === "saved" ? savedKeyLine(status.key) : null;
  const modelHint = [
    "Decision models answer with a choice and how sure they are. Cogwheel's thresholds were set from Jev 1.13's published accuracy; other models may be more or less sure of themselves.",
    greyed
      ? "Greyed-out models are run only by providers that may keep what they are sent. COGWHEEL_AI__ZERO_RETENTION=false allows them."
      : null,
  ]
    .filter(Boolean)
    .join(" ");
  const limitHint = `Reviews stop for the rest of the day (until ${resetTime()}) once this is spent; your lists keep working.${
    perThousand ? ` At this model's price that is about ${formatEstimate((limit / perThousand) * 1000)} names a day.` : ""
  }`;

  return (
    <form aria-labelledby={headingId} className="max-w-xl space-y-6" noValidate onSubmit={submit}>
      <h3 className="font-medium text-foreground text-sm" id={headingId}>
        {mode === "first" ? "Set up" : "Change set-up"}
      </h3>

      {source === "environment" ? (
        <div className="flex flex-col gap-2">
          <GroupLabel id={`${headingId}-key`}>OpenRouter key</GroupLabel>
          <p className="text-foreground text-sm">
            Key · Set by <span className="font-mono">COGWHEEL_AI__OPENROUTER_API_KEY</span>
          </p>
        </div>
      ) : keyLine && !replacing ? (
        <div className="flex flex-col gap-2">
          <GroupLabel id={`${headingId}-key`}>OpenRouter key</GroupLabel>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <p className="flex min-w-0 items-center gap-2 text-foreground text-sm">
              {keyLine.warn ? <Status size="sm" variant="warning" /> : null}
              {keyLine.text}
            </p>
            <span className="flex gap-2">
              <Button onClick={() => setReplacing(true)} variant="outline">
                Replace
              </Button>
              <RemoveKey onRemoved={onStatus} />
            </span>
          </div>
          {problems.key ? <p className="text-destructive-foreground text-sm">{problems.key}</p> : null}
        </div>
      ) : (
        <FormField
          error={problems.key}
          hint="Make a key just for Cogwheel at openrouter.ai and give it a credit limit: that limit holds even if something here goes wrong. Kept on this appliance and never shown again."
          label="OpenRouter key"
          required={mode === "first"}
        >
          <Input
            autoCapitalize="none"
            autoComplete="off"
            autoCorrect="off"
            onChange={(event) => {
              setKey(event.target.value);
              setProblems((current) => ({ ...current, key: undefined }));
            }}
            placeholder={replacing ? "The new key" : "sk-or-…"}
            ref={keyRef}
            spellCheck={false}
            type="password"
            value={key}
          />
        </FormField>
      )}
      {replacing ? (
        <Button
          className="-mt-3"
          onClick={() => {
            setReplacing(false);
            setKey("");
          }}
          size="sm"
          variant="ghost"
        >
          Keep the saved key
        </Button>
      ) : null}

      <div className="space-y-2">
        <FormField
          error={problems.model}
          hint={models.list || models.error ? modelHint : "Loading models from OpenRouter…"}
          label="Model"
          required
        >
          <NativeSelect
            className="w-full"
            onChange={(event) => {
              setModel(event.target.value);
              setProblems((current) => ({ ...current, model: undefined }));
              setOutcome(null);
            }}
            ref={modelRef}
            value={model}
          >
            <NativeSelectOption value="">{models.list ? "Choose a model…" : "Loading models…"}</NativeSelectOption>
            {saved ? (
              <NativeSelectOption value={saved.id}>{shortModelName(saved.name ?? saved.id)}</NativeSelectOption>
            ) : null}
            {listed.map((entry) => {
              const name = shortModelName(entry.name);
              const off = required && entry.zero_retention === false;
              const price =
                entry.usd_per_thousand_names === null
                  ? "price not listed"
                  : `about ${formatCents(entry.usd_per_thousand_names)} per 1,000 names`;
              const tested =
                entry.tested === "passed" ? " · passed a test" : entry.tested === "failed" ? " · failed a test" : "";
              return (
                <NativeSelectOption disabled={off} key={entry.id} value={entry.id}>
                  {off ? `${name} — no zero-retention provider` : `${name} — ${price}${tested}`}
                </NativeSelectOption>
              );
            })}
          </NativeSelect>
        </FormField>
        {models.error ? (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <p className="text-muted-foreground text-sm">Could not load models from OpenRouter. {models.error}</p>
            <Button onClick={() => setAttempt((count) => count + 1)} size="sm" variant="outline">
              <RotateCwIcon aria-hidden />
              Try again
            </Button>
          </div>
        ) : null}
      </div>

      <SelectField
        error={problems.limit}
        hint={limitHint}
        label="Daily spending limit"
        onChange={(value) => setLimit(DAILY_LIMITS.find((entry) => String(entry) === value) ?? 0.1)}
        options={DAILY_LIMITS.map((value) => ({ value: String(value), label: `${formatCents(value)} a day` }))}
        value={String(limit)}
      />

      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <Button disabled={saving} isLoading={testing} onClick={() => void test()} variant="outline">
            Test
          </Button>
          <Button isLoading={saving} type="submit">
            {mode === "first" ? "Turn on AI review…" : "Save"}
          </Button>
          <Button disabled={saving} onClick={onCancel} variant="ghost">
            Cancel
          </Button>
        </div>
        <TestLine outcome={problems.form ? { ok: false, sentence: problems.form } : outcome} />
      </div>

      <TurnOnDialog
        limitUsd={limit}
        onConfirm={() => save(patch(), true)}
        onOpenChange={setConfirming}
        open={confirming}
      />
    </form>
  );
}
