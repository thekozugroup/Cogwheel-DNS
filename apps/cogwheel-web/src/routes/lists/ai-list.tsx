import React from "react";
import { Trash2Icon } from "lucide-react";
import { api, errorMessage, type AiOverview, type AiState, type AiStatus } from "@/lib/api";
import { AI_REQUESTS_PER_DAY, TONE_VARIANT, aiPausedBy, aiStateWord } from "@/lib/derive";
import { emptyOverview } from "@/lib/constants";
import { formatCount, formatUsd, pluralize } from "@/lib/format";
import { useCogwheelActions, useCogwheelStatus, useSnapshot } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { Switch } from "@/components/ui/switch";
import { ConfirmDialog } from "@/components/app/confirm-dialog";
import { RowMenu } from "@/components/app/row-menu";
import { SectionCard } from "@/components/app/section-card";
import { ErrorState, LoadingSkeleton, NoticeBanner } from "@/components/app/states";
import { AiSetupForm, RemoveKey, TestLine, TurnOnDialog, type TestOutcome } from "./ai-setup";
import { AiVerdicts } from "./ai-verdicts";

/** Every paragraph in the card is set to the page's one measure. */
const MEASURE = "max-w-[56ch]";

/** How often the card re-reads AI review's status while the page is in view. */
const STATUS_INTERVAL_MS = 30_000;

const clock = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });

/**
 * Hands the card the overview's four AI fields whenever one of them changes,
 * and not on the polls in between. Its own component so the five-second poll
 * re-renders this, not the card and its table.
 */
function OverviewWatcher({ onChange }: { onChange: (ai: AiOverview) => void }) {
  const overview = useSnapshot("overview");
  const known = overview !== emptyOverview;
  const { state, applying, applied_block, applied_allow } = overview.ai;
  React.useEffect(() => {
    if (known) onChange({ state, applying, applied_block, applied_allow });
  }, [known, state, applying, applied_block, applied_allow, onChange]);
  return null;
}

/**
 * The card's status line: a dot and words, from the polled state and the
 * counts in GET /ai. A stopped state names what stopped it and offers the fix.
 */
function StatusLine({ status, state, onChange }: { status: AiStatus; state: AiState; onChange: () => void }) {
  const { today, verdicts } = status;
  const kept = verdicts.block + verdicts.allow;
  const judged = today.requests > 0 || kept + verdicts.ignore > 0;
  const resumes = `resumes at ${clock.format(today.resets_at * 1000)}`;
  const words: Record<AiState, string> = {
    reviewing: judged
      ? `On · judged ${pluralize(today.requests, "name")} today · ${formatUsd(today.spent_usd)} of ${formatUsd(status.daily_limit_usd)}`
      : "On · nothing judged yet; open a website on any device",
    // Two limits pause review: with a cheap model the day's questions run out
    // first, under a spend that is plainly short of the limit just above.
    paused_budget:
      aiPausedBy(today.requests) === "requests"
        ? `Today's ${formatCount(AI_REQUESTS_PER_DAY)} questions are used · ${resumes}`
        : `Daily limit reached · ${resumes}`,
    no_key: "Waiting for a key",
    retrying: "OpenRouter is not answering · retrying; DNS is unaffected",
    key_refused: "Stopped · OpenRouter refused the key",
    out_of_credit: "Stopped · the OpenRouter account or this key is out of credit",
    model_refused: "Stopped · OpenRouter would not run this model",
    stopped: "Stopped · AI review hit an internal error; restart the appliance",
    off: kept > 0 ? `Off · ${pluralize(kept, "verdict")} kept, not applied` : "Off",
    unavailable: "Unavailable",
  };
  const { tone } = aiStateWord(state);
  // Green only when something has been judged: "On" over an empty list is idle.
  const shown = state === "reviewing" && !judged ? "idle" : tone;
  const fixable = state === "key_refused" || state === "out_of_credit" || state === "model_refused";
  // The sentence the server keeps says why, where the line alone cannot.
  const detail =
    status.last_error && (state === "model_refused" || state === "retrying" || state === "no_key")
      ? status.last_error
      : null;
  return (
    <span className="block">
      {/* The dot runs inline with the words, so on a phone it wraps with
          them instead of standing alone on a line above them. */}
      <span className="text-foreground">
        <Status className="me-2 inline-block align-middle ring-0" size="sm" variant={TONE_VARIANT[shown]} />
        {words[state]}
      </span>
      {fixable ? (
        <Button className="ms-1 h-auto px-1 align-baseline" onClick={onChange} size="sm" variant="link">
          Change set-up
        </Button>
      ) : null}
      {detail ? <span className={`mt-1 block ${MEASURE}`}>{detail}</span> : null}
    </span>
  );
}

/**
 * The AI list, between the subscribed lists and the rules because that is
 * where it ranks. Its status and verdicts are read as the card's own state,
 * never into the snapshot; the polled overview only tells it when to read.
 */
export function AiListCard() {
  const { busy } = useCogwheelStatus();
  const { mutate } = useCogwheelActions();
  const [status, setStatus] = React.useState<AiStatus | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [live, setLive] = React.useState<AiOverview | null>(null);
  const [attempt, setAttempt] = React.useState(0);
  const [form, setForm] = React.useState<"first" | "edit" | null>(null);
  const [override, setOverride] = React.useState<boolean | null>(null);
  const [turningOn, setTurningOn] = React.useState(false);
  // The count is fixed when the dialog opens, so its title does not change
  // under the spinner or go blank while it animates closed.
  const [clearing, setClearing] = React.useState(false);
  const [clearCount, setClearCount] = React.useState(0);
  const [testing, setTesting] = React.useState(false);
  const [outcome, setOutcome] = React.useState<TestOutcome>(null);
  // Whether the switch may turn review on without asking. Consent is known to
  // stand while review is on, or once the dialog has been answered on this
  // visit; making review unavailable withdraws it on the appliance, so seeing
  // that withdraws it here. The server keeps no record of it otherwise, so a
  // visit that finds review off asks once, through the same dialog.
  const consented = React.useRef(false);
  const actionsRef = React.useRef<HTMLSpanElement>(null);
  const setupRef = React.useRef<HTMLButtonElement>(null);
  const refocus = React.useRef(false);
  const switchLabel = React.useId();

  const refetch = React.useCallback(() => setAttempt((count) => count + 1), []);
  const liveKey = live ? `${live.state}|${live.applying}|${live.applied_block}|${live.applied_allow}` : "";

  React.useEffect(() => {
    const controller = new AbortController();
    api
      .ai({ signal: controller.signal })
      .then((next) => {
        setStatus(next);
        setError(null);
        if (!next.available) consented.current = false;
        else if (next.enabled) consented.current = true;
      })
      .catch((cause) => {
        if (cause instanceof DOMException && cause.name === "AbortError") return;
        setError(errorMessage(cause));
      });
    return () => controller.abort();
  }, [attempt, liveKey]);

  // Today's count and spend move without the overview's four fields moving.
  React.useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") refetch();
    }, STATUS_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [refetch]);

  // Focus goes back to what opened the form, once it has gone.
  React.useEffect(() => {
    if (form !== null || !refocus.current) return;
    refocus.current = false;
    const menu = actionsRef.current?.querySelector<HTMLElement>('[aria-haspopup="menu"]');
    (menu ?? setupRef.current)?.focus();
  }, [form]);

  const closeForm = () => {
    refocus.current = true;
    setForm(null);
  };

  const setEnabled = async (next: boolean) => {
    setOverride(next);
    const result = await mutate({
      key: "ai-enabled",
      action: () => api.updateAi({ enabled: next }),
      successTitle: next ? "AI review is on" : "AI review is off",
      successDetail: next
        ? "New names are usually judged within a minute of a website first loading them."
        : "Nothing more is sent to OpenRouter. The AI list is kept, and not applied while review is off.",
      failureTitle: next ? "Could not turn AI review on" : "Could not turn AI review off",
      undo: () => api.updateAi({ enabled: !next }),
    });
    // On failure the switch snaps back to what the server has, and the toast says why.
    setOverride(null);
    if (result) {
      setStatus(result);
      if (next) consented.current = true;
    }
  };

  const testNow = async () => {
    setTesting(true);
    setOutcome(null);
    try {
      const result = await api.testAi();
      setOutcome({ ok: result.ok, sentence: result.sentence });
    } catch (cause) {
      setOutcome({ ok: false, sentence: errorMessage(cause) });
    } finally {
      setTesting(false);
      refetch();
    }
  };

  const clearAll = async () => {
    const result = await mutate({
      key: "ai-clear",
      action: () => api.clearAiVerdicts(),
      successTitle: "AI list cleared",
      successDetail: (cleared) => `${pluralize(cleared.deleted, "verdict")} forgotten.`,
      failureTitle: "Could not clear the AI list",
      after: "light",
    });
    if (result) refetch();
  };

  const watcher = <OverviewWatcher onChange={setLive} />;

  if (!status) {
    return (
      <SectionCard title="AI list">
        {watcher}
        {error ? (
          <ErrorState detail={error} onRetry={refetch} title="Could not read AI review's state" />
        ) : (
          <LoadingSkeleton rows={3} variant="text" />
        )}
      </SectionCard>
    );
  }

  const keyRemove = status.key.source === "saved" ? <RemoveKey label="Remove key…" onRemoved={setStatus} /> : null;

  if (!status.available) {
    const history = status.unavailable_reason === "history_off";
    return (
      <SectionCard title="AI list">
        {watcher}
        <NoticeBanner
          actions={keyRemove}
          className="[&_p]:max-w-[56ch]"
          detail={
            history
              ? "COGWHEEL_RETENTION__HISTORY_DAYS is 0, which asks Cogwheel to keep no record of what is looked up. AI review sends names out and remembers which website loaded them. The AI list was emptied, and AI review stays off until you turn it on again."
              : "COGWHEEL_AI__AVAILABLE is false. Verdicts already stored are kept and not applied. If it is switched back on, AI review stays off here until you turn it on again."
          }
          title={
            history ? "Not available while the activity log is off" : "AI review is switched off on this appliance"
          }
          tone="neutral"
        />
      </SectionCard>
    );
  }

  const verdicts = status.verdicts;
  const total = verdicts.block + verdicts.allow + verdicts.ignore;
  // A saved key came through this form and its dialog; an environment key did
  // not, so on its own it does not count as having been set up.
  const setUp = status.enabled || status.key.source === "saved" || total > 0;
  const onSaved = (next: AiStatus) => {
    setStatus(next);
    if (form === "first") consented.current = true;
    closeForm();
  };
  const setupForm = (mode: "first" | "edit") => (
    <AiSetupForm
      mode={mode}
      onCancel={closeForm}
      onSaved={onSaved}
      onStatus={setStatus}
      onTested={refetch}
      status={status}
    />
  );

  if (!setUp) {
    return (
      <SectionCard title="AI list">
        {watcher}
        <div className="space-y-4">
          <p className={`${MEASURE} text-muted-foreground text-sm`}>
            When a device opens a website, Cogwheel can send the names that website loaded — the names only, never
            which device asked — to a decision model on OpenRouter, using your own key. For each name the model picks
            block, allow, or leave it to your lists. It answers after the page has loaded, never before: a first visit
            is filtered by your lists alone, and later visits use the answers.
          </p>
          <NoticeBanner
            className="[&_p]:max-w-[56ch]"
            detail="OpenRouter and the company that runs the model see each new name your household's websites load, and which website loaded it. Cogwheel asks OpenRouter only for providers that do not collect or keep it, but it cannot check that they comply. Your OpenRouter account pays for every answer."
            title="Domain names leave your network while this is on"
            tone="warn"
          />
          {form === "first" ? (
            <div className="border-border border-t pt-6">{setupForm("first")}</div>
          ) : (
            <Button onClick={() => setForm("first")} ref={setupRef} variant="outline">
              Set up AI review
            </Button>
          )}
        </div>
      </SectionCard>
    );
  }

  const state = live?.state ?? status.state;
  const notApplied = verdicts.block + verdicts.allow - verdicts.applied_block - verdicts.applied_allow;
  // The table reads its rows again whenever any of these move.
  const version = [
    verdicts.block,
    verdicts.allow,
    verdicts.ignore,
    verdicts.applied_block,
    verdicts.applied_allow,
    status.enabled,
  ].join("|");

  const askClear = () => {
    setClearCount(total);
    setClearing(true);
  };

  const actions = (
    <span className="flex items-center gap-3" ref={actionsRef}>
      <span className="flex items-center gap-2">
        {/* While "Turn on AI review?" is open the switch shows on: it follows the
            hand that moved it, and Cancel visibly puts it back. */}
        <Switch
          aria-labelledby={switchLabel}
          checked={turningOn || (override ?? status.enabled)}
          disabled={busy === "ai-enabled"}
          onCheckedChange={(details) => {
            if (details.checked && !consented.current) setTurningOn(true);
            else void setEnabled(details.checked);
          }}
        />
        <span className="font-medium text-foreground text-sm" id={switchLabel}>
          AI review
        </span>
      </span>
      <RowMenu
        actions={[
          { value: "setup", label: "Change set-up" },
          { value: "test", label: "Test now", disabled: testing || status.model === null },
          { value: "clear", label: "Forget every verdict…", destructive: true, disabled: total === 0 },
        ]}
        label="AI list actions"
        onSelect={(value) => {
          if (value === "setup") setForm("edit");
          else if (value === "test") void testNow();
          else askClear();
        }}
      />
    </span>
  );

  return (
    <SectionCard
      actions={actions}
      busy={testing}
      description={<StatusLine onChange={() => setForm("edit")} state={state} status={status} />}
      footer={
        <div className="flex w-full flex-wrap items-end justify-between gap-x-gutter gap-y-3">
          <p className={`${MEASURE} min-w-0 text-muted-foreground text-sm`}>
            Exact names only: a verdict on cdn.site.com says nothing about img.cdn.site.com, and an allow lifts a
            list's block on that name, not on a name it redirects to. Your own rules beat the AI list; it beats every
            subscribed list. A block or allow is judged again the first time a website loads it 30 days or more after
            its last judgement; a name left to your lists, once your activity log has forgotten it or after 30 days,
            whichever is sooner (90 days if two websites disagreed about it).
          </p>
          {total > 0 ? (
            <Button onClick={askClear} variant="destructive">
              <Trash2Icon aria-hidden />
              Clear AI list…
            </Button>
          ) : null}
        </div>
      }
      title="AI list"
    >
      {watcher}
      {/* Always mounted, so Test now's answer is announced when it lands: a
          live region inserted already holding its sentence is not read. It
          takes room only while it says something. */}
      <div className={testing || outcome ? "mb-6 flex flex-wrap items-start justify-between gap-3" : undefined}>
        <TestLine outcome={outcome} pending={testing ? "Asking the model a test question…" : undefined} />
        {outcome ? (
          <Button
            onClick={() => {
              setOutcome(null);
              // The button goes with the answer; focus goes back to the menu that asked.
              actionsRef.current?.querySelector<HTMLElement>('[aria-haspopup="menu"]')?.focus();
            }}
            size="sm"
            variant="outline"
          >
            Dismiss
          </Button>
        ) : null}
      </div>
      <div className="space-y-6">
        {form === "edit" ? <div className="border-border border-b pb-6">{setupForm("edit")}</div> : null}

        <p className="text-foreground text-sm">
          Blocking <span className="tabular">{formatCount(verdicts.applied_block)}</span> · allowing{" "}
          <span className="tabular">{formatCount(verdicts.applied_allow)}</span> over your lists ·{" "}
          <span className="tabular">{formatCount(verdicts.ignore)}</span> left to your lists
          {notApplied > 0 ? (
            <>
              {" "}
              · <span className="tabular">{formatCount(notApplied)}</span> not applied
            </>
          ) : null}
        </p>

        <AiVerdicts counts={verdicts} onChanged={refetch} state={status.state} version={version} />
      </div>

      <TurnOnDialog
        limitUsd={status.daily_limit_usd}
        onConfirm={() => setEnabled(true)}
        onOpenChange={setTurningOn}
        open={turningOn}
      />
      <ConfirmDialog
        confirmLabel="Forget verdicts"
        description="Your lists decide for these names again until each is judged anew, the next time a website loads it. Each new judgement is paid for again."
        onConfirm={clearAll}
        onOpenChange={setClearing}
        open={clearing}
        title={`Forget all ${formatCount(clearCount)} AI verdicts?`}
      />
    </SectionCard>
  );
}
