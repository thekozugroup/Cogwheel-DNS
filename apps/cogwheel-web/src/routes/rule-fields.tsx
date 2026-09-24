import React from "react";
import type { RuleAction } from "@/lib/api";
import { pastedDomain } from "@/lib/derive";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { SegmentGroup, SegmentGroupItem, SegmentGroupItemText } from "@/components/ui/segment-group";
import { FormField, GroupLabel } from "@/components/app/form-field";

/**
 * The domain + action + button row that Lists (household rules, Check a
 * domain) and Devices (a device's own rules) each draw. One file so the three
 * cannot drift: the paste handling, the error wording and the way the button
 * lines up with the input are the same everywhere a domain is typed.
 */

/**
 * A required domain input. A pasted address becomes its host as it lands, so
 * `https://www.youtube.com/watch?v=…` reads `www.youtube.com` in the field —
 * the person sees exactly what will be checked or saved before they press
 * anything, and can shorten it to `youtube.com` if that is what they meant.
 */
export function DomainField({
  value,
  onChange,
  error,
  hint,
  label = "Domain",
  placeholder = "ads.example.com",
  className,
  inputRef,
  onKeyDown,
  searchTarget = false,
  required = true,
}: {
  value: string;
  onChange: (value: string) => void;
  error?: string;
  /** A note that is not an error, e.g. that the rule already exists. */
  hint?: string;
  label?: string;
  placeholder?: string;
  className?: string;
  inputRef?: React.Ref<HTMLInputElement>;
  onKeyDown?: (event: React.KeyboardEvent<HTMLInputElement>) => void;
  /** The field `/` focuses on this screen. */
  searchTarget?: boolean;
  /** False where the form can be sent without it: a device's rule input. */
  required?: boolean;
}) {
  return (
    <FormField className={className} error={error} hint={hint} label={label} required={required}>
      <Input
        autoCapitalize="none"
        autoComplete="off"
        autoCorrect="off"
        data-screen-search={searchTarget ? "true" : undefined}
        inputMode="url"
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={onKeyDown}
        onPaste={(event) => {
          const input = event.currentTarget;
          const start = input.selectionStart ?? input.value.length;
          const end = input.selectionEnd ?? input.value.length;
          const next = `${input.value.slice(0, start)}${event.clipboardData.getData("text")}${input.value.slice(end)}`;
          const host = pastedDomain(next);
          if (host === null) return;
          event.preventDefault();
          onChange(host);
        }}
        placeholder={placeholder}
        ref={inputRef}
        spellCheck={false}
        value={value}
      />
    </FormField>
  );
}

/**
 * Block or Allow, as two visible choices rather than a dropdown: there are
 * only two, and a select hid the one not chosen. It is also what tells a rule
 * form apart from Check a domain, whose second control is a device picker.
 */
export function RuleActionField({
  value,
  onChange,
  className,
}: {
  value: RuleAction;
  onChange: (value: RuleAction) => void;
  className?: string;
}) {
  const labelId = React.useId();
  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <GroupLabel id={labelId}>Action</GroupLabel>
      <SegmentGroup
        aria-labelledby={labelId}
        className="w-fit rounded-lg border p-0.5 pointer-fine:h-8"
        onValueChange={(details) => {
          if (details.value === "block" || details.value === "allow") onChange(details.value);
        }}
        value={value}
      >
        <SegmentGroupItem className="px-3" value="block">
          <SegmentGroupItemText className="text-sm">Block</SegmentGroupItemText>
        </SegmentGroupItem>
        <SegmentGroupItem className="px-3" value="allow">
          <SegmentGroupItemText className="text-sm">Allow</SegmentGroupItemText>
        </SegmentGroupItem>
      </SegmentGroup>
    </div>
  );
}

/**
 * Holds a row's button level with the inputs beside it. The rows align to the
 * top, not the bottom: bottom-aligned, the button dropped by a line whenever
 * the field above grew an error under it, and the whole row jumped as the
 * person typed. The spacer is the field label's own line box, so the button
 * sits on the inputs' line whatever the label's size.
 */
export function RowButtonSlot({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      <span aria-hidden className="select-none text-sm leading-snug">
        &nbsp;
      </span>
      {children}
    </div>
  );
}
