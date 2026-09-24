import React from "react";
import { api, type CheckResult } from "@/lib/api";
import { checkSentence, domainProblem, isRuleDomain, normalizeDomain } from "@/lib/derive";
import { notify } from "@/lib/toast";
import { useSnapshot } from "@/data/context";
import { Button } from "@/components/ui/button";
import { Status } from "@/components/ui/status";
import { SectionCard } from "@/components/app/section-card";
import { SelectField } from "@/components/app/select-field";
import { DomainField, RowButtonSlot } from "@/routes/rule-fields";

const HOUSEHOLD = "household";

export function CheckDomain() {
  const { devices } = useSnapshot("devices");
  const [domain, setDomain] = React.useState("");
  const [client, setClient] = React.useState(HOUSEHOLD);
  const [answer, setAnswer] = React.useState<CheckResult | null>(null);
  const [checking, setChecking] = React.useState(false);
  const [error, setError] = React.useState<string | undefined>();
  const inputRef = React.useRef<HTMLInputElement>(null);

  const run = async (event: React.FormEvent) => {
    event.preventDefault();
    if (checking) return;
    const normalized = normalizeDomain(domain);
    const problem = domainProblem(domain, isRuleDomain(normalized));
    if (problem) {
      setError(problem);
      inputRef.current?.focus();
      return;
    }
    setDomain(normalized);
    setChecking(true);
    try {
      setAnswer(await api.check(normalized, client === HOUSEHOLD ? undefined : client));
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
      <div className="space-y-6">
        <form
          aria-label="Check a domain"
          className="flex flex-wrap items-start gap-x-3 gap-y-4"
          noValidate
          onSubmit={(event) => void run(event)}
          role="search"
        >
          <DomainField
            className="max-w-md flex-1 basis-64"
            error={error}
            inputRef={inputRef}
            onChange={(value) => {
              setDomain(value);
              setError(undefined);
            }}
            placeholder="www.example.com"
            searchTarget
            value={domain}
          />
          {/* The household is a real option, not a placeholder: it is the
              answer an unnamed device gets, and it was the value selected. */}
          <SelectField
            className="min-w-0 max-w-full flex-1 basis-40 sm:w-56 sm:flex-none"
            label="As device"
            onChange={setClient}
            options={[
              { value: HOUSEHOLD, label: "The household" },
              ...devices.map((device) => ({ value: device.ip_address, label: device.name })),
            ]}
            value={client}
          />
          <RowButtonSlot>
            <Button isLoading={checking} type="submit" variant="outline">
              Check
            </Button>
          </RowButtonSlot>
        </form>

        <div aria-live="polite">
          {answer ? (
            <p className="flex items-start gap-2.5 text-foreground text-sm">
              <Status
                className="mt-1.5"
                size="sm"
                variant={answer.verdict === "block" ? "destructive" : "success"}
              />
              <span className="min-w-0 break-words">{checkSentence(answer)}</span>
            </p>
          ) : null}
        </div>
      </div>
    </SectionCard>
  );
}
