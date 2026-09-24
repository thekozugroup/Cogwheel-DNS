import React from "react";
import { Link } from "react-router-dom";
import { ChevronRightIcon, Trash2Icon } from "lucide-react";
import { api, type RuleAction } from "@/lib/api";
import { domainProblem, isRuleDomain, normalizeDomain } from "@/lib/derive";
import { emptyRules } from "@/lib/constants";
import { useCogwheelActions, useCogwheelStatus, useSnapshot } from "@/data/context";
import { Button } from "@/components/ui/button";
import { IconButton } from "@/components/ui/icon-button";
import { SectionCard } from "@/components/app/section-card";
import { StatusPill } from "@/components/app/status-indicator";
import { DomainName } from "@/components/app/domain-name";
import { DomainField, RowButtonSlot, RuleActionField } from "@/routes/rule-fields";

/**
 * Household rules, which this page edits, and device rules, which it only
 * shows. A device's own rules are the usual answer to "why does the iPad
 * behave differently", and they used to be visible only inside that device's
 * edit form on another page.
 */
export function RulesCard() {
  const rules = useSnapshot("rules");
  const { devices } = useSnapshot("devices");
  const { busy } = useCogwheelStatus();
  const { mutate } = useCogwheelActions();
  const [domain, setDomain] = React.useState("");
  const [action, setAction] = React.useState<RuleAction>("block");
  const [error, setError] = React.useState<string | undefined>();
  const [notice, setNotice] = React.useState<string | undefined>();
  const inputRef = React.useRef<HTMLInputElement>(null);
  const ids = { household: React.useId(), device: React.useId() };

  const household = rules.filter((rule) => rule.device_id === null);
  // "None yet" is a claim about what is stored; before the rules have loaded
  // once — an appliance that is not answering — nothing is said instead.
  const loaded = rules !== emptyRules;
  const byDevice = React.useMemo(() => {
    const groups = new Map<string, { id: string; name: string; rules: typeof rules }>();
    for (const rule of rules) {
      if (rule.device_id === null) continue;
      const name = devices.find((device) => device.id === rule.device_id)?.name ?? rule.device_name ?? "A device";
      const group = groups.get(rule.device_id) ?? { id: rule.device_id, name, rules: [] };
      group.rules.push(rule);
      groups.set(rule.device_id, group);
    }
    return [...groups.values()].sort((left, right) => left.name.localeCompare(right.name));
  }, [rules, devices]);

  const adding = busy === "household-rule-add";

  const add = async (event: React.FormEvent) => {
    event.preventDefault();
    if (adding) return;
    const normalized = normalizeDomain(domain);
    const problem = domainProblem(domain, isRuleDomain(normalized));
    if (problem) {
      setError(problem);
      inputRef.current?.focus();
      return;
    }
    const verb = (value: RuleAction) => (value === "allow" ? "allowed" : "blocked");
    const existing = household.find((rule) => rule.domain === normalized);
    setDomain(normalized);
    if (existing?.action === action) {
      setNotice(`${normalized} is already ${verb(action)} for everyone.`);
      return;
    }
    const result = await mutate({
      key: "household-rule-add",
      action: () => api.createRule({ domain: normalized, action }),
      // Saving a rule for a domain that has one replaces it. Say so, rather
      // than report a new rule and let the old one vanish from the list.
      successTitle: existing ? "Rule changed" : action === "allow" ? "Allowed for everyone" : "Blocked for everyone",
      successDetail: existing
        ? `${normalized} is now ${verb(action)} for everyone. It was ${verb(existing.action)}.`
        : normalized,
      failureTitle: "Could not save the rule",
      // A household rule applies to every device the moment it is saved, with
      // no confirmation, so the toast can take it back.
      undo: (created) =>
        existing
          ? api.createRule({ domain: normalized, action: existing.action })
          : api.deleteRule(created.id),
    });
    if (result) {
      setDomain("");
      inputRef.current?.focus();
    }
  };

  return (
    <SectionCard
      description="Your own decisions. They beat every list."
      footer={<p className="text-muted-foreground text-sm">Allow beats block. A domain covers its subdomains.</p>}
      title="Rules"
    >
      <div className="space-y-8">
        <section aria-labelledby={ids.household} className="space-y-4">
          <div>
            <h3 className="font-medium text-foreground text-sm" id={ids.household}>
              Household rules
            </h3>
            <p className="text-muted-foreground text-sm">For every device on the network.</p>
          </div>
          <form
            aria-labelledby={ids.household}
            className="flex flex-wrap items-start gap-x-3 gap-y-4"
            noValidate
            onSubmit={(event) => void add(event)}
          >
            <DomainField
              className="max-w-md flex-1 basis-64"
              error={error}
              hint={notice}
              inputRef={inputRef}
              onChange={(value) => {
                setDomain(value);
                setError(undefined);
                setNotice(undefined);
              }}
              value={domain}
            />
            <RuleActionField
              onChange={(value) => {
                setAction(value);
                setNotice(undefined);
              }}
              value={action}
            />
            <RowButtonSlot>
              <Button isLoading={adding} type="submit" variant="outline">
                Add rule
              </Button>
            </RowButtonSlot>
          </form>

          {!loaded ? null : household.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              None yet. Add one when a list blocks something you need, or to block a domain everywhere.
            </p>
          ) : (
            // As wide as the form above it, not the card: at 1440 the pill sat
            // 950px from the name it belongs to.
            <ul aria-labelledby={ids.household} className="max-w-2xl divide-y divide-border">
              {household.map((rule) => (
                <li className="flex items-center gap-3 py-1.5" key={rule.id}>
                  <span className="min-w-0 flex-1 font-mono text-sm [overflow-wrap:anywhere]">
                    <DomainName name={rule.domain} />
                  </span>
                  <StatusPill
                    label={rule.action === "allow" ? "Allow" : "Block"}
                    tone={rule.action === "allow" ? "good" : "bad"}
                    verdict
                  />
                  <IconButton
                    isLoading={busy === `household-rule-${rule.id}`}
                    label={`Remove ${rule.domain}`}
                    onClick={() =>
                      void mutate({
                        key: `household-rule-${rule.id}`,
                        action: () => api.deleteRule(rule.id),
                        successTitle: "Rule removed",
                        successDetail: `${rule.domain} is no longer ${rule.action === "allow" ? "allowed" : "blocked"} for everyone.`,
                        failureTitle: "Could not remove the rule",
                        undo: () => api.createRule({ domain: rule.domain, action: rule.action }),
                      })
                    }
                  >
                    <Trash2Icon aria-hidden />
                  </IconButton>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section aria-labelledby={ids.device} className="space-y-4">
          <div>
            <h3 className="font-medium text-foreground text-sm" id={ids.device}>
              Device rules
            </h3>
            <p className="text-muted-foreground text-sm">
              Set on one device, and checked before the household rules for it.
            </p>
          </div>
          {!loaded ? null : byDevice.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              None yet. Open a device on{" "}
              <Link className="rounded-sm text-foreground underline underline-offset-4" to="/devices">
                Devices
              </Link>{" "}
              to give it rules of its own.
            </p>
          ) : (
            <ul className="max-w-2xl divide-y divide-border">
              {byDevice.map((group) => (
                <li className="py-2" key={group.id}>
                  <Link
                    aria-label={`Edit ${group.name}`}
                    className="inline-flex min-h-8 items-center gap-1 rounded-sm font-medium text-foreground text-sm underline-offset-4 hover:underline pointer-coarse:min-h-11"
                    to={`/devices?device=${encodeURIComponent(group.id)}`}
                  >
                    {group.name}
                    <ChevronRightIcon aria-hidden className="size-3.5 text-muted-foreground" />
                  </Link>
                  <ul aria-label={`Rules for ${group.name}`}>
                    {group.rules.map((rule) => (
                      <li className="flex items-center gap-3 py-1" key={rule.id}>
                        <span className="min-w-0 flex-1 font-mono text-sm [overflow-wrap:anywhere]">
                          <DomainName name={rule.domain} />
                        </span>
                        <StatusPill
                          label={rule.action === "allow" ? "Allow" : "Block"}
                          tone={rule.action === "allow" ? "good" : "bad"}
                          verdict
                        />
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </SectionCard>
  );
}
