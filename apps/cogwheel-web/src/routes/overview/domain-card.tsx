import React from "react";
import { Link } from "react-router-dom";
import { ShieldOffIcon } from "lucide-react";
import { type DomainCount } from "@/lib/api";
import { formatCount } from "@/lib/format";
import { notify } from "@/lib/toast";
import { useSnapshot } from "@/data/context";
import { Button } from "@/components/ui/button";
import { SectionCard } from "@/components/app/section-card";
import { RowMenu } from "@/components/app/row-menu";
import { EmptyState, NoticeBanner } from "@/components/app/states";
import { DomainName } from "@/components/app/domain-name";
import { useRovingMenus } from "@/hooks/use-roving-menus";
import { explain, type Explanation } from "./explain";

type Why = { domain: string; answer: Explanation | null };

/**
 * Top blocked or Top queried: ten names, their counts, and a menu that can
 * allow, block, or answer "Why?" for each.
 */
export function DomainCard({
  title,
  rows,
  blocked,
  empty,
  onAllow,
  onBlock,
}: {
  title: string;
  rows: DomainCount[];
  /** True for Top blocked: its "Why?" also asks the log, and its Activity link filters to blocks. */
  blocked: boolean;
  empty: { title: string; description: string };
  onAllow: (domain: string) => void;
  onBlock: (domain: string) => void;
}) {
  const { devices } = useSnapshot("devices");
  // Held per card, not per page. A domain in both tables is one domain but two
  // rows, and one shared answer printed itself under both of them.
  const [why, setWhy] = React.useState<Why | null>(null);
  const inflight = React.useRef<AbortController | null>(null);
  // Ten row menus are one tab stop, as on Activity: Overview's two cards used
  // to put twenty stops between the chart and the address to copy.
  const listRef = React.useRef<HTMLUListElement>(null);
  const roving = useRovingMenus(listRef);
  const hintId = React.useId();

  React.useEffect(() => () => inflight.current?.abort(), []);

  const ask = async (domain: string) => {
    inflight.current?.abort();
    const controller = new AbortController();
    inflight.current = controller;
    setWhy({ domain, answer: null });
    try {
      const answer = await explain(domain, { devices, blocked, signal: controller.signal });
      if (!controller.signal.aborted) setWhy({ domain, answer });
    } catch {
      if (controller.signal.aborted) return;
      setWhy(null);
      notify.error("Could not check that domain", "The control plane did not answer.");
    }
  };

  const dismiss = () => {
    inflight.current?.abort();
    setWhy(null);
  };

  return (
    <SectionCard title={title}>
      {rows.length === 0 ? (
        <EmptyState description={empty.description} icon={ShieldOffIcon} title={empty.title} />
      ) : (
        <ul
          aria-describedby={hintId}
          className="divide-y divide-border"
          onBlur={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget as Node | null)) roving.leave();
          }}
          onFocus={(event) => roving.noteFocus(event.target)}
          onKeyDownCapture={roving.onKeyDownCapture}
          ref={listRef}
        >
          {rows.map((row) => (
            <li className="py-2" key={row.domain}>
              {/* The name wraps rather than truncating ("googlesyndicat…" at
                  320px), and where even nine characters will not fit beside the
                  count — 200% text on a phone — it takes the whole line and the
                  count and menu drop under it, right-aligned. */}
              <div className="flex flex-wrap items-center gap-x-3">
                <span className="min-w-0 flex-1 basis-[9ch] font-mono text-sm [overflow-wrap:anywhere]">
                  <DomainName name={row.domain} />
                </span>
                <span className="tabular ms-auto shrink-0 text-sm">{formatCount(row.count)}</span>
                <span className="inline-flex" data-row-actions>
                  <RowMenu
                    actions={[
                      { value: "allow", label: "Allow for everyone" },
                      { value: "block", label: "Block for everyone" },
                      { value: "why", label: "Why?" },
                    ]}
                    label={`Actions for ${row.domain}`}
                    onSelect={(value) => {
                      if (value === "allow") onAllow(row.domain);
                      else if (value === "block") onBlock(row.domain);
                      else void ask(row.domain);
                    }}
                  />
                </span>
              </div>
              {why?.domain === row.domain ? (
                <NoticeBanner
                  actions={
                    <>
                      <Button asChild size="sm" variant="outline">
                        <Link
                          to={`/activity?q=${encodeURIComponent(row.domain)}${blocked ? "&verdict=blocked" : ""}`}
                        >
                          Show in Activity
                        </Link>
                      </Button>
                      <Button onClick={dismiss} size="sm" variant="outline">
                        Dismiss
                      </Button>
                    </>
                  }
                  className="mt-2"
                  detail={why.answer?.detail}
                  title={why.answer?.title ?? `Checking ${row.domain}…`}
                  tone="neutral"
                />
              ) : null}
            </li>
          ))}
        </ul>
      )}
      <p className="sr-only" id={hintId}>
        Arrow keys move between rows.
      </p>
    </SectionCard>
  );
}
