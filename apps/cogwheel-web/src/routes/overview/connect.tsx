import React from "react";
import { CheckIcon, CopyIcon, ShieldOffIcon } from "lucide-react";
import { looksIpv6 } from "@/lib/derive";
import { notify } from "@/lib/toast";
import { IconButton } from "@/components/ui/icon-button";
import { SectionCard } from "@/components/app/section-card";
import { EmptyState } from "@/components/app/states";

/** Three hints cover every platform in the house; more is a manual, not a page. */
const PLATFORMS = [
  { name: "Android", steps: "Wi-Fi settings → modify network → IP settings Static → DNS 1." },
  { name: "iPhone, iPad and Mac", steps: "Wi-Fi → the info icon → Configure DNS → Manual." },
  { name: "Windows", steps: "Network & Internet → Hardware properties → DNS server assignment → Edit." },
];

/**
 * The exact addresses to type into a router, then where each platform keeps
 * the field. One card, no boxes inside it: the address rows and the platform
 * rows are separated by hairlines, as every other list on the page is. Four
 * bordered tiles inside a bordered card was a card of cards.
 */
export function ConnectCard({ targets, port }: { targets: string[]; port: number }) {
  return (
    <SectionCard
      description="Set this as the DNS server on a device, or hand it out from your router over DHCP."
      title="Connect your devices"
    >
      {targets.length === 0 ? (
        <EmptyState
          description="The appliance could not work out its own address. Set COGWHEEL_SERVER__ADVERTISED_DNS_TARGETS and restart."
          icon={ShieldOffIcon}
          title="No address to advertise"
        />
      ) : (
        <div className="flex flex-col gap-gutter">
          <Targets port={port} targets={targets} />
          <dl className="divide-y divide-border border-border border-t">
            {PLATFORMS.map((platform) => (
              // Side by side by the card's width, not the window's: at 1024px
              // with 200% text the 12rem label column took the whole card and
              // squeezed the steps to nothing.
              <div
                className="grid gap-1 py-3 last:pb-0 @md/card:grid-cols-[minmax(0,12rem)_minmax(0,1fr)] @md/card:gap-gutter"
                key={platform.name}
              >
                <dt className="font-medium text-foreground text-sm">{platform.name}</dt>
                <dd className="text-muted-foreground text-sm">{platform.steps}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </SectionCard>
  );
}

function Targets({ targets, port }: { targets: string[]; port: number }) {
  const [copied, setCopied] = React.useState<string | null>(null);
  const timer = React.useRef<number | undefined>(undefined);

  React.useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = async (target: string) => {
    try {
      await navigator.clipboard.writeText(target);
      setCopied(target);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(null), 2_000);
    } catch {
      notify.error("Could not copy", "Select the address and copy it by hand.");
    }
  };

  return (
    <>
      <ul className="flex flex-col gap-3">
        {targets.map((target) => (
          <li className="flex items-center gap-3" key={target}>
            <div className="min-w-0">
              <span className="block break-all font-medium font-mono text-foreground text-lg">{target}</span>
              <span className="block text-muted-foreground text-xs">
                {looksIpv6(target) ? "IPv6" : "IPv4"} · port {port}
              </span>
            </div>
            <IconButton label={copied === target ? `Copied ${target}` : `Copy ${target}`} onClick={() => void copy(target)}>
              {copied === target ? <CheckIcon aria-hidden /> : <CopyIcon aria-hidden />}
            </IconButton>
          </li>
        ))}
      </ul>
      <span aria-live="polite" className="sr-only">
        {copied ? `Copied ${copied}` : ""}
      </span>
    </>
  );
}
