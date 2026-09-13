import { Link } from "react-router-dom";
import { formatCount } from "@/lib/format";
import { useCogwheel } from "@/data/context";
import { Button } from "@/components/ui/button";
import { PageHeader, PageSections, PageShell } from "@/components/app/page";
import { SectionCard } from "@/components/app/section-card";
import { StatTile } from "@/components/app/stat-tile";
import { LoadingSkeleton } from "@/components/app/states";

/**
 * Read-only. Everything the appliance persists is edited on its own page;
 * this screen is the summary of `GET /api/v1/settings` plus a pointer to where
 * the resolver itself is configured.
 */
export function SettingsScreen() {
  const { data, phase } = useCogwheel();
  const settings = data.settings;
  const enabledSources = settings.blocklists.filter((source) => source.enabled).length;

  const rows = [
    {
      label: "Blocklists",
      value: `${formatCount(settings.blocklists.length)} configured · ${formatCount(enabledSources)} enabled`,
      to: "/protection?tab=blocklists",
      action: "Manage blocklists",
    },
    {
      label: "Block profiles",
      value: `${formatCount(settings.block_profiles.length)} saved`,
      to: "/protection?tab=profiles",
      action: "Manage profiles",
    },
    {
      label: "Named devices",
      value: `${formatCount(settings.devices.length)} named · ${formatCount(
        settings.devices.filter((device) => device.policy_mode === "custom").length,
      )} with custom policy`,
      to: "/devices",
      action: "Manage devices",
    },
  ];

  return (
    <PageShell>
      <PageHeader
        description="What the appliance stores, and where the rest is configured."
        title="Settings"
      />

      <PageSections>
        {phase === "loading" ? (
          <LoadingSkeleton rows={3} variant="cards" />
        ) : (
          <div className="grid gap-6 sm:grid-cols-3">
            <StatTile
              delta={`${formatCount(enabledSources)} enabled`}
              label="Blocklists"
              value={formatCount(settings.blocklists.length)}
            />
            <StatTile label="Block profiles" value={formatCount(settings.block_profiles.length)} />
            <StatTile label="Named devices" value={formatCount(settings.devices.length)} />
          </div>
        )}

        <SectionCard
          description="Each of these is edited on its own page; this is the read-only summary."
          title="Stored on this appliance"
        >
          <dl className="divide-y divide-border">
            {rows.map((row) => (
              <div className="flex flex-wrap items-center justify-between gap-3 py-3" key={row.label}>
                <div className="min-w-0">
                  <dt className="font-medium text-foreground text-sm">{row.label}</dt>
                  <dd className="tabular text-muted-foreground text-sm">{row.value}</dd>
                </div>
                <Button asChild size="sm" variant="outline">
                  <Link to={row.to}>{row.action}</Link>
                </Button>
              </div>
            ))}
          </dl>
        </SectionCard>

        <SectionCard
          description="Upstream servers, bind addresses and retention are set by environment variables on the appliance. There is no endpoint to change them from here."
          title="Resolver configuration"
        >
          <p className="text-muted-foreground text-sm">
            Set the <span className="font-mono text-foreground">COGWHEEL_*</span> variables in{" "}
            <span className="font-mono text-foreground">/etc/cogwheel/cogwheel.env</span> (installer) or{" "}
            <span className="font-mono text-foreground">.env</span> (compose), then restart the service.
          </p>
        </SectionCard>
      </PageSections>
    </PageShell>
  );
}
