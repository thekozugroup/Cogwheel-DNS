import { useMemo } from "react";
import { Activity, ShieldOff } from "lucide-react";
import { useCogwheel } from "@/contexts/cogwheel-context";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

function EmptyRow({
  colSpan,
  icon: Icon,
  children,
}: {
  colSpan: number;
  icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  children: React.ReactNode;
}) {
  return (
    <TableRow>
      <TableCell colSpan={colSpan} className="h-32 text-center">
        <div className="flex flex-col items-center gap-2 text-muted-foreground">
          {Icon && <Icon className="h-8 w-8 text-muted-foreground/30" />}
          <p className="text-sm">{children}</p>
        </div>
      </TableCell>
    </TableRow>
  );
}

export function OverviewTab() {
  const {
    dashboard,
    settings,
    resolverAccess,
    state,
    error,
    busyAction,
    handlePauseRuntime,
    handleResumeRuntime,
  } = useCogwheel();

  const enabledBlocklists = useMemo(
    () => settings.blocklists.filter((source) => source.enabled),
    [settings.blocklists],
  );

  const allowlistCount = useMemo(
    () =>
      settings.block_profiles.reduce(
        (total, profile) => total + profile.allowlists.length,
        0,
      ),
    [settings.block_profiles],
  );

  const protectionBadgeVariant = useMemo(() => {
    switch (dashboard.protection_status) {
      case "Active":
        return "default" as const;
      case "Paused":
        return "secondary" as const;
      default:
        return "outline" as const;
    }
  }, [dashboard.protection_status]);

  const primaryDnsTarget = resolverAccess.dns_targets[0] ?? "fractal.local";
  const androidDnsTarget =
    resolverAccess.dns_targets.find((target) =>
      /^\d{1,3}(\.\d{1,3}){3}$/.test(target),
    ) ?? primaryDnsTarget;
  const ipv6DnsTarget = resolverAccess.dns_targets.find(
    (target) => target.includes(":") && !target.includes("."),
  );

  const platformGuides = [
    {
      title: "Android",
      detail: ipv6DnsTarget
        ? "Use the Wi-Fi network DNS server setting with this LAN IPv4 and also add the IPv6 resolver shown below on dual-stack networks. Do not use Android Private DNS unless Cogwheel is serving DNS-over-TLS."
        : "Use the Wi-Fi network DNS server setting with this LAN IP. Do not use Android Private DNS unless Cogwheel is serving DNS-over-TLS.",
      target: androidDnsTarget,
    },
    {
      title: "iPhone / iPad",
      detail: "Wi-Fi -> tap the info icon -> Configure DNS -> Manual.",
      target: primaryDnsTarget,
    },
    {
      title: "Mac",
      detail:
        "System Settings -> Wi-Fi -> Details -> DNS, then add this resolver.",
      target: primaryDnsTarget,
    },
    {
      title: "Windows",
      detail:
        "Network & Internet -> Hardware properties -> DNS server assignment -> Edit.",
      target: primaryDnsTarget,
    },
  ];

  return (
    <div className="p-4 md:p-6 space-y-4">
      {/* ---------- Error Banner ---------- */}
      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* ---------- Section Cards ---------- */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {/* Protection Status */}
        <Card className={`animate-fade-up stagger-1 ${dashboard.protection_status === "Active" ? "ring-2 ring-primary/20" : dashboard.protection_status === "Paused" ? "" : "ring-2 ring-destructive/20"}`}>
          <CardHeader>
            <CardDescription>Protection Status</CardDescription>
            <CardTitle className="text-2xl font-semibold tabular-nums">
              {dashboard.protection_status}
            </CardTitle>
            <CardAction>
              <Badge variant={protectionBadgeVariant}>
                {dashboard.protection_status}
              </Badge>
            </CardAction>
          </CardHeader>
          <CardFooter className="flex-col items-start gap-1 text-sm">
            <div className="flex gap-2">
              {dashboard.protection_status === "Paused" ? (
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => void handleResumeRuntime()}
                  disabled={busyAction === "resume-runtime"}
                >
                  Resume protection
                </Button>
              ) : (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => void handlePauseRuntime(10)}
                  disabled={busyAction === "pause-runtime"}
                >
                  Pause 10 min
                </Button>
              )}
            </div>
            <div className="text-muted-foreground">
              {dashboard.active_ruleset
                ? `Ruleset ${dashboard.active_ruleset.hash.slice(0, 12)}`
                : "No active ruleset"}
            </div>
          </CardFooter>
        </Card>

        {/* Sources */}
        <Card className="animate-fade-up stagger-2">
          <CardHeader>
            <CardDescription>Sources</CardDescription>
            <CardTitle className="text-2xl font-semibold tabular-nums">
              {dashboard.enabled_source_count.toLocaleString()}
            </CardTitle>
            <CardAction>
              <Badge variant="secondary">enabled</Badge>
            </CardAction>
          </CardHeader>
          <CardFooter className="flex-col items-start gap-1 text-sm">
            <div className="line-clamp-1 flex gap-2 font-medium">
              {settings.blocklists.length} blocklist source{settings.blocklists.length === 1 ? "" : "s"}
            </div>
            <div className="text-muted-foreground">
              {allowlistCount} saved allowlist entr{allowlistCount === 1 ? "y" : "ies"}
            </div>
          </CardFooter>
        </Card>

        {/* Blocked Queries */}
        <Card className="animate-fade-up stagger-3">
          <CardHeader>
            <CardDescription>Blocked Queries</CardDescription>
            <CardTitle className="text-2xl font-semibold tabular-nums">
              {dashboard.runtime_health.snapshot.blocked_total.toLocaleString()}
            </CardTitle>
            <CardAction>
              <Badge variant="destructive">blocked</Badge>
            </CardAction>
          </CardHeader>
          <CardFooter className="flex-col items-start gap-1 text-sm">
            <div className="line-clamp-1 flex gap-2 font-medium">
              {dashboard.runtime_health.snapshot.queries_total.toLocaleString()} total queries
            </div>
            <div className="text-muted-foreground">
              Observed by this node
            </div>
          </CardFooter>
        </Card>

        {/* Devices */}
        <Card className="animate-fade-up stagger-4">
          <CardHeader>
            <CardDescription>Devices</CardDescription>
            <CardTitle className="text-2xl font-semibold tabular-nums">
              {dashboard.device_count.toLocaleString()}
            </CardTitle>
            <CardAction>
              <Badge variant="outline">visible</Badge>
            </CardAction>
          </CardHeader>
          <CardFooter className="flex-col items-start gap-1 text-sm">
            <div className="line-clamp-1 flex gap-2 font-medium">
              Unique devices
            </div>
            <div className="text-muted-foreground">
              Currently visible to the control plane
            </div>
          </CardFooter>
        </Card>
      </div>

      {/* ---------- Domain Lists ---------- */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* Top Queried Domains */}
        <Card className="animate-fade-up stagger-5">
          <CardHeader>
            <CardTitle>Top Queried Domains</CardTitle>
            <CardDescription>Recent destinations seen by the resolver over the last day</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Domain</TableHead>
                  <TableHead className="text-right">Queries</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dashboard.domain_insights.top_queried_domains.length === 0 ? (
                  <EmptyRow colSpan={2} icon={Activity}>
                    Query activity will appear here once devices begin sending traffic through Cogwheel.
                  </EmptyRow>
                ) : (
                  dashboard.domain_insights.top_queried_domains.map((entry) => (
                    <TableRow key={entry.domain}>
                      <TableCell className="font-medium">{entry.domain}</TableCell>
                      <TableCell className="text-right tabular-nums">{entry.count}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Top Blocked Domains */}
        <Card className="animate-fade-up stagger-5">
          <CardHeader>
            <CardTitle>Top Blocked Domains</CardTitle>
            <CardDescription>Where protection is actively stepping in right now</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Domain</TableHead>
                  <TableHead className="text-right">Blocked</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {dashboard.domain_insights.top_blocked_domains.length === 0 ? (
                  <EmptyRow colSpan={2} icon={ShieldOff}>
                    No blocked domains yet. When filtering engages, the busiest blocked destinations will appear here.
                  </EmptyRow>
                ) : (
                  dashboard.domain_insights.top_blocked_domains.map((entry) => (
                    <TableRow key={entry.domain}>
                      <TableCell className="font-medium">{entry.domain}</TableCell>
                      <TableCell className="text-right">
                        <Badge variant="destructive">{entry.count}</Badge>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* ---------- Resolver Access & Resolver Summary ---------- */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Resolver Access */}
        <Card className="animate-fade-up stagger-6">
          <CardHeader>
            <CardTitle>How to Connect Devices</CardTitle>
            <CardDescription>
              Use one of these DNS targets on phones, laptops, TVs, or routers that should use this Cogwheel instance
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Target</TableHead>
                  <TableHead className="text-right">Address</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {resolverAccess.dns_targets.length === 0 ? (
                  <EmptyRow colSpan={2}>
                    Resolver targets will appear here once the control plane reports reachable DNS addresses.
                  </EmptyRow>
                ) : (
                  resolverAccess.dns_targets.map((target) => (
                    <TableRow key={target}>
                      <TableCell className="font-medium">DNS server</TableCell>
                      <TableCell className="text-right font-mono font-semibold">{target}</TableCell>
                    </TableRow>
                  ))
                )}
                <TableRow>
                  <TableCell className="font-medium">Tailscale</TableCell>
                  <TableCell className="text-right font-mono text-muted-foreground">
                    {resolverAccess.tailscale_ip ?? "Not available on this node"}
                  </TableCell>
                </TableRow>
                {ipv6DnsTarget ? (
                  <TableRow>
                    <TableCell className="font-medium">IPv6 DNS</TableCell>
                    <TableCell className="text-right font-mono font-semibold break-all">
                      {ipv6DnsTarget}
                    </TableCell>
                  </TableRow>
                ) : null}
              </TableBody>
            </Table>

            {resolverAccess.notes.length > 0 ? (
              <p className="mt-4 text-sm text-muted-foreground">
                {resolverAccess.notes.join(" ")}
              </p>
            ) : null}

            {/* Platform guides */}
            <div className="mt-4">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Platform</TableHead>
                    <TableHead>Instructions</TableHead>
                    <TableHead className="text-right">DNS</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {platformGuides.map((platform) => (
                    <TableRow key={platform.title}>
                      <TableCell className="font-medium">{platform.title}</TableCell>
                      <TableCell className="text-muted-foreground max-w-[300px] whitespace-normal">
                        {platform.detail}
                      </TableCell>
                      <TableCell className="text-right font-mono font-semibold">
                        {platform.target}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Resolver Summary */}
        <Card className="animate-fade-up stagger-6">
          <CardHeader>
            <CardTitle>Resolver Summary</CardTitle>
            <CardDescription>
              Operational details from the running resolver instance
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Metric</TableHead>
                  <TableHead className="text-right">Value</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow>
                  <TableCell className="font-medium">Protection</TableCell>
                  <TableCell className="text-right">
                    <Badge variant={protectionBadgeVariant}>{dashboard.protection_status}</Badge>
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium">Active ruleset</TableCell>
                  <TableCell className="text-right font-mono">
                    {dashboard.active_ruleset?.hash.slice(0, 12) ?? "None"}
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium">Cache hits</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {dashboard.runtime_health.snapshot.cache_hits_total.toLocaleString()}
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium">Fallback served</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {dashboard.runtime_health.snapshot.fallback_served_total.toLocaleString()}
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium">Runtime notes</TableCell>
                  <TableCell className="text-right tabular-nums">
                    {dashboard.runtime_health.notes.length}
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* ---------- Security Events ---------- */}
      <Card className="animate-fade-up stagger-6">
        <CardHeader>
          <CardTitle>Recent Risky Events</CardTitle>
          <CardDescription>
            High-signal security events from the resolver
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Domain</TableHead>
                <TableHead>Device</TableHead>
                <TableHead>Client IP</TableHead>
                <TableHead className="text-right">Severity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {dashboard.recent_security_events.length === 0 ? (
                <EmptyRow colSpan={4}>
                  No risky DNS events recorded yet.
                </EmptyRow>
              ) : (
                dashboard.recent_security_events.slice(0, 4).map((event) => (
                  <TableRow key={event.id}>
                    <TableCell className="font-medium">{event.domain}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {event.device_name ?? "Unassigned device"}
                    </TableCell>
                    <TableCell className="font-mono text-muted-foreground">
                      {event.client_ip}
                    </TableCell>
                    <TableCell className="text-right">
                      <Badge variant={event.severity === "high" ? "destructive" : "secondary"}>
                        {event.severity}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* ---------- Footer Status ---------- */}
      {state === "loading" ? (
        <p className="text-sm text-muted-foreground">
          Loading control plane data...
        </p>
      ) : (
        <p className="text-sm text-muted-foreground">
          {enabledBlocklists.length} enabled blocklists and{" "}
          {settings.devices.length} named devices.
          {error ? " (offline)" : ""}
        </p>
      )}
    </div>
  );
}
