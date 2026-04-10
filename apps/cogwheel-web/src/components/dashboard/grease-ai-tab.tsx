import { useMemo } from "react";
import { useCogwheel } from "@/contexts/cogwheel-context";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

export function GreaseAiTab() {
  const { dashboard, settings, latencyBudget } = useCogwheel();

  const greaseAiSignals = useMemo(() => {
    const totalQueries = Math.max(
      dashboard.runtime_health.snapshot.queries_total,
      1,
    );
    const blockedRatio =
      dashboard.runtime_health.snapshot.blocked_total / totalQueries;
    const riskyEventRatio = Math.min(
      dashboard.recent_security_events.length / 6,
      1,
    );
    const latencyHeadroom = latencyBudget.within_budget ? 0.78 : 0.46;
    return [
      {
        label: "Classifier confidence",
        value: Math.min(0.35 + blockedRatio * 1.8, 0.96),
      },
      {
        label: "Risk memory",
        value: Math.min(0.22 + riskyEventRatio * 0.7, 0.92),
      },
      {
        label: "Latency headroom",
        value: latencyHeadroom,
      },
    ];
  }, [
    dashboard.recent_security_events.length,
    dashboard.runtime_health.snapshot.blocked_total,
    dashboard.runtime_health.snapshot.queries_total,
    latencyBudget.within_budget,
  ]);

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        {/* Left: Classifier workspace */}
        <Card className="animate-fade-up">
          <CardHeader>
            <CardTitle>Grease-AI Classifier</CardTitle>
            <CardDescription>
              Live learning signals and classifier workspace
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Learning pulse */}
            <div className="space-y-4">
              <h4 className="text-sm font-medium">Learning Pulse</h4>
              {greaseAiSignals.map((signal) => (
                <div key={signal.label} className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>{signal.label}</span>
                    <span className="text-muted-foreground">
                      {Math.round(signal.value * 100)}%
                    </span>
                  </div>
                  <Progress value={signal.value * 100} className="gold-shimmer" />
                </div>
              ))}
            </div>

            {/* Classifier animation visualization */}
            <div className="rounded-lg border border-border p-5">
              <div className="text-xs uppercase tracking-widest text-muted-foreground">
                Classifier animation
              </div>
              <div className="mt-4 grid gap-3">
                {[0, 1, 2, 3, 4].map((row) => (
                  <div key={row} className="grid grid-cols-8 gap-2">
                    {greaseAiSignals.map((signal, index) => (
                      <div
                        key={`${row}-${signal.label}-${index}`}
                        className="h-5 rounded-full bg-gradient-to-r from-primary/10 via-primary/40 to-secondary/30"
                        style={{
                          opacity: Math.max(
                            0.2,
                            signal.value - row * 0.12 + index * 0.04,
                          ),
                          animation: `pulse-bar ${2 + row * 0.4}s ease-in-out ${row * 0.3 + index * 0.1}s infinite alternate`,
                          "--bar-opacity": Math.max(
                            0.2,
                            signal.value - row * 0.12 + index * 0.04,
                          ),
                        } as React.CSSProperties}
                      />
                    ))}
                    <div className="h-5 rounded-full bg-background/80" />
                    <div className="h-5 rounded-full bg-background/60" />
                    <div className="h-5 rounded-full bg-background/80" />
                    <div className="h-5 rounded-full bg-background/60" />
                    <div className="h-5 rounded-full bg-background/80" />
                  </div>
                ))}
              </div>
              <p className="mt-4 text-sm text-muted-foreground">
                The bars brighten as more DNS activity arrives, blocked decisions
                climb, and the runtime stays inside latency budget.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Right: Stats cards grid */}
        <div className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <Card className="animate-fade-up [animation-delay:100ms]">
              <CardHeader className="py-3 gap-3">
                <CardDescription>Mode</CardDescription>
                <CardTitle className="text-2xl">
                  {settings.classifier.mode}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card className="animate-fade-up [animation-delay:150ms]">
              <CardHeader className="py-3 gap-3">
                <CardDescription>Threshold</CardDescription>
                <CardTitle className="text-2xl">
                  {settings.classifier.threshold.toFixed(2)}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card className="animate-fade-up [animation-delay:200ms]">
              <CardHeader className="py-3 gap-3">
                <CardDescription>Queries observed</CardDescription>
                <CardTitle className="text-2xl">
                  {dashboard.runtime_health.snapshot.queries_total.toLocaleString()}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card className="animate-fade-up [animation-delay:250ms]">
              <CardHeader className="py-3 gap-3">
                <CardDescription>Blocked queries</CardDescription>
                <CardTitle className="text-2xl">
                  {dashboard.runtime_health.snapshot.blocked_total.toLocaleString()}
                </CardTitle>
              </CardHeader>
            </Card>
          </div>

          {/* Latency budgets table */}
          <Card className="animate-fade-up [animation-delay:300ms]">
            <CardHeader>
              <CardTitle>Latency Budgets</CardTitle>
              <CardDescription>
                Live hot-path budget checks after the latest traffic observed by
                this resolver
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Path</TableHead>
                    <TableHead>Target p50</TableHead>
                    <TableHead>Observed</TableHead>
                    <TableHead>Samples</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {latencyBudget.checks.length === 0 ? (
                    <TableRow>
                      <TableCell
                        colSpan={5}
                        className="h-24 text-center text-muted-foreground"
                      >
                        No latency budget checks available yet.
                      </TableCell>
                    </TableRow>
                  ) : (
                    latencyBudget.checks.map((check) => (
                      <TableRow key={check.label}>
                        <TableCell className="font-medium">
                          {check.label}
                        </TableCell>
                        <TableCell>
                          {check.target_p50_ms.toFixed(1)} ms
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {check.observed_ms.toFixed(3)} ms
                        </TableCell>
                        <TableCell>{check.sample_count}</TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              check.status === "ok" ? "secondary" : "default"
                            }
                          >
                            {check.status}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
