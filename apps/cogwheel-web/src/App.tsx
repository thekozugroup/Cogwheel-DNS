import { useEffect, useMemo, useState } from "react";
import { Activity, ListFilter, ShieldCheck, Sparkles } from "lucide-react";
import { api, type DashboardSummary, type SettingsSummary } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";

type LoadState = "idle" | "loading" | "ready" | "error";

const emptyDashboard: DashboardSummary = {
  protection_status: "Loading",
  active_ruleset: null,
  source_count: 0,
  enabled_source_count: 0,
  service_toggle_count: 0,
  runtime_health: {
    snapshot: {
      upstream_failures_total: 0,
      fallback_served_total: 0,
      cache_hits_total: 0,
      cname_uncloaks_total: 0,
      cname_blocks_total: 0,
    },
    degraded: false,
    notes: [],
  },
  latest_audit_events: [],
};

const emptySettings: SettingsSummary = {
  blocklists: [],
  blocklist_statuses: [],
  services: [],
  classifier: { mode: "Monitor", threshold: 0.92 },
  runtime_guard: { probe_domains: [], max_upstream_failures_delta: 0, max_fallback_served_delta: 0 },
};

export default function App() {
  const [dashboard, setDashboard] = useState<DashboardSummary>(emptyDashboard);
  const [settings, setSettings] = useState<SettingsSummary>(emptySettings);
  const [state, setState] = useState<LoadState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [blocklistName, setBlocklistName] = useState("");
  const [blocklistUrl, setBlocklistUrl] = useState("");
  const [blocklistProfile, setBlocklistProfile] = useState("custom");
  const [blocklistStrictness, setBlocklistStrictness] = useState<"strict" | "balanced" | "relaxed">("balanced");
  const [blocklistInterval, setBlocklistInterval] = useState("60");
  const [classifierThreshold, setClassifierThreshold] = useState("0.92");
  const [editingBlocklistId, setEditingBlocklistId] = useState<string | null>(null);
  const [serviceSearch, setServiceSearch] = useState("");

  async function load() {
    setState("loading");
    setError(null);
    try {
      const [dashboardData, settingsData] = await Promise.all([api.dashboard(), api.settings()]);
      setDashboard(dashboardData);
      setSettings(settingsData);
      setState("ready");
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Unknown error");
      setState("error");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    setClassifierThreshold(settings.classifier.threshold.toFixed(2));
  }, [settings.classifier.threshold]);

  const enabledBlocklists = useMemo(
    () => settings.blocklists.filter((source) => source.enabled),
    [settings.blocklists],
  );
  const filteredServices = useMemo(
    () => settings.services.filter((service) => {
      const query = serviceSearch.trim().toLowerCase();
      if (!query) return true;
      return `${service.manifest.display_name} ${service.manifest.category} ${service.manifest.risk_notes}`
        .toLowerCase()
        .includes(query);
    }),
    [serviceSearch, settings.services],
  );

  async function handleClassifierUpdate(mode: SettingsSummary["classifier"]["mode"]) {
    await api.updateClassifier(mode, Number.parseFloat(classifierThreshold) || settings.classifier.threshold);
    await load();
  }

  async function handleClassifierThresholdSave() {
    await api.updateClassifier(settings.classifier.mode, Number.parseFloat(classifierThreshold) || settings.classifier.threshold);
    await load();
  }

  async function handleServiceUpdate(serviceId: string, mode: "Inherit" | "Allow" | "Block") {
    await api.updateService(serviceId, mode);
    await load();
  }

  async function handleBlocklistCreate() {
    await api.upsertBlocklist({
      name: blocklistName,
      url: blocklistUrl,
      kind: "domains",
      enabled: true,
      refresh_interval_minutes: Number.parseInt(blocklistInterval, 10) || 60,
      profile: blocklistProfile,
      verification_strictness: blocklistStrictness,
    });
    setBlocklistName("");
    setBlocklistUrl("");
    setBlocklistProfile("custom");
    setBlocklistStrictness("balanced");
    setBlocklistInterval("60");
    await load();
  }

  async function handleBlocklistEdit(source: SettingsSummary["blocklists"][number]) {
    await api.upsertBlocklist({
      id: source.id,
      name: source.name,
      url: source.url,
      kind: source.kind,
      enabled: source.enabled,
      refresh_interval_minutes: source.refresh_interval_minutes,
      profile: source.profile,
      verification_strictness: source.verification_strictness,
    });
    setEditingBlocklistId(null);
    await load();
  }

  async function handleBlocklistToggle(id: string, enabled: boolean) {
    await api.setBlocklistEnabled(id, enabled);
    await load();
  }

  async function handleBlocklistDelete(id: string) {
    await api.deleteBlocklist(id);
    await load();
  }

  return (
    <main className="mx-auto flex min-h-screen max-w-7xl flex-col gap-6 px-6 py-8 md:px-10">
      <section className="grid gap-4 md:grid-cols-[1.4fr_0.9fr]">
        <Card className="overflow-hidden bg-gradient-to-br from-card via-white to-secondary/70">
          <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
            <div className="space-y-4">
              <Badge className="bg-primary/10 text-primary">Cogwheel Control Plane</Badge>
              <div className="space-y-2">
                <h1 className="font-display text-4xl font-semibold tracking-tight md:text-5xl">Quiet control, visible protection.</h1>
                <p className="max-w-2xl text-sm text-muted-foreground md:text-base">
                  A shadcn-based shell for the Cogwheel backend. The UI consumes the new dashboard and settings summaries so the frontend can stay simple while the Rust control plane handles the hard parts.
                </p>
              </div>
            </div>
            <div className="rounded-[24px] border border-border/60 bg-white/75 px-5 py-4 text-sm shadow-lg">
              <div className="font-medium">Status</div>
              <div className="mt-1 text-2xl font-semibold">{dashboard.protection_status}</div>
              <div className="mt-2 text-muted-foreground">{dashboard.runtime_health.degraded ? "Runtime guard is reporting attention-worthy notes." : "Runtime and control plane look healthy."}</div>
            </div>
          </div>
        </Card>

        <Card>
          <CardTitle>Quick health</CardTitle>
          <CardDescription>Backend-facing summary for the future onboarding and dashboard flows.</CardDescription>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <Metric label="Sources" value={String(dashboard.source_count)} icon={<ListFilter className="size-4" />} />
            <Metric label="Enabled" value={String(dashboard.enabled_source_count)} icon={<ShieldCheck className="size-4" />} />
            <Metric label="Service toggles" value={String(dashboard.service_toggle_count)} icon={<Sparkles className="size-4" />} />
            <Metric label="Cache hits" value={String(dashboard.runtime_health.snapshot.cache_hits_total)} icon={<Activity className="size-4" />} />
          </div>
        </Card>
      </section>

      {error ? <Card className="border-accent/30 bg-accent/10 text-accent-foreground">{error}</Card> : null}

      <section className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
        <Card>
          <CardTitle>Dashboard</CardTitle>
          <CardDescription>Current backend summary surfaced in a UI-first shape.</CardDescription>
          <div className="mt-6 space-y-4">
            <Row label="Active ruleset" value={dashboard.active_ruleset?.hash.slice(0, 12) ?? "None"} />
            <Row label="Fallback served" value={String(dashboard.runtime_health.snapshot.fallback_served_total)} />
            <Row label="CNAME uncloaks" value={String(dashboard.runtime_health.snapshot.cname_uncloaks_total)} />
            <Row label="Probe domains" value={settings.runtime_guard.probe_domains.join(", ") || "None"} />
          </div>
          <Separator className="my-6" />
          <div className="space-y-3">
            <div className="font-medium">Recent audit events</div>
            <div className="grid gap-3">
              {dashboard.latest_audit_events.map((event) => (
                <div key={event.id} className="rounded-2xl border border-border/70 bg-muted/60 p-3 text-sm">
                  <div className="font-medium">{event.event_type}</div>
                  <div className="text-muted-foreground">{new Date(event.created_at).toLocaleString()}</div>
                </div>
              ))}
            </div>
          </div>
        </Card>

        <Card>
          <CardTitle>Settings</CardTitle>
          <CardDescription>Blocklists, classifier, and service toggles mapped to backend endpoints.</CardDescription>

          <div className="mt-6 space-y-5">
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium">Classifier mode</div>
                  <div className="text-sm text-muted-foreground">Persisted directly in the backend control plane.</div>
                </div>
                <Badge>{settings.classifier.mode}</Badge>
              </div>
              <div className="flex flex-wrap gap-2">
                {(["Off", "Monitor", "Protect"] as const).map((mode) => (
                  <Button key={mode} variant={settings.classifier.mode === mode ? "primary" : "secondary"} size="sm" onClick={() => void handleClassifierUpdate(mode)}>
                    {mode}
                  </Button>
                ))}
              </div>
              <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                <Input value={classifierThreshold} onChange={(event) => setClassifierThreshold(event.target.value)} placeholder="0.92" />
                <Button variant="secondary" onClick={() => void handleClassifierThresholdSave()}>Save threshold</Button>
              </div>
            </section>

            <Separator />

            <section className="space-y-3">
              <div className="font-medium">Add blocklist</div>
              <div className="grid gap-3">
                <Input value={blocklistName} onChange={(event) => setBlocklistName(event.target.value)} placeholder="Human-readable name" />
                <Input value={blocklistUrl} onChange={(event) => setBlocklistUrl(event.target.value)} placeholder="Source URL or data: URL" />
                <div className="grid gap-3 sm:grid-cols-3">
                  <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={blocklistProfile} onChange={(event) => setBlocklistProfile(event.target.value)}>
                    <option value="custom">Custom</option>
                    <option value="essential">Essential</option>
                    <option value="balanced">Balanced</option>
                    <option value="aggressive">Aggressive</option>
                  </select>
                  <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={blocklistStrictness} onChange={(event) => setBlocklistStrictness(event.target.value as "strict" | "balanced" | "relaxed")}>
                    <option value="strict">Strict</option>
                    <option value="balanced">Balanced</option>
                    <option value="relaxed">Relaxed</option>
                  </select>
                  <Input value={blocklistInterval} onChange={(event) => setBlocklistInterval(event.target.value)} placeholder="Refresh minutes" />
                </div>
                <Button onClick={() => void handleBlocklistCreate()} disabled={!blocklistName || !blocklistUrl}>Add blocklist</Button>
              </div>
            </section>
          </div>
        </Card>
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardTitle>Blocklists</CardTitle>
          <CardDescription>Schedule, profile, verification strictness, and refresh status are already backend-driven.</CardDescription>
          <div className="mt-5 grid gap-3">
            {settings.blocklists.map((source) => {
              const status = settings.blocklist_statuses.find((entry) => entry.id === source.id);
              return (
                <div key={source.id} className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="font-medium">{source.name}</div>
                      <div className="text-sm text-muted-foreground">{source.url}</div>
                    </div>
                    <Badge className={source.enabled ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground"}>{source.enabled ? "Enabled" : "Disabled"}</Badge>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
                    <Badge>{source.profile}</Badge>
                    <Badge>{source.verification_strictness}</Badge>
                  <Badge>{source.refresh_interval_minutes}m</Badge>
                  <Badge>{status?.due_for_refresh ? "Due" : "Fresh"}</Badge>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button variant="ghost" size="sm" onClick={() => setEditingBlocklistId(editingBlocklistId === source.id ? null : source.id)}>
                    {editingBlocklistId === source.id ? "Close" : "Edit"}
                  </Button>
                  <Button variant="secondary" size="sm" onClick={() => void handleBlocklistToggle(source.id, !source.enabled)}>
                    {source.enabled ? "Disable" : "Enable"}
                  </Button>
                  {source.name !== "baseline" ? (
                    <Button variant="ghost" size="sm" onClick={() => void handleBlocklistDelete(source.id)}>
                      Delete
                    </Button>
                  ) : null}
                </div>
                {editingBlocklistId === source.id ? (
                  <div className="mt-4 grid gap-3 rounded-[20px] border border-border/70 bg-muted/40 p-4">
                    <Input value={source.name} readOnly />
                    <Input value={source.url} readOnly />
                    <div className="grid gap-3 sm:grid-cols-3 text-sm text-muted-foreground">
                      <label className="grid gap-1">
                        <span>Profile</span>
                        <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={source.profile} onChange={(event) => {
                          setSettings((current) => ({
                            ...current,
                            blocklists: current.blocklists.map((item) => item.id === source.id ? { ...item, profile: event.target.value } : item),
                          }));
                        }}>
                          <option value="essential">Essential</option>
                          <option value="balanced">Balanced</option>
                          <option value="aggressive">Aggressive</option>
                          <option value="custom">Custom</option>
                        </select>
                      </label>
                      <label className="grid gap-1">
                        <span>Strictness</span>
                        <select className="h-11 rounded-2xl border border-input bg-white/80 px-4 text-sm" value={source.verification_strictness} onChange={(event) => {
                          setSettings((current) => ({
                            ...current,
                            blocklists: current.blocklists.map((item) => item.id === source.id ? { ...item, verification_strictness: event.target.value } : item),
                          }));
                        }}>
                          <option value="strict">Strict</option>
                          <option value="balanced">Balanced</option>
                          <option value="relaxed">Relaxed</option>
                        </select>
                      </label>
                      <label className="grid gap-1">
                        <span>Refresh (minutes)</span>
                        <Input value={String(source.refresh_interval_minutes)} onChange={(event) => {
                          setSettings((current) => ({
                            ...current,
                            blocklists: current.blocklists.map((item) => item.id === source.id ? { ...item, refresh_interval_minutes: Number.parseInt(event.target.value, 10) || item.refresh_interval_minutes } : item),
                          }));
                        }} />
                      </label>
                    </div>
                    <Button size="sm" onClick={() => void handleBlocklistEdit(source)}>Save metadata</Button>
                  </div>
                ) : null}
              </div>
            );
          })}
          </div>
        </Card>

        <Card>
          <CardTitle>Services</CardTitle>
          <CardDescription>Optional common-service toggles powered by the layered service rules already built in Rust.</CardDescription>
          <div className="mt-5 space-y-4">
            <Input value={serviceSearch} onChange={(event) => setServiceSearch(event.target.value)} placeholder="Search services or categories" />
            <div className="grid gap-3">
            {filteredServices.map((service) => (
              <div key={service.manifest.service_id} className="rounded-[24px] border border-border/70 bg-white/80 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium">{service.manifest.display_name}</div>
                    <div className="text-sm text-muted-foreground">{service.manifest.risk_notes}</div>
                  </div>
                  <Badge>{service.mode}</Badge>
                </div>
                <div className="mt-3 flex gap-2">
                  {(["Inherit", "Allow", "Block"] as const).map((mode) => (
                    <Button key={mode} variant={service.mode === mode ? "primary" : "secondary"} size="sm" onClick={() => void handleServiceUpdate(service.manifest.service_id, mode)}>
                      {mode}
                    </Button>
                  ))}
                </div>
              </div>
            ))}
            </div>
          </div>
        </Card>
      </section>

      {state === "loading" ? <div className="text-sm text-muted-foreground">Loading control plane data...</div> : null}
      {state === "ready" ? <div className="text-sm text-muted-foreground">{enabledBlocklists.length} enabled blocklists, classifier threshold {settings.classifier.threshold.toFixed(2)}.</div> : null}
    </main>
  );
}

function Metric({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) {
  return (
    <div className="rounded-[24px] border border-border/70 bg-muted/60 p-4">
      <div className="flex items-center gap-2 text-sm text-muted-foreground">{icon}{label}</div>
      <div className="mt-2 font-display text-2xl font-semibold">{value}</div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
