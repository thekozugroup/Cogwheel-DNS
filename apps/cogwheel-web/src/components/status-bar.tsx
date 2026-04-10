import { useCogwheel } from "@/contexts/cogwheel-context";

export function StatusBar() {
  const { dashboard, state } = useCogwheel();

  return (
    <footer className="flex h-6 shrink-0 items-center border-t border-border bg-sidebar px-4 md:px-6 text-[10px] font-mono text-muted-foreground/60 select-none gap-4 overflow-hidden">
      {/* Connection dot */}
      <span className="flex items-center gap-1.5 shrink-0">
        <span
          className={`inline-block h-1.5 w-1.5 rounded-full ${
            state === "ready"
              ? "bg-emerald-400"
              : state === "error"
                ? "bg-destructive"
                : "bg-muted-foreground"
          }`}
        />
        {state === "ready" ? "Connected" : state === "error" ? "Offline" : "Loading"}
      </span>

      <span className="h-3 w-px bg-border shrink-0" />

      {/* Stats */}
      <span className="truncate tabular-nums">
        {dashboard.runtime_health.snapshot.queries_total.toLocaleString()} queries
        {" \u00B7 "}
        {dashboard.runtime_health.snapshot.blocked_total.toLocaleString()} blocked
      </span>

      <span className="flex-1" />

      {/* Protection status */}
      <span className="shrink-0 tabular-nums">{dashboard.protection_status}</span>
    </footer>
  );
}
