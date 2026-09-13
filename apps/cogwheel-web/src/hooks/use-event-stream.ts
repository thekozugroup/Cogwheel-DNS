import React from "react";
import { eventsStreamUrl, type StreamQueryEvent } from "@/lib/api";
import { ACTIVITY_BUFFER_LIMIT } from "@/lib/constants";

export type StreamStatus = "connecting" | "open" | "reconnecting" | "paused";

export type ActivityRow = { id: string } & StreamQueryEvent;

export type StreamState = {
  rows: ActivityRow[];
  status: StreamStatus;
  /** Rows that arrived while paused and will be merged in on resume. */
  pendingCount: number;
  /** Populated when the stream has never connected, so the screen can explain why. */
  error: string | null;
};

const RECONNECT_STEPS_MS = [1_000, 2_000, 5_000, 10_000, 30_000];

function parse<T>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T;
  } catch {
    // A malformed frame must not tear down a working stream.
    return null;
  }
}

let sequence = 0;
const nextId = () => `row-${(sequence += 1)}`;

/**
 * Live query stream over SSE with pause/resume and capped buffering.
 *
 * `EventSource` reconnects on its own but with no visible state and no backoff
 * ceiling we control, so the connection is managed explicitly: an error closes
 * it and schedules a retry with growing delay, and the UI is told which of the
 * three states it is in at all times.
 */
export function useEventStream(paused: boolean): StreamState & { clear: () => void } {
  const [rows, setRows] = React.useState<ActivityRow[]>([]);
  const [status, setStatus] = React.useState<StreamStatus>("connecting");
  const [error, setError] = React.useState<string | null>(null);
  const [pendingCount, setPendingCount] = React.useState(0);

  const pausedRef = React.useRef(paused);
  const pendingRef = React.useRef<ActivityRow[]>([]);
  const everConnected = React.useRef(false);

  const append = React.useCallback((row: ActivityRow) => {
    if (pausedRef.current) {
      pendingRef.current = [row, ...pendingRef.current].slice(0, ACTIVITY_BUFFER_LIMIT);
      setPendingCount(pendingRef.current.length);
      return;
    }
    setRows((current) => [row, ...current].slice(0, ACTIVITY_BUFFER_LIMIT));
  }, []);

  React.useEffect(() => {
    pausedRef.current = paused;
    if (paused) {
      setStatus("paused");
      return;
    }
    // Flush whatever arrived while the operator was reading a frozen list.
    if (pendingRef.current.length > 0) {
      const flushed = pendingRef.current;
      pendingRef.current = [];
      setPendingCount(0);
      setRows((current) => [...flushed, ...current].slice(0, ACTIVITY_BUFFER_LIMIT));
    }
    setStatus(everConnected.current ? "open" : "connecting");
  }, [paused]);

  React.useEffect(() => {
    let source: EventSource | null = null;
    let retryTimer: number | undefined;
    let attempt = 0;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      source = new EventSource(eventsStreamUrl);

      source.addEventListener("open", () => {
        attempt = 0;
        everConnected.current = true;
        setError(null);
        if (!pausedRef.current) setStatus("open");
      });

      source.addEventListener("query", (event) => {
        const payload = parse<StreamQueryEvent>((event as MessageEvent<string>).data);
        if (payload) append({ id: nextId(), ...payload });
      });

      source.addEventListener("error", () => {
        source?.close();
        source = null;
        if (disposed) return;

        if (!everConnected.current) {
          setError("The live stream is not available on this node.");
        }
        setStatus("reconnecting");

        const delay = RECONNECT_STEPS_MS[Math.min(attempt, RECONNECT_STEPS_MS.length - 1)];
        attempt += 1;
        retryTimer = window.setTimeout(connect, delay);
      });
    };

    connect();

    return () => {
      disposed = true;
      window.clearTimeout(retryTimer);
      source?.close();
    };
  }, [append]);

  const clear = React.useCallback(() => {
    pendingRef.current = [];
    setPendingCount(0);
    setRows([]);
  }, []);

  return { rows, status, pendingCount, error, clear };
}
