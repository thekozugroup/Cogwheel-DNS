import React from "react";
import { api, type StreamQueryEvent } from "@/lib/api";

export type StreamStatus = "off" | "connecting" | "open" | "reconnecting";

const RECONNECT_STEPS_MS = [1_000, 2_000, 5_000, 10_000, 30_000];

function parse(raw: string): StreamQueryEvent | null {
  try {
    return JSON.parse(raw) as StreamQueryEvent;
  } catch {
    // A malformed frame must not tear down a working stream.
    return null;
  }
}

/**
 * The live query feed. `EventSource` reconnects on its own, but with no visible
 * state and no backoff ceiling we control, so the connection is managed here:
 * an error closes it and schedules a retry with a growing delay, and the screen
 * is told which state it is in.
 *
 * Nothing is held here — frames go straight to `onFrame`, because the Activity
 * screen has to merge them into the same list as the query-log history and is
 * the only place that can deduplicate the two.
 */
export function useQueryStream(
  enabled: boolean,
  onFrame: (frame: StreamQueryEvent) => void,
): { status: StreamStatus; error: string | null } {
  const [status, setStatus] = React.useState<StreamStatus>("off");
  const [error, setError] = React.useState<string | null>(null);

  // Kept in a ref so a new handler identity does not drop the connection: the
  // Activity screen rebuilds it every time a filter changes.
  const handler = React.useRef(onFrame);
  React.useEffect(() => {
    handler.current = onFrame;
  });

  React.useEffect(() => {
    if (!enabled) {
      setStatus("off");
      setError(null);
      return;
    }

    let source: EventSource | null = null;
    let retryTimer: number | undefined;
    let attempt = 0;
    let connected = false;
    let disposed = false;

    setStatus("connecting");

    const connect = () => {
      if (disposed) return;
      source = new EventSource(api.eventsStreamUrl());

      source.addEventListener("open", () => {
        attempt = 0;
        connected = true;
        setError(null);
        setStatus("open");
      });

      source.addEventListener("query", (event) => {
        const frame = parse((event as MessageEvent<string>).data);
        if (frame) handler.current(frame);
      });

      source.addEventListener("error", () => {
        source?.close();
        source = null;
        if (disposed) return;

        if (!connected) setError("The live stream is not available on this appliance.");
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
  }, [enabled]);

  return { status, error };
}
