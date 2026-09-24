import React from "react";
import { api, type StreamQueryEvent } from "@/lib/api";

export type StreamStatus = "off" | "connecting" | "open" | "reconnecting";

const RECONNECT_STEPS_MS = [1_000, 2_000, 5_000, 10_000, 30_000];

/**
 * How long frames are gathered before the screen hears about them. A
 * household resolver answers several queries a second and each one used to be
 * its own React commit of the whole log: at 10 queries a second that was ~9
 * commits a second of ~1,500 component renders each. A quarter of a second is
 * below what reads as lag on a scrolling log and turns those into four
 * commits carrying two or three rows apiece.
 *
 * A timer rather than `requestAnimationFrame`: frames arrive further apart
 * than one animation frame, so rAF would batch nothing, and rAF stops in a
 * background tab while the socket keeps delivering.
 */
const FLUSH_MS = 250;

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
 * Frames are handed on in batches, oldest first (see FLUSH_MS). Nothing else is
 * held here: the Activity screen has to merge them into the same list as the
 * query-log history, decide whether to show them now or hold them, and is the
 * only place that can deduplicate the two.
 */
export function useQueryStream(
  enabled: boolean,
  onFrames: (frames: StreamQueryEvent[]) => void,
): { status: StreamStatus; error: string | null } {
  const [status, setStatus] = React.useState<StreamStatus>("off");
  const [error, setError] = React.useState<string | null>(null);

  // Kept in a ref so a new handler identity does not drop the connection.
  const handler = React.useRef(onFrames);
  React.useEffect(() => {
    handler.current = onFrames;
  });

  React.useEffect(() => {
    if (!enabled) {
      setStatus("off");
      setError(null);
      return;
    }

    let source: EventSource | null = null;
    let retryTimer: number | undefined;
    let flushTimer: number | undefined;
    let queue: StreamQueryEvent[] = [];
    let attempt = 0;
    let connected = false;
    let disposed = false;

    setStatus("connecting");

    const flush = () => {
      flushTimer = undefined;
      if (disposed || queue.length === 0) return;
      const batch = queue;
      queue = [];
      handler.current(batch);
    };

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
        if (!frame) return;
        queue.push(frame);
        if (flushTimer === undefined) flushTimer = window.setTimeout(flush, FLUSH_MS);
      });

      source.addEventListener("error", () => {
        source?.close();
        source = null;
        if (disposed) return;

        // What is known is that it has not connected, not why: it said "not
        // available on this appliance" when the appliance was simply not
        // answering, which is the stale banner's news, not a missing feature.
        if (!connected) setError("The live stream has not connected. Cogwheel keeps trying.");
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
      window.clearTimeout(flushTimer);
      queue = [];
      source?.close();
    };
  }, [enabled]);

  return { status, error };
}
