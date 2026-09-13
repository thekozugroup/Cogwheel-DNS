#!/usr/bin/env python3
"""Multiprocessing closed-loop DNS throughput, stdlib only.

dnsbench.py measures the *shape* of one query's latency; this measures what
happens under concurrent load -- the spec §12 "Throughput (4x25,000)" row --
by running several worker processes, each hammering the target with its own
UDP socket in a tight closed loop (send, wait for the reply, send the next),
and combining their per-query latencies and a wall-clock QPS figure.

Multiprocessing rather than threading: CPython's GIL would serialize the
send/recv calls of N threads onto one core, which measures Python's
scheduler more than it measures the DNS server. Separate processes, one per
core, keep the client side from being the bottleneck it would otherwise be
against a server that answers in low single-digit microseconds.

Given a `--pid` of the server under test, it also reports CPU cost per query
and how many cores were kept busy, read from /proc/<pid>/stat before and
after the run (Linux-only; the whole point is a Raspberry Pi in Phase 4).

Usage:
    python3 mpbench.py --host 127.0.0.1 --port 35353 --workers 4 --queries 25000 [--pid 1234]
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import socket
import sys
import time

import dnsproto
import stats

DEFAULT_TIMEOUT = 2.0


def _worker(host: str, port: int, worker_id: int, n_queries: int, qname: str, qtype: int, timeout: float, start_event, out_queue) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    latencies: list[float] = []
    timeouts = 0
    errors = 0
    # A distinct query id per iteration (rather than a fixed one) means a
    # stray reply to a *previous* iteration's query -- possible if the
    # server is slow enough that two are briefly in flight -- is detectable
    # instead of silently accepted as this iteration's answer.
    base_id = (worker_id * 100_003) & 0xFFFF
    packets = [dnsproto.build_query(qname, qtype, (base_id + i) & 0xFFFF) for i in range(min(n_queries, 65536))]

    start_event.wait()
    for i in range(n_queries):
        packet = packets[i % len(packets)]
        t0 = time.perf_counter()
        try:
            sock.send(packet)
            sock.recv(512)
        except socket.timeout:
            timeouts += 1
            continue
        except OSError:
            errors += 1
            continue
        latencies.append(time.perf_counter() - t0)
    sock.close()
    out_queue.put((worker_id, latencies, timeouts, errors))


def _read_proc_stat_ticks(pid: int) -> tuple[int, int]:
    """(utime, stime) in clock ticks for `pid`, from /proc/<pid>/stat.

    `comm` (field 2) is parenthesized and may itself contain spaces or
    parens, so the safe way to split the line is from the *last* ')',
    per `man 5 proc` -- everything after that is space-separated fields
    starting at field 3 (state).
    """
    with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
        content = handle.read()
    after_comm = content[content.rindex(")") + 2 :]
    fields = after_comm.split()
    utime = int(fields[11])  # field 14 overall
    stime = int(fields[12])  # field 15 overall
    return utime, stime


def _clock_ticks_per_sec() -> int:
    return os.sysconf("SC_CLK_TCK")


def run_throughput(host: str, port: int, workers: int, queries_per_worker: int, qname: str, qtype: int, timeout: float, pid: int | None) -> dict:
    ctx = mp.get_context("fork")
    start_event = ctx.Event()
    out_queue: mp.Queue = ctx.Queue()
    procs = [
        ctx.Process(
            target=_worker,
            args=(host, port, worker_id, queries_per_worker, qname, qtype, timeout, start_event, out_queue),
            daemon=True,
        )
        for worker_id in range(workers)
    ]
    for proc in procs:
        proc.start()

    cpu_before = _read_proc_stat_ticks(pid) if pid else None
    wall_start = time.perf_counter()
    start_event.set()

    results = [out_queue.get() for _ in procs]
    for proc in procs:
        proc.join(timeout=30)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)
    wall_elapsed = time.perf_counter() - wall_start
    cpu_after = _read_proc_stat_ticks(pid) if pid else None

    all_latencies: list[float] = []
    total_timeouts = 0
    total_errors = 0
    for _worker_id, latencies, timeouts, errors in results:
        all_latencies.extend(latencies)
        total_timeouts += timeouts
        total_errors += errors

    completed = len(all_latencies)
    result: dict = {
        "tool": "mpbench",
        "target": {"host": host, "port": port},
        "workers": workers,
        "queries_per_worker": queries_per_worker,
        "queries_requested": workers * queries_per_worker,
        "queries_completed": completed,
        "timeouts": total_timeouts,
        "errors": total_errors,
        "wall_seconds": wall_elapsed,
        "qps": completed / wall_elapsed if wall_elapsed > 0 else 0.0,
    }
    if all_latencies:
        result["latency_ms"] = stats.summarize(stats.scaled(all_latencies, 1000.0)).to_dict()

    if pid is not None and cpu_before is not None and cpu_after is not None:
        ticks_per_sec = _clock_ticks_per_sec()
        delta_ticks = (cpu_after[0] - cpu_before[0]) + (cpu_after[1] - cpu_before[1])
        delta_cpu_seconds = delta_ticks / ticks_per_sec
        result["server_cpu"] = {
            "pid": pid,
            "delta_cpu_seconds": delta_cpu_seconds,
            "cpu_us_per_query": (delta_cpu_seconds * 1_000_000 / completed) if completed else None,
            "cores_busy": (delta_cpu_seconds / wall_elapsed) if wall_elapsed > 0 else None,
        }
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--queries", type=int, default=25_000, help="queries per worker")
    parser.add_argument("--name", default="throughput.bench.test", help="name queried in a loop -- prime it first if it needs to be a cache hit")
    parser.add_argument("--qtype", choices=("a", "aaaa"), default="a")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--pid", type=int, default=None, help="server PID, for /proc/<pid>/stat CPU accounting (Linux only)")
    parser.add_argument("--prime", action="store_true", help="send one warm-up query before starting the timed run")
    parser.add_argument("--out", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    qtype = dnsproto.QTYPE_AAAA if args.qtype == "aaaa" else dnsproto.QTYPE_A

    try:
        probe = socket.socket(socket.AF_INET6 if ":" in args.host else socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(min(args.timeout, 1.0))
        probe.connect((args.host, args.port))
        probe.close()
    except OSError as exc:
        print(f"mpbench: cannot reach {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2

    if args.pid is not None:
        try:
            _read_proc_stat_ticks(args.pid)
        except OSError as exc:
            print(f"mpbench: --pid {args.pid} unreadable ({exc}); continuing without CPU accounting", file=sys.stderr)
            args.pid = None

    if args.prime:
        sock = socket.socket(socket.AF_INET6 if ":" in args.host else socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(args.timeout)
        sock.connect((args.host, args.port))
        try:
            sock.send(dnsproto.build_query(args.name, qtype, 1))
            sock.recv(512)
        except OSError as exc:
            print(f"mpbench: warm-up query failed: {exc}", file=sys.stderr)
        finally:
            sock.close()

    result = run_throughput(args.host, args.port, args.workers, args.queries, args.name, qtype, args.timeout, args.pid)

    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)

    # UDP has no connect-time handshake to fail, so "nothing is listening"
    # only shows up here, as every single query erroring or timing out --
    # that is worth a non-zero exit even though the JSON itself was written.
    if result["queries_requested"] > 0 and result["queries_completed"] == 0:
        print(f"mpbench: every query to {args.host}:{args.port} failed; is the server up?", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
