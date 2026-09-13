#!/usr/bin/env python3
"""The Phase 3 benchmark driver -- spec §11 gate B, §12's numbers.

Starts a loopback stub upstream (stub_upstream.py), a `python3 -m
http.server` for a real blocklist file, and the cogwheel-server release
binary wired to both via COGWHEEL_* environment variables; adds the list and
a household block rule through the API; waits for the list to actually
finish loading; then runs every measurement in spec §12 plus the extra
correctness checks §11 gate B calls for (AAAA-after-A, CNAME cloaking, a
hung upstream, `blocked_total` exactness, query-log write cost, database
growth, the prune row cap, and two endpoint-latency checks).

Three server lifecycles run in sequence, all on the same fixed host/port
pair (so nothing here works around a real port conflict, it just avoids
one): the main run under the default retention settings; a second run with
COGWHEEL_RETENTION__HISTORY_DAYS=0 to compare against the first's
server-internal cache-hit latency; and a third with a small
QUERY_LOG_MAX_ROWS and a 60 s PRUNE_INTERVAL_SECS to prove the prune
actually enforces the cap. Each writes to its own temporary database so
none of the three can contaminate another's numbers.

    python3 run.py --label phase3 --list-file /path/to/oisd-small.txt \\
        --http-port 38080 --dns-port 35353 --db /tmp/cogwheel-bench.db \\
        --out /tmp/bench-results

This talks to the Phase 3 API (spec §3, 22 routes). Against the tree as of
this writing -- which still serves the old 16-route API -- every API call
below fails fast with a clear message; see the README for what this script
has and has not been validated against.
"""

from __future__ import annotations

import argparse
import atexit
import concurrent.futures
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import dnsbench
import dnsproto
import mpbench
import stats

HERE = Path(__file__).resolve().parent

STUB_HOST = "127.0.0.1"
DEFAULT_STUB_PORT = 35399
DEFAULT_LIST_HTTP_PORT = 38899

RULES_LOADED_FLOOR = 55_000  # spec §11 gate B: "rules_loaded >= 55000"
READY_TIMEOUT_S = 30.0
RULES_LOADED_TIMEOUT_S = 60.0

HOUSEHOLD_BLOCK_DOMAIN = "ads.example.com"  # the fixture verify-install.sh / pi-acceptance.sh already use
CNAME_CLOAK_TARGET_SUFFIX = "blocked.test"  # what stub_upstream.py's cname.test CNAMEs point at
CACHE_HIT_NAME = "cache-hit.bench.test"


class BenchError(RuntimeError):
    """Something the harness cannot proceed past: missing binary, a 404, a failed assertion."""


class ChildFleet:
    """Every subprocess run.py starts, guaranteed dead by the time this exits.

    A benchmark script that leaks the stub resolver or the list HTTP server
    past its own process' lifetime leaves a fixed port bound, which makes
    the *next* run fail to bind it for a completely unrelated reason -- so
    every Popen goes through here, and cleanup fires on the happy path, on
    an uncaught exception (via `with`), and on SIGINT/SIGTERM/interpreter
    exit (via signal handlers and atexit), whichever happens first.
    """

    def __init__(self) -> None:
        self._procs: list[tuple[str, subprocess.Popen]] = []
        atexit.register(self.killall)
        self._prev_handlers = {
            sig: signal.signal(sig, self._on_signal) for sig in (signal.SIGTERM, signal.SIGINT)
        }

    def _on_signal(self, signum: int, _frame: object) -> None:
        self.killall()
        sys.exit(128 + signum)

    def spawn(self, name: str, args: list[str], **kwargs) -> subprocess.Popen:
        proc = subprocess.Popen(args, **kwargs)
        self._procs.append((name, proc))
        return proc

    def get(self, name: str) -> subprocess.Popen | None:
        for proc_name, proc in self._procs:
            if proc_name == name:
                return proc
        return None

    def stop(self, proc: subprocess.Popen, timeout: float = 10.0) -> None:
        """Stop one child early (e.g. between phases) without touching the rest."""
        if proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    def killall(self) -> None:
        # Newest-first: the server usually depends on the stub/list-server
        # already being up, so tearing it down before them avoids it logging
        # a burst of upstream-failure noise on its way out.
        for _name, proc in reversed(self._procs):
            if proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
        deadline = time.monotonic() + 10.0
        for _name, proc in reversed(self._procs):
            if proc.poll() is None:
                try:
                    proc.wait(timeout=max(0.0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                        proc.wait(timeout=5)
                    except OSError:
                        pass
        self._procs.clear()

    def __enter__(self) -> "ChildFleet":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.killall()
        return False


# --------------------------------------------------------------------------
# Small stdlib helpers: HTTP polling/timing, /proc reading, DB file size.
# --------------------------------------------------------------------------


def wait_http_ready(url: str, timeout_s: float) -> float:
    """Poll `url` until it answers 200, returning the elapsed seconds.

    /health/ready answers 503 (not an exception-worthy failure) until every
    subsystem is up, so a 503 is treated the same as "connection refused":
    keep polling until the deadline.
    """
    start = time.monotonic()
    deadline = start + timeout_s
    last_error = "never attempted"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return time.monotonic() - start
                last_error = f"HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(0.02)
    raise BenchError(f"{url} did not return 200 within {timeout_s}s (last: {last_error})")


def api_request(base_url: str, method: str, path: str, body: dict | None = None, timeout: float = 5.0) -> tuple[float, int, dict | None]:
    """One API call, returning (elapsed_seconds, http_status, parsed_json_or_None).

    Raises BenchError on a 404 specifically -- that almost always means this
    script is pointed at a server that doesn't speak the Phase 3 API yet,
    which deserves a clear message up front rather than a KeyError deep in
    some scenario function reading `data["lists"]`.
    """
    url = base_url + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read()
            elapsed = time.perf_counter() - start
            return elapsed, resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        elapsed = time.perf_counter() - start
        raw = exc.read()
        payload = None
        try:
            payload = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            pass
        if exc.code == 404:
            raise BenchError(
                f"{method} {path} -> 404. This driver targets the Phase 3 API (spec §3); "
                "the server in the tree right now may still be serving the old routes."
            ) from exc
        return elapsed, exc.code, payload


def read_proc_status_kb(pid: int, field: str) -> int:
    """One VmRSS/VmHWM-style field from /proc/<pid>/status, in kB."""
    with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith(field + ":"):
                # e.g. "VmRSS:\t   12345 kB\n"
                return int(line.split()[1])
    raise BenchError(f"{field} not found in /proc/{pid}/status")


def total_db_bytes(db_path: Path) -> int:
    """Size of the main db file plus its WAL/SHM siblings, if present.

    In WAL mode (the common SQLite perf setup) writes land in `<db>-wal`
    first and the main file doesn't grow until a checkpoint, so measuring
    just `db_path` would under-count -- sometimes to zero -- how much a
    batch of query_log inserts actually cost on disk.
    """
    total = 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(str(db_path) + suffix)
        if candidate.exists():
            total += candidate.stat().st_size
    return total


def count_list_lines(path: Path) -> int:
    with open(path, encoding="utf-8", errors="ignore") as handle:
        return sum(1 for _ in handle)


# --------------------------------------------------------------------------
# Process lifecycle: stub upstream, list HTTP server, the server under test.
# --------------------------------------------------------------------------


def start_stub(fleet: ChildFleet, port: int) -> subprocess.Popen:
    return fleet.spawn(
        "stub_upstream",
        [sys.executable, str(HERE / "stub_upstream.py"), "--host", STUB_HOST, "--port", str(port), "--quiet"],
    )


def start_list_http_server(fleet: ChildFleet, list_file: Path, port: int) -> str:
    fleet.spawn(
        "list_http_server",
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1", "--directory", str(list_file.parent)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return f"http://127.0.0.1:{port}/{list_file.name}"


def build_env(
    *,
    http_port: int,
    dns_port: int,
    db_path: Path,
    stub_port: int,
    history_days: int,
    max_rows: int,
    prune_interval_secs: int,
    block_mode: str = "null_ip",
) -> dict:
    env = os.environ.copy()
    env.update(
        {
            "COGWHEEL_PROFILE": "dev",
            "COGWHEEL_SERVER__HTTP_BIND_ADDR": f"127.0.0.1:{http_port}",
            "COGWHEEL_SERVER__DNS_UDP_BIND_ADDR": f"127.0.0.1:{dns_port}",
            "COGWHEEL_SERVER__DNS_TCP_BIND_ADDR": f"127.0.0.1:{dns_port}",
            "COGWHEEL_SERVER__ADVERTISED_DNS_PORT": str(dns_port),
            "COGWHEEL_STORAGE__DATABASE_URL": f"sqlite://{db_path}",
            "COGWHEEL_UPSTREAM__SERVERS": f"{STUB_HOST}:{stub_port}",
            "COGWHEEL_BLOCKING__MODE": block_mode,
            # Floor is 300s; nothing in this run waits for a scheduled
            # refresh, every list load here is triggered explicitly by the
            # POST /api/v1/lists call, so this just needs to be legal.
            "COGWHEEL_UPDATER__REFRESH_INTERVAL_SECS": "300",
            "COGWHEEL_RETENTION__HISTORY_DAYS": str(history_days),
            "COGWHEEL_RETENTION__QUERY_LOG_MAX_ROWS": str(max_rows),
            "COGWHEEL_RETENTION__PRUNE_INTERVAL_SECS": str(prune_interval_secs),
            "RUST_LOG": env.get("RUST_LOG", "info"),
        }
    )
    return env


def start_server(fleet: ChildFleet, binary: Path, env: dict, log_path: Path) -> subprocess.Popen:
    # The file handle is intentionally left open past this function's return:
    # its lifetime needs to match the child process's, not this call's, so
    # the server's stdout/stderr keep landing in the log for as long as it runs.
    log_handle = open(log_path, "w", encoding="utf-8")
    return fleet.spawn(f"cogwheel-server[{log_path.stem}]", [str(binary)], env=env, stdout=log_handle, stderr=subprocess.STDOUT)


def require_binary(binary: Path) -> None:
    if not binary.exists():
        raise BenchError(f"release binary not found at {binary} -- build it first: cargo build --release --locked -p cogwheel-server")
    if not os.access(binary, os.X_OK):
        raise BenchError(f"{binary} exists but is not executable")


# --------------------------------------------------------------------------
# Setup performed once per server lifecycle: add the list, add rules, wait
# for the index to actually finish building.
# --------------------------------------------------------------------------


def wait_rules_loaded(base_url: str, floor: int, timeout_s: float) -> float:
    start = time.monotonic()
    deadline = start + timeout_s
    last_seen = -1
    while time.monotonic() < deadline:
        _elapsed, status, data = api_request(base_url, "GET", "/api/v1/overview")
        if status == 200 and data is not None:
            last_seen = data["data"]["lists"]["rules_loaded"]
            if last_seen >= floor:
                return time.monotonic() - start
        time.sleep(0.1)
    raise BenchError(f"rules_loaded stuck at {last_seen} (< {floor}) after {timeout_s}s")


def seed_list_and_household_rule(base_url: str, list_url: str) -> None:
    _elapsed, status, data = api_request(
        base_url, "POST", "/api/v1/lists", {"name": "bench-oisd-small", "url": list_url, "kind": "adblock"}
    )
    if status not in (200, 201):
        raise BenchError(f"POST /api/v1/lists -> {status}: {data}")
    _elapsed, status, data = api_request(
        base_url, "POST", "/api/v1/rules", {"domain": HOUSEHOLD_BLOCK_DOMAIN, "action": "block"}
    )
    if status not in (200, 201):
        raise BenchError(f"POST /api/v1/rules -> {status}: {data}")


def get_overview(base_url: str) -> dict:
    _elapsed, status, data = api_request(base_url, "GET", "/api/v1/overview")
    if status != 200 or data is None:
        raise BenchError(f"GET /api/v1/overview -> {status}: {data}")
    return data["data"]


# --------------------------------------------------------------------------
# Correctness checks (spec §11 gate B: these ride along with the perf run).
# --------------------------------------------------------------------------


def check_aaaa_after_a(host: str, port: int, timeout: float) -> dict:
    """A cached A answer must never leak into an AAAA answer for the same name.

    This is the regression test for spec §10's "cache key omits qtype": the
    cache key is `(scope, qtype, domain)`, so the second query here must
    miss (or hit its own, separate AAAA entry) rather than replay the A
    record it already has cached.
    """
    name = "aaaa-after-a.bench.test"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    try:
        sock.send(dnsproto.build_query(name, dnsproto.QTYPE_A, 1))
        dnsproto.parse_message(sock.recv(4096))  # prime the A entry; response itself isn't asserted on
        sock.send(dnsproto.build_query(name, dnsproto.QTYPE_AAAA, 2))
        response = dnsproto.parse_message(sock.recv(4096))
    finally:
        sock.close()
    question_matches = bool(response.questions) and response.questions[0].qtype == dnsproto.QTYPE_AAAA
    no_a_leak = not response.answers_of_type(dnsproto.QTYPE_A)
    return {"question_matches_aaaa": question_matches, "no_a_records_leaked": no_a_leak, "correct": question_matches and no_a_leak}


def check_cname_cloak_blocking(host: str, port: int, timeout: float, block_mode: str) -> dict:
    """A block rule on the CNAME *target* must block the name that points at it (spec §6 step 11)."""
    name = "cloak-probe.cname.test"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    try:
        sock.send(dnsproto.build_query(name, dnsproto.QTYPE_A, 3))
        response = dnsproto.parse_message(sock.recv(4096))
    finally:
        sock.close()
    return {"blocked": dnsbench.is_blocked_answer(response, block_mode, dnsproto.QTYPE_A)}


def check_blocked_total_exact(base_url: str, host: str, port: int, timeout: float, block_mode: str, domains: list[str]) -> dict:
    """`blocked_total`'s delta must equal exactly the number of answers actually served blocked (spec §12)."""
    before = get_overview(base_url)["runtime"]["blocked_total"]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    served_blocked = 0
    try:
        for i, domain in enumerate(domains):
            sock.send(dnsproto.build_query(domain, dnsproto.QTYPE_A, 100 + i))
            try:
                response = dnsproto.parse_message(sock.recv(4096))
            except (socket.timeout, dnsproto.DnsWireError):
                continue
            if dnsbench.is_blocked_answer(response, block_mode, dnsproto.QTYPE_A):
                served_blocked += 1
    finally:
        sock.close()
    after = get_overview(base_url)["runtime"]["blocked_total"]
    actual_delta = after - before
    return {
        "domains_tried": len(domains),
        "served_blocked": served_blocked,
        "blocked_total_before": before,
        "blocked_total_after": after,
        "actual_delta": actual_delta,
        "exact": actual_delta == served_blocked,
    }


def check_hung_upstream(stub_proc: subprocess.Popen, host: str, port: int, timeout: float) -> dict:
    """Cache hits must stay fast even while a burst of misses is stuck behind a hung upstream.

    This is the regression test for spec §5.2's miss hand-off: misses go
    through a bounded semaphore on a spawned task, never inline in the
    receive loop, so a stalled upstream can only ever starve *other misses*
    (once the 512 permits are exhausted) -- it must never delay a cache hit,
    which is served straight out of the receive loop before any of that.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    try:
        sock.send(dnsproto.build_query(CACHE_HIT_NAME, dnsproto.QTYPE_A, 1))
        sock.recv(4096)  # prime the cache entry before hanging the upstream

        os.kill(stub_proc.pid, signal.SIGSTOP)
        try:
            def fire_miss(i: int) -> None:
                miss_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                miss_sock.settimeout(3.0)
                miss_sock.connect((host, port))
                try:
                    miss_sock.send(dnsproto.build_query(f"hung-upstream-miss-{i}.bench.test", dnsproto.QTYPE_A, 200 + i))
                    miss_sock.recv(4096)
                except OSError:
                    pass  # SERVFAIL, a timeout, or a late answer once resumed -- none of it is asserted on
                finally:
                    miss_sock.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                miss_futures = [pool.submit(fire_miss, i) for i in range(20)]

                hit_latencies_s: list[float] = []
                hit_timeouts = 0
                for i in range(30):
                    sock.send(dnsproto.build_query(CACHE_HIT_NAME, dnsproto.QTYPE_A, 300 + i))
                    t0 = time.perf_counter()
                    try:
                        sock.recv(4096)
                    except socket.timeout:
                        # This is exactly the failure this check exists to
                        # catch (a cache hit stuck behind the miss queue), so
                        # it must be recorded, not let the exception cancel
                        # the rest of the run -- SIGCONT below still has to
                        # run either way.
                        hit_timeouts += 1
                        continue
                    hit_latencies_s.append(time.perf_counter() - t0)

                concurrent.futures.wait(miss_futures, timeout=5.0)
        finally:
            os.kill(stub_proc.pid, signal.SIGCONT)
    finally:
        sock.close()

    if not hit_latencies_s:
        return {"cache_hit_ms": None, "hit_timeouts": hit_timeouts, "stayed_under_5ms": False}
    summary = stats.summarize(stats.scaled(hit_latencies_s, 1000.0))
    return {"cache_hit_ms": summary.to_dict(), "hit_timeouts": hit_timeouts, "stayed_under_5ms": hit_timeouts == 0 and summary.max < 5.0}


# --------------------------------------------------------------------------
# The three phases.
# --------------------------------------------------------------------------


def run_main_phase(args: argparse.Namespace, fleet: ChildFleet, list_url: str, out_dir: Path) -> dict:
    db_path = Path(str(args.db) + ".main")
    env = build_env(
        http_port=args.http_port,
        dns_port=args.dns_port,
        db_path=db_path,
        stub_port=args.stub_port,
        history_days=7,
        max_rows=250_000,
        prune_interval_secs=3600,
        block_mode=args.block_mode,
    )
    base_url = f"http://127.0.0.1:{args.http_port}"
    server = start_server(fleet, args.binary, env, out_dir / f"server_{args.label}_main.log")

    result: dict = {}
    result["startup_ms"] = wait_http_ready(f"{base_url}/health/ready", READY_TIMEOUT_S) * 1000.0
    seed_list_and_household_rule(base_url, list_url)
    result["list_activation_ms"] = wait_rules_loaded(base_url, RULES_LOADED_FLOOR, RULES_LOADED_TIMEOUT_S) * 1000.0

    result["rss_idle_after_load_kb"] = read_proc_status_kb(server.pid, "VmRSS")
    result["rss_hwm_after_load_kb"] = read_proc_status_kb(server.pid, "VmHWM")

    # -- database growth per logged row --
    # Each name is unique so every query is both a fresh cache miss and a
    # fresh query_log row; the answers themselves aren't interesting here
    # (dnsbench's cold-miss scenario already covers that), only that they
    # got logged.
    growth_before = total_db_bytes(db_path)
    growth_names = [f"growth-{i}.bench.test" for i in range(args.growth_rows)]
    dnsbench.run_series("127.0.0.1", args.dns_port, args.timeout, [(n, dnsproto.QTYPE_A) for n in growth_names])
    time.sleep(8.0)  # writer flushes at 500 rows or a 5s tick (spec §7); several such flushes may be needed for growth_rows rows
    growth_after = total_db_bytes(db_path)
    result["db_growth_bytes_per_row"] = (growth_after - growth_before) / args.growth_rows

    # -- correctness checks --
    result["aaaa_after_a"] = check_aaaa_after_a("127.0.0.1", args.dns_port, args.timeout)
    cname_before = get_overview(base_url)["runtime"]["cname_blocks_total"]
    api_request(base_url, "POST", "/api/v1/rules", {"domain": CNAME_CLOAK_TARGET_SUFFIX, "action": "block"})
    result["cname_cloak"] = check_cname_cloak_blocking("127.0.0.1", args.dns_port, args.timeout, args.block_mode)
    result["cname_cloak"]["cname_blocks_total_delta"] = get_overview(base_url)["runtime"]["cname_blocks_total"] - cname_before

    blocked_domains = dnsbench.load_names_from_list_file(str(args.list_file), args.blocked_total_sample)
    result["blocked_total"] = check_blocked_total_exact(base_url, "127.0.0.1", args.dns_port, args.timeout, args.block_mode, blocked_domains)

    # -- hung upstream --
    stub_proc = fleet.get("stub_upstream")
    if stub_proc is None:
        raise BenchError("stub_upstream process not tracked by ChildFleet -- cannot run the hung-upstream check")
    result["hung_upstream"] = check_hung_upstream(stub_proc, "127.0.0.1", args.dns_port, args.timeout)

    # -- latency scenarios (dnsbench) --
    cold_miss_nonce = uuid.uuid4().hex[:8]
    result["dnsbench"] = {
        "cold_miss": dnsbench.cold_miss_scenario("127.0.0.1", args.dns_port, args.timeout, args.cold_miss_count, dnsproto.QTYPE_A, cold_miss_nonce),
        "cache_hit": dnsbench.cache_hit_scenario("127.0.0.1", args.dns_port, args.timeout, args.cache_hit_repeat, CACHE_HIT_NAME, dnsproto.QTYPE_A),
        "blocked": dnsbench.blocked_scenario(
            "127.0.0.1", args.dns_port, args.timeout, args.blocked_repeat, HOUSEHOLD_BLOCK_DOMAIN, dnsproto.QTYPE_A, args.block_mode
        ),
        "first_time_blocked_miss": dnsbench.first_time_blocked_miss_scenario(
            "127.0.0.1", args.dns_port, args.timeout, str(args.list_file), args.blocklist_sample, dnsproto.QTYPE_A
        ),
    }

    # -- throughput (mpbench) --
    result["throughput"] = mpbench.run_throughput(
        "127.0.0.1", args.dns_port, args.throughput_workers, args.throughput_queries, CACHE_HIT_NAME, dnsproto.QTYPE_A, args.timeout, server.pid
    )

    result["rss_after_bench_kb"] = read_proc_status_kb(server.pid, "VmRSS")
    result["rss_hwm_after_bench_kb"] = read_proc_status_kb(server.pid, "VmHWM")

    # -- endpoint latency, now that the log has real volume in it --
    queries_latencies = []
    overview_latencies = []
    for _ in range(30):
        elapsed, status, _data = api_request(base_url, "GET", "/api/v1/queries?limit=200")
        if status == 200:
            queries_latencies.append(elapsed)
        elapsed, status, _data = api_request(base_url, "GET", "/api/v1/overview")
        if status == 200:
            overview_latencies.append(elapsed)
    if queries_latencies:
        result["queries_endpoint_ms"] = stats.summarize(stats.scaled(queries_latencies, 1000.0)).to_dict()
    if overview_latencies:
        result["overview_endpoint_ms"] = stats.summarize(stats.scaled(overview_latencies, 1000.0)).to_dict()

    result["cache_hit_server_internal_ns"] = get_overview(base_url)["runtime"]["cache_hit_latency_avg_ns"]

    fleet.stop(server)
    return result


def run_history_days_zero_phase(args: argparse.Namespace, fleet: ChildFleet, list_url: str, out_dir: Path) -> dict:
    """Same cache-hit workload with query-log writing disabled, to isolate its cost (spec §12 "Query log")."""
    db_path = Path(str(args.db) + ".nolog")
    env = build_env(
        http_port=args.http_port,
        dns_port=args.dns_port,
        db_path=db_path,
        stub_port=args.stub_port,
        history_days=0,
        max_rows=250_000,
        prune_interval_secs=3600,
        block_mode=args.block_mode,
    )
    base_url = f"http://127.0.0.1:{args.http_port}"
    server = start_server(fleet, args.binary, env, out_dir / f"server_{args.label}_nolog.log")

    wait_http_ready(f"{base_url}/health/ready", READY_TIMEOUT_S)
    seed_list_and_household_rule(base_url, list_url)
    wait_rules_loaded(base_url, RULES_LOADED_FLOOR, RULES_LOADED_TIMEOUT_S)

    logging_flag = api_request(base_url, "GET", "/api/v1/queries?limit=1")[2]["data"]["logging"]
    dnsbench.cache_hit_scenario("127.0.0.1", args.dns_port, args.timeout, args.cache_hit_repeat, CACHE_HIT_NAME, dnsproto.QTYPE_A)
    cache_hit_ns = get_overview(base_url)["runtime"]["cache_hit_latency_avg_ns"]

    fleet.stop(server)
    return {"logging_reported_off": logging_flag is False, "cache_hit_server_internal_ns": cache_hit_ns}


def run_prune_cap_phase(args: argparse.Namespace, fleet: ChildFleet, list_url: str, out_dir: Path) -> dict:
    """A small QUERY_LOG_MAX_ROWS with a fast prune interval must actually cap the table (spec §7)."""
    db_path = Path(str(args.db) + ".prune")
    max_rows = args.prune_max_rows
    env = build_env(
        http_port=args.http_port,
        dns_port=args.dns_port,
        db_path=db_path,
        stub_port=args.stub_port,
        history_days=7,
        max_rows=max_rows,
        prune_interval_secs=60,  # the config floor (spec §8)
        block_mode=args.block_mode,
    )
    base_url = f"http://127.0.0.1:{args.http_port}"
    server = start_server(fleet, args.binary, env, out_dir / f"server_{args.label}_prune.log")

    wait_http_ready(f"{base_url}/health/ready", READY_TIMEOUT_S)
    seed_list_and_household_rule(base_url, list_url)
    wait_rules_loaded(base_url, RULES_LOADED_FLOOR, RULES_LOADED_TIMEOUT_S)

    rows_to_insert = max_rows + 500
    names = [f"prune-{i}.bench.test" for i in range(rows_to_insert)]
    dnsbench.run_series("127.0.0.1", args.dns_port, args.timeout, [(n, dnsproto.QTYPE_A) for n in names])

    # The prune scheduler's first tick fires immediately at server startup,
    # before these rows exist, so it's a no-op; the tick that actually has
    # to catch this batch is the next one, prune_interval_secs after startup
    # -- and startup happened somewhat before this sleep starts (health-ready
    # wait, list activation, firing rows_to_insert queries). The default
    # margin covers that head start plus the 5 s querylog flush tick.
    time.sleep(args.prune_wait_secs)

    row_count = _read_query_log_row_count(db_path)

    fleet.stop(server)
    return {
        "max_rows_configured": max_rows,
        "rows_inserted": rows_to_insert,
        "rows_after_prune_wait": row_count,
        "within_cap": row_count <= max_rows,
    }


def _read_query_log_row_count(db_path: Path) -> int:
    # Read-only URI connection: WAL mode lets a reader see a consistent
    # snapshot without taking any lock the server's own writer would block
    # on, so this can run with the server still up.
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5.0)
    try:
        return conn.execute("SELECT COUNT(*) FROM query_log").fetchone()[0]
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Reporting.
# --------------------------------------------------------------------------

# (row label, dotted path into the result dict, format) -- format is a
# strftime-style hint only in spirit: "ms"/"us"/"ns"/"kb"/"b"/"qps"/"pct"/"n"
# just say what to append, everything is already the right unit by here.
TABLE_ROWS: list[tuple[str, str, str]] = [
    ("Binary size", "binary_size_bytes", "b"),
    ("Startup -> ready", "main.startup_ms", "ms"),
    ("List activation", "main.list_activation_ms", "ms"),
    ("RSS idle (after load)", "main.rss_idle_after_load_kb", "kb"),
    ("RSS HWM (after load)", "main.rss_hwm_after_load_kb", "kb"),
    ("RSS (after full bench)", "main.rss_after_bench_kb", "kb"),
    ("RSS HWM (after full bench)", "main.rss_hwm_after_bench_kb", "kb"),
    ("Cache hit, server-internal", "main.cache_hit_server_internal_ns", "ns"),
    ("Cache hit, client p50", "main.dnsbench.cache_hit.ms.p50", "ms"),
    ("Cache hit, client p99", "main.dnsbench.cache_hit.ms.p99", "ms"),
    ("Blocked, client p50", "main.dnsbench.blocked.ms.p50", "ms"),
    ("Blocked, client p99", "main.dnsbench.blocked.ms.p99", "ms"),
    ("Blocked answers correct", "main.dnsbench.blocked.all_blocked_correctly", "bool"),
    ("First-time blocked miss p50", "main.dnsbench.first_time_blocked_miss.ms.p50", "ms"),
    ("Cold miss p50", "main.dnsbench.cold_miss.ms.p50", "ms"),
    ("Throughput", "main.throughput.qps", "qps"),
    ("Server CPU per query", "main.throughput.server_cpu.cpu_us_per_query", "us"),
    ("blocked_total exact", "main.blocked_total.exact", "bool"),
    ("AAAA-after-A correct", "main.aaaa_after_a.correct", "bool"),
    ("CNAME cloak blocked", "main.cname_cloak.blocked", "bool"),
    ("Hung upstream: hits stayed <5ms", "main.hung_upstream.stayed_under_5ms", "bool"),
    ("DB growth per logged row", "main.db_growth_bytes_per_row", "b"),
    ("GET /queries p50", "main.queries_endpoint_ms.p50", "ms"),
    ("GET /overview p50", "main.overview_endpoint_ms.p50", "ms"),
    ("Cache hit, HISTORY_DAYS=0", "history_days_zero.cache_hit_server_internal_ns", "ns"),
    ("Prune cap held", "prune_cap.within_cap", "bool"),
]


def _dotted_get(d: dict, path: str):
    node = d
    for key in path.split("."):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def format_table(result: dict) -> str:
    lines = [f"Cogwheel bench -- label={result.get('label')} generated_at={result.get('generated_at')}", ""]
    name_width = max(len(name) for name, _, _ in TABLE_ROWS)
    for name, path, unit in TABLE_ROWS:
        value = _dotted_get(result, path)
        if value is None:
            rendered = "n/a"
        elif unit == "bool":
            rendered = "yes" if value else "NO"
        elif unit == "b":
            rendered = f"{value:,.0f} B"
        elif unit == "kb":
            rendered = f"{value:,} kB"
        elif unit in ("ms", "us", "ns"):
            rendered = f"{value:,.3f} {unit}"
        elif unit == "qps":
            rendered = f"{value:,.0f} qps"
        else:
            rendered = str(value)
        lines.append(f"  {name.ljust(name_width)}  {rendered}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Entry point.
# --------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--label", required=True, help="tag for this run; output goes to <out>/bench_<label>.json")
    parser.add_argument("--binary", default="target/release/cogwheel-server", type=Path)
    parser.add_argument("--list-file", required=True, type=Path, help="a real blocklist file, e.g. oisd small fetched per the README")
    parser.add_argument("--http-port", type=int, default=38080)
    parser.add_argument("--dns-port", type=int, default=35353)
    parser.add_argument("--db", required=True, type=Path, help="base path for this run's SQLite databases (suffixes are appended per phase)")
    parser.add_argument("--out", required=True, type=Path, help="directory for bench_<label>.json and server logs")

    parser.add_argument("--stub-port", type=int, default=DEFAULT_STUB_PORT)
    parser.add_argument("--list-http-port", type=int, default=DEFAULT_LIST_HTTP_PORT)
    parser.add_argument("--block-mode", choices=("null_ip", "nxdomain", "nodata", "refused"), default="null_ip")
    parser.add_argument("--timeout", type=float, default=2.0, help="per-query socket timeout, seconds")

    parser.add_argument("--cold-miss-count", type=int, default=200)
    parser.add_argument("--cache-hit-repeat", type=int, default=1000)
    parser.add_argument("--blocked-repeat", type=int, default=500)
    parser.add_argument("--blocklist-sample", type=int, default=500)
    parser.add_argument("--blocked-total-sample", type=int, default=200)
    parser.add_argument("--growth-rows", type=int, default=3000)
    parser.add_argument("--throughput-workers", type=int, default=4)
    parser.add_argument("--throughput-queries", type=int, default=25_000, help="per worker")
    parser.add_argument("--prune-max-rows", type=int, default=500)
    parser.add_argument("--prune-wait-secs", type=float, default=75.0, help="past the 60s prune-interval floor, plus startup/flush slack")

    parser.add_argument("--skip-history-days-zero-phase", action="store_true")
    parser.add_argument("--skip-prune-phase", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        require_binary(args.binary)
        if not args.list_file.exists():
            raise BenchError(f"list file not found: {args.list_file} (see README.md for how to fetch oisd small)")
        args.out.mkdir(parents=True, exist_ok=True)
    except BenchError as exc:
        print(f"run.py: {exc}", file=sys.stderr)
        return 2

    result: dict = {
        "label": args.label,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "binary": str(args.binary),
        "binary_size_bytes": args.binary.stat().st_size,
        "list_file": str(args.list_file),
        "list_line_count": count_list_lines(args.list_file),
        "http_port": args.http_port,
        "dns_port": args.dns_port,
    }

    try:
        with ChildFleet() as fleet:
            start_stub(fleet, args.stub_port)
            list_url = start_list_http_server(fleet, args.list_file, args.list_http_port)
            time.sleep(0.3)  # let both bind before the server tries to reach them

            result["main"] = run_main_phase(args, fleet, list_url, args.out)

            if not args.skip_history_days_zero_phase:
                result["history_days_zero"] = run_history_days_zero_phase(args, fleet, list_url, args.out)

            if not args.skip_prune_phase:
                result["prune_cap"] = run_prune_cap_phase(args, fleet, list_url, args.out)
    except BenchError as exc:
        print(f"run.py: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        # Deliberately broad: this is the top-level driver, so any failure
        # anywhere in a phase must still reach `with ChildFleet()`'s cleanup
        # and get reported clearly instead of a bare traceback.
        print(f"run.py: unexpected failure: {exc}", file=sys.stderr)
        return 1

    out_path = args.out / f"bench_{args.label}.json"
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print(format_table(result))
    print(f"\nFull results: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
