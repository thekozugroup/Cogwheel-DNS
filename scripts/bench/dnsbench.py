#!/usr/bin/env python3
"""A stdlib-only DNS latency client for the Cogwheel bench harness.

Measures, against a single `--host`/`--port` UDP target, one query at a time
in a closed loop (send, wait for the matching reply, record the elapsed
time) -- throughput under concurrent load is mpbench.py's job, this tool is
about the shape of the latency distribution for four scenarios that matter
to Cogwheel specifically:

  * cold-miss   -- N distinct names never queried before (spec §12's
                   "First-time blocked miss" sibling for *allowed* names: this
                   is what a name looks like the first time any household
                   device asks for it, cache empty, upstream in the loop).
  * cache-hit   -- one name primed once, then queried N more times (the
                   `moka` in-process cache from cogwheel-dns-core answering
                   without touching upstream at all).
  * blocked     -- a name expected to be on the seeded blocklist, queried N
                   times, asserting the answer really does mean "blocked"
                   under whatever --block-mode the server is configured for.
  * first-time-blocked-miss -- names read from a real blocklist file, each
                   queried exactly once (a name can only be "first-time" once
                   per server lifetime, so no repeat-and-average here) --
                   this is the number spec §12 calls "First-time blocked miss
                   (55,852 rules)": how long the very first lookup against a
                   freshly-loaded ~56k-rule index takes.

Every scenario is optional except cold-miss and cache-hit, which need
nothing but a live DNS responder to test against (so `dnsbench.py` run
directly at a stub_upstream.py instance proves the client and its statistics
math work, per the Phase 3b brief, without a real Cogwheel server in the
loop). --blocked-domain and --blocklist-file switch the other two on.

Output is one JSON object on stdout (or written to --out).
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import sys
import time
import uuid
from dataclasses import dataclass

import dnsproto
import stats

DEFAULT_TIMEOUT = 2.0
NULL_IPV4 = "0.0.0.0"
NULL_IPV6 = "::"


@dataclass
class Probe:
    """One query/response round trip, or a timeout."""

    qname: str
    qtype: int
    elapsed_s: float | None  # None on timeout
    message: dnsproto.DnsMessage | None
    error: str | None = None


def _new_socket(host: str, port: int, timeout: float) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    # connect() on a UDP socket doesn't dial anything, it just filters
    # incoming datagrams to this peer and lets us use send()/recv() -- and
    # it's what makes a stray reply from something else on the box (or a
    # very late duplicate) invisible instead of corrupting the next sample.
    sock.connect((host, port))
    return sock


def query_once(sock: socket.socket, qname: str, qtype: int) -> Probe:
    query_id = random.randint(0, 0xFFFF)
    packet = dnsproto.build_query(qname, qtype, query_id)
    start = time.perf_counter()
    try:
        sock.send(packet)
        data = sock.recv(4096)
    except socket.timeout:
        return Probe(qname, qtype, None, None, error="timeout")
    except OSError as exc:
        return Probe(qname, qtype, None, None, error=str(exc))
    elapsed = time.perf_counter() - start
    try:
        message = dnsproto.parse_message(data)
    except dnsproto.DnsWireError as exc:
        return Probe(qname, qtype, elapsed, None, error=f"unparseable response: {exc}")
    if message.query_id != query_id:
        return Probe(qname, qtype, elapsed, message, error="query id mismatch (stray/late reply)")
    return Probe(qname, qtype, elapsed, message)


def run_series(host: str, port: int, timeout: float, queries: list[tuple[str, int]]) -> list[Probe]:
    sock = _new_socket(host, port, timeout)
    try:
        return [query_once(sock, qname, qtype) for qname, qtype in queries]
    finally:
        sock.close()


def _ms_summary(probes: list[Probe]) -> dict:
    good = [p.elapsed_s for p in probes if p.elapsed_s is not None]
    timeouts = sum(1 for p in probes if p.error == "timeout")
    # A probe can fail without timing out (ECONNREFUSED via ICMP on a
    # connected UDP socket when nothing is listening, an unparseable reply,
    # ...); folding those into "timeouts" would make a dead target and a slow
    # one look identical in the JSON, so they get their own count.
    other_errors = [p.error for p in probes if p.error is not None and p.error != "timeout"]
    result: dict = {"count": len(probes), "timeouts": timeouts, "errors": len(other_errors)}
    if other_errors:
        result["sample_error"] = other_errors[0]
    if good:
        summary = stats.summarize(stats.scaled(good, 1000.0))
        result["ms"] = summary.to_dict()
    return result


def cold_miss_scenario(host: str, port: int, timeout: float, count: int, qtype: int, nonce: str) -> dict:
    # The nonce guarantees "never queried before" even across repeated runs
    # against a long-lived server (a fixed name pattern would be a cache hit
    # on the second invocation of dnsbench.py, silently turning a cold-miss
    # measurement into a cache-hit one).
    names = [f"coldmiss-{nonce}-{i}.bench.test" for i in range(count)]
    probes = run_series(host, port, timeout, [(n, qtype) for n in names])
    return _ms_summary(probes)


def cache_hit_scenario(host: str, port: int, timeout: float, repeat: int, name: str, qtype: int) -> dict:
    sock = _new_socket(host, port, timeout)
    try:
        prime = query_once(sock, name, qtype)
        repeats = [query_once(sock, name, qtype) for _ in range(repeat)]
    finally:
        sock.close()
    result = _ms_summary(repeats)
    result["name"] = name
    result["prime"] = {
        "elapsed_ms": None if prime.elapsed_s is None else prime.elapsed_s * 1000.0,
        "error": prime.error,
    }
    return result


def is_blocked_answer(message: dnsproto.DnsMessage, block_mode: str, qtype: int) -> bool:
    if block_mode == "nxdomain":
        return message.rcode == dnsproto.RCODE_NXDOMAIN
    if block_mode == "refused":
        return message.rcode == dnsproto.RCODE_REFUSED
    if block_mode == "nodata":
        return message.rcode == dnsproto.RCODE_NOERROR and not message.answers
    if block_mode == "null_ip":
        if message.rcode != dnsproto.RCODE_NOERROR:
            return False
        if qtype == dnsproto.QTYPE_A:
            return any(rr.rtype == dnsproto.QTYPE_A and rr.text == NULL_IPV4 for rr in message.answers)
        if qtype == dnsproto.QTYPE_AAAA:
            return any(rr.rtype == dnsproto.QTYPE_AAAA and rr.text == NULL_IPV6 for rr in message.answers)
        return False
    raise ValueError(f"unknown block mode {block_mode!r}")


def blocked_scenario(host: str, port: int, timeout: float, repeat: int, domain: str, qtype: int, block_mode: str) -> dict:
    probes = run_series(host, port, timeout, [(domain, qtype)] * repeat)
    result = _ms_summary(probes)
    result["domain"] = domain
    result["block_mode"] = block_mode
    checked = [p for p in probes if p.message is not None]
    mismatches = [p for p in checked if not is_blocked_answer(p.message, block_mode, qtype)]
    result["checked"] = len(checked)
    result["mismatches"] = len(mismatches)
    result["all_blocked_correctly"] = bool(checked) and not mismatches
    return result


def load_names_from_list_file(path: str, limit: int) -> list[str]:
    """Pull up to `limit` domain names out of an ABP/hosts/plain-domains blocklist file.

    Deliberately permissive about format (this harness's job is to grab
    *some* real, never-before-queried domains from oisd small, not to
    re-implement cogwheel-lists' parser) -- it strips ABP's `||...^` wrapper
    and comment/header lines, and skips anything that doesn't look like a
    domain, but does not validate against the DNSNet+ grammar.
    """
    names: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith(("!", "#", "[")):
                continue
            if line.startswith("||"):
                line = line[2:]
            line = line.split("^", 1)[0].split("$", 1)[0]
            # hosts-format lines are "0.0.0.0 example.com" or "127.0.0.1 example.com"
            parts = line.split()
            candidate = parts[-1] if len(parts) > 1 and parts[0].replace(".", "").isdigit() else line
            candidate = candidate.strip().lower()
            if not candidate or " " in candidate or "/" in candidate:
                continue
            if "." not in candidate:
                continue
            names.append(candidate)
            if len(names) >= limit:
                break
    return names


def first_time_blocked_miss_scenario(host: str, port: int, timeout: float, list_file: str, count: int, qtype: int) -> dict:
    names = load_names_from_list_file(list_file, count)
    if not names:
        return {"count": 0, "error": f"no usable domain names found in {list_file}"}
    probes = run_series(host, port, timeout, [(n, qtype) for n in names])
    result = _ms_summary(probes)
    result["source_file"] = list_file
    result["requested"] = count
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-query socket timeout, seconds")
    parser.add_argument("--qtype", choices=("a", "aaaa"), default="a", help="record type for every scenario")

    parser.add_argument("--cold-miss-count", type=int, default=200)
    parser.add_argument("--skip-cold-miss", action="store_true")

    parser.add_argument("--cache-hit-repeat", type=int, default=1000)
    parser.add_argument("--cache-hit-name", default="cache-hit.bench.test")
    parser.add_argument("--skip-cache-hit", action="store_true")

    parser.add_argument("--blocked-domain", default=None, help="a domain expected to already be blocked; omit to skip this scenario")
    parser.add_argument("--blocked-repeat", type=int, default=500)
    parser.add_argument(
        "--block-mode",
        choices=("null_ip", "nxdomain", "nodata", "refused"),
        default="null_ip",
        help="must match the server's COGWHEEL_BLOCKING__MODE for the correctness assertion to mean anything",
    )

    parser.add_argument("--blocklist-file", default=None, help="a real blocklist file to draw never-queried names from; omit to skip this scenario")
    parser.add_argument("--blocklist-sample", type=int, default=500)

    parser.add_argument("--out", default=None, help="write JSON here instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    qtype = dnsproto.QTYPE_AAAA if args.qtype == "aaaa" else dnsproto.QTYPE_A

    try:
        # connect() on a UDP socket never dials anything -- it can only catch
        # a malformed address/port, not "nothing is listening". Whether the
        # target actually answers is checked after every scenario has run,
        # below: if literally nothing came back, that is reported clearly
        # instead of as a wall of per-scenario timeouts.
        probe_sock = _new_socket(args.host, args.port, min(args.timeout, 1.0))
        probe_sock.close()
    except OSError as exc:
        print(f"dnsbench: cannot reach {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 2

    result: dict = {
        "tool": "dnsbench",
        "target": {"host": args.host, "port": args.port},
        "qtype": args.qtype.upper(),
    }

    if not args.skip_cold_miss:
        nonce = uuid.uuid4().hex[:8]
        result["cold_miss"] = cold_miss_scenario(args.host, args.port, args.timeout, args.cold_miss_count, qtype, nonce)

    if not args.skip_cache_hit:
        result["cache_hit"] = cache_hit_scenario(args.host, args.port, args.timeout, args.cache_hit_repeat, args.cache_hit_name, qtype)

    if args.blocked_domain:
        result["blocked"] = blocked_scenario(args.host, args.port, args.timeout, args.blocked_repeat, args.blocked_domain, qtype, args.block_mode)

    if args.blocklist_file:
        result["first_time_blocked_miss"] = first_time_blocked_miss_scenario(
            args.host, args.port, args.timeout, args.blocklist_file, args.blocklist_sample, qtype
        )

    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)

    ran_scenarios = [v for v in result.values() if isinstance(v, dict) and "count" in v]
    if ran_scenarios and all(scenario.get("ms") is None for scenario in ran_scenarios):
        print(f"dnsbench: every query to {args.host}:{args.port} failed; is the server up?", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
