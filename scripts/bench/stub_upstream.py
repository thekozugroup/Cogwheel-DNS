#!/usr/bin/env python3
"""A tiny stdlib-only UDP DNS server that stands in for a real upstream resolver.

Cogwheel's benchmark gate (spec §11 gate B) needs an upstream that answers
instantly and deterministically -- a real recursive resolver would make every
number this harness produces depend on the internet being fast that day, and
a flaky egress path would turn a benchmark run into a coin flip. So instead:

  * any A query gets 203.0.113.<hash(name) % 250>, TTL 300
    (203.0.113.0/24 is TEST-NET-3, RFC 5737 -- guaranteed never a real host)
  * any AAAA query gets 2001:db8::<hash(name) % 0xffff + 1>, TTL 300
    (2001:db8::/32 is the documentation prefix, RFC 3849)
  * an A query for a name under `cname.test` gets a CNAME to
    `target-<n>.blocked.test` plus that target's own A record in the same
    response -- this is the "cloaked" shape run.py's CNAME-blocking test
    needs: the server is expected to inspect the CNAME chain and evaluate the
    target against block lists too (spec §6 step 11), which a plain A answer
    can never exercise.
  * anything else (unknown qtype, malformed packet) gets NOERROR/no-answer
    rather than an error, matching how a real upstream shrugs off a record
    type it has nothing to say about.

Usage:
    python3 stub_upstream.py [--host 127.0.0.1] [--port 35399] [--quiet]

Run standalone it just serves forever; SIGINT/SIGTERM stop it. run.py starts
it as a subprocess and kills it by PID when the benchmark run ends.
"""

from __future__ import annotations

import argparse
import signal
import socket
import sys

import dnsproto

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 35399

# Cheap and constant regardless of query volume, so building these once at
# import time keeps the per-packet work down to hashing the name and packing
# one RR -- the "tight loop, minimal per-packet allocation" the spec asks for.
_A_MOD = 250
_AAAA_MOD = 0xFFFF  # kept off 0 below so the address is never `2001:db8::`
_CNAME_TARGET_MOD = 250
_CNAME_SUFFIX = ".cname.test"
_CNAME_APEX = "cname.test"


def _is_under_cname_test(qname: str) -> bool:
    lowered = qname.rstrip(".").lower()
    return lowered == _CNAME_APEX or lowered.endswith(_CNAME_SUFFIX)


def build_response(request: bytes) -> bytes | None:
    """Build the wire-format response for one request datagram, or None to drop it.

    Dropping (rather than sending SERVFAIL) is reserved for packets too
    malformed to safely answer at all -- a real upstream that can't parse a
    question doesn't reply either, and dnsbench.py's timeout handling already
    covers "no response came back" as a distinct outcome from "an error came
    back".
    """
    try:
        query_id, flags, qname, qtype, qclass, question_end = dnsproto.parse_question_only(request)
    except dnsproto.DnsWireError:
        return None
    if qclass != dnsproto.QCLASS_IN:
        return None

    question = request[12:question_end]  # echoed verbatim, see below

    if qtype == dnsproto.QTYPE_A and _is_under_cname_test(qname):
        n = dnsproto.stable_hash_mod(qname, _CNAME_TARGET_MOD)
        target = f"target-{n}.blocked.test"
        target_ip = f"203.0.113.{dnsproto.stable_hash_mod(target, _A_MOD)}"
        cname_rr = dnsproto.build_answer_rr(0x0C, dnsproto.QTYPE_CNAME, 300, dnsproto.encode_qname(target))
        # The A record's owner is the CNAME's target, which we just wrote out
        # in full above (no compression pointer available for it), so its
        # rdata has to repeat those name bytes rather than pointing at 0x0C.
        a_rr = dnsproto.build_answer_rr_for_name(target, dnsproto.QTYPE_A, 300, dnsproto.a_rdata(target_ip))
        header = dnsproto.build_response_header(query_id, flags, dnsproto.RCODE_NOERROR, 2)
        return header + question + cname_rr + a_rr

    if qtype == dnsproto.QTYPE_A:
        ip = f"203.0.113.{dnsproto.stable_hash_mod(qname, _A_MOD)}"
        rr = dnsproto.build_answer_rr(0x0C, dnsproto.QTYPE_A, 300, dnsproto.a_rdata(ip))
        header = dnsproto.build_response_header(query_id, flags, dnsproto.RCODE_NOERROR, 1)
        return header + question + rr

    if qtype == dnsproto.QTYPE_AAAA:
        n = dnsproto.stable_hash_mod(qname, _AAAA_MOD) + 1
        ip = f"2001:db8::{n:x}"
        rr = dnsproto.build_answer_rr(0x0C, dnsproto.QTYPE_AAAA, 300, dnsproto.aaaa_rdata(ip))
        header = dnsproto.build_response_header(query_id, flags, dnsproto.RCODE_NOERROR, 1)
        return header + question + rr

    # Unhandled qtype (HTTPS/SVCB, NS, whatever else a real resolver library
    # probes for): answer with no records rather than pretend to know.
    header = dnsproto.build_response_header(query_id, flags, dnsproto.RCODE_NOERROR, 0)
    return header + question


def serve(host: str, port: int, *, quiet: bool) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    # A finite timeout, not a bare blocking recvfrom, is what makes the
    # `running` flag actually get checked: PEP 475 auto-retries a blocking
    # syscall interrupted by a signal, so a plain blocking recvfrom would
    # never return once nothing more is arriving and the process would sit
    # past SIGTERM until something else (SIGKILL) ends it. The 0.5 s ceiling
    # is the worst-case shutdown latency; the extra per-packet select it
    # costs is noise next to everything else a Python loop is already doing.
    sock.settimeout(0.5)
    if not quiet:
        print(f"stub_upstream: listening on {host}:{port} (udp)", file=sys.stderr, flush=True)

    running = True

    def _stop(signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    served = 0
    while running:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            # Interrupted by the signal handler mid-syscall; the `running`
            # check at the top of the loop is what actually decides to stop.
            continue
        response = build_response(data)
        if response is not None:
            try:
                sock.sendto(response, addr)
            except OSError:
                pass  # a client that vanished mid-flight isn't this process's problem
            served += 1
            if not quiet and served % 50_000 == 0:
                print(f"stub_upstream: served {served} responses", file=sys.stderr, flush=True)
    sock.close()
    if not quiet:
        print(f"stub_upstream: stopped after {served} responses", file=sys.stderr, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--quiet", action="store_true", help="suppress startup/progress/shutdown lines on stderr")
    args = parser.parse_args(argv)
    serve(args.host, args.port, quiet=args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
