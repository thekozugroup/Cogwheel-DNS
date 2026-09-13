"""Minimal DNS wire-format encode/decode, stdlib only.

The bench harness needs to build and read raw DNS messages (queries, and the
answers stub_upstream.py / cogwheel-server send back) without pulling in a
third-party resolver library -- these scripts have to run unmodified on
whatever Python ships on the target box (a Raspberry Pi in Phase 4), so
"stdlib only" is load-bearing, not a style preference.

This is not a general-purpose DNS library: just enough of RFC 1035 (plus the
EDNS0 OPT pseudo-RR from RFC 6891, so responses over 512 B round-trip on a
loopback UDP socket) to build A/AAAA queries and parse A/AAAA/CNAME answers,
which is all four bench tools need.
"""

from __future__ import annotations

import socket
import struct
import zlib
from dataclasses import dataclass, field

# Query types this harness cares about. The numeric values are the IANA
# assignments, not something we get to choose.
QTYPE_A = 1
QTYPE_CNAME = 5
QTYPE_AAAA = 28
QTYPE_OPT = 41  # EDNS0 pseudo-RR, RFC 6891
QCLASS_IN = 1

_QTYPE_NAMES = {QTYPE_A: "A", QTYPE_CNAME: "CNAME", QTYPE_AAAA: "AAAA", QTYPE_OPT: "OPT"}


def qtype_name(qtype: int) -> str:
    return _QTYPE_NAMES.get(qtype, str(qtype))


# Header flag bits (RFC 1035 §4.1.1). Only the ones this harness reads or sets.
FLAG_QR = 0x8000  # 1 = response
FLAG_TC = 0x0200  # truncated
FLAG_RD = 0x0100  # recursion desired
FLAG_RA = 0x0080  # recursion available
RCODE_MASK = 0x000F

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3
RCODE_REFUSED = 5

_RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}


def rcode_name(rcode: int) -> str:
    return _RCODE_NAMES.get(rcode, str(rcode))


class DnsWireError(ValueError):
    """A packet did not parse. Bench code should treat this as a failed probe, not crash the run."""


def encode_qname(name: str) -> bytes:
    """Encode a dotted name as length-prefixed labels terminated by a zero octet.

    A trailing dot is accepted and ignored, matching how DNS names are
    usually written (`example.com.`); it is not required.
    """
    name = name.strip()
    if name in ("", "."):
        return b"\x00"
    if name.endswith("."):
        name = name[:-1]
    out = bytearray()
    for label in name.split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) <= 63:
            raise DnsWireError(f"label {label!r} in {name!r} is not 1..63 bytes")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a name starting at `offset`, following compression pointers.

    Returns (name, offset_after_the_name_or_pointer) -- the second value is
    where the *containing* record's fixed fields continue, which for a
    pointer is right after the 2-byte pointer itself, not wherever the
    pointer led.
    """
    labels: list[str] = []
    cursor = offset
    end_of_field: int | None = None  # set once we jump through the first pointer
    visited: set[int] = set()
    while True:
        if cursor >= len(data):
            raise DnsWireError("name runs past end of packet")
        length = data[cursor]
        if length == 0:
            cursor += 1
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise DnsWireError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if end_of_field is None:
                end_of_field = cursor + 2
            if pointer in visited or pointer >= cursor:
                # Forward or repeated pointers can't happen in a well-formed
                # message and would otherwise loop forever.
                raise DnsWireError("compression pointer loop")
            visited.add(pointer)
            cursor = pointer
            continue
        if length & 0xC0:
            raise DnsWireError("reserved label-length bits set")
        cursor += 1
        label = data[cursor : cursor + length]
        if len(label) != length:
            raise DnsWireError("label runs past end of packet")
        labels.append(label.decode("ascii", errors="replace"))
        cursor += length
    name = ".".join(labels) + "." if labels else "."
    return name, (end_of_field if end_of_field is not None else cursor)


def build_query(qname: str, qtype: int, query_id: int, *, edns: bool = True, want_dnssec: bool = False) -> bytes:
    """Build a single-question query with RD=1, optionally carrying an EDNS0 OPT RR.

    EDNS0 defaults on because that's what a real stub resolver sends and the
    server's `edns_max` handling (spec §5.2) only kicks in when it sees the
    OPT record; querying without it would exercise a code path real clients
    rarely hit.
    """
    flags = FLAG_RD
    arcount = 1 if edns else 0
    header = struct.pack(">HHHHHH", query_id & 0xFFFF, flags, 1, 0, 0, arcount)
    question = encode_qname(qname) + struct.pack(">HH", qtype, QCLASS_IN)
    packet = header + question
    if edns:
        # name=root, type=OPT, UDP payload size=4096, extended-rcode/version=0,
        # flags (DO bit for DNSSEC) optional, rdlength=0.
        opt_flags = 0x8000 if want_dnssec else 0x0000
        packet += b"\x00" + struct.pack(">HHIH", QTYPE_OPT, 4096, opt_flags, 0)
    return packet


@dataclass
class Question:
    name: str
    qtype: int
    qclass: int


@dataclass
class ResourceRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    # Best-effort human-readable rdata: an IP string for A/AAAA, a dotted
    # name for CNAME, otherwise the raw bytes' hex.
    text: str = ""


@dataclass
class DnsMessage:
    query_id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    questions: list[Question] = field(default_factory=list)
    answers: list[ResourceRecord] = field(default_factory=list)

    @property
    def rcode(self) -> int:
        return self.flags & RCODE_MASK

    @property
    def truncated(self) -> bool:
        return bool(self.flags & FLAG_TC)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_QR)

    def answers_of_type(self, rtype: int) -> list[ResourceRecord]:
        return [rr for rr in self.answers if rr.rtype == rtype]


def _decode_rdata(rtype: int, rdata: bytes, packet: bytes, rdata_offset: int) -> str:
    try:
        if rtype == QTYPE_A and len(rdata) == 4:
            return socket.inet_ntop(socket.AF_INET, rdata)
        if rtype == QTYPE_AAAA and len(rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rtype == QTYPE_CNAME:
            # CNAME rdata can itself use compression, so it must be decoded
            # against the full packet at its real offset, not the rdata slice.
            name, _ = decode_name(packet, rdata_offset)
            return name
    except (OSError, DnsWireError):
        pass
    return rdata.hex()


def parse_message(data: bytes, *, parse_answers: bool = True) -> DnsMessage:
    """Parse a full DNS message. Raises DnsWireError on anything malformed."""
    if len(data) < 12:
        raise DnsWireError(f"packet too short ({len(data)} bytes)")
    query_id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    questions: list[Question] = []
    for _ in range(qd):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DnsWireError("question runs past end of packet")
        qtype, qclass = struct.unpack(">HH", data[offset : offset + 4])
        offset += 4
        questions.append(Question(name, qtype, qclass))
    answers: list[ResourceRecord] = []
    if parse_answers:
        for _ in range(an):
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                raise DnsWireError("answer RR header runs past end of packet")
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset : offset + 10])
            offset += 10
            if offset + rdlen > len(data):
                raise DnsWireError("answer RR rdata runs past end of packet")
            rdata = data[offset : offset + rdlen]
            text = _decode_rdata(rtype, rdata, data, offset)
            offset += rdlen
            answers.append(ResourceRecord(name, rtype, rclass, ttl, rdata, text))
    return DnsMessage(query_id, flags, qd, an, ns, ar, questions, answers)


def parse_question_only(data: bytes) -> tuple[int, int, str, int, int, int]:
    """Fast path for a responder that only needs the request's question.

    Returns (query_id, flags, qname, qtype, qclass, offset_after_question) so
    a caller (stub_upstream.py) can echo the raw question bytes back verbatim
    instead of re-encoding them.
    """
    if len(data) < 12:
        raise DnsWireError(f"packet too short ({len(data)} bytes)")
    query_id, flags = struct.unpack(">HH", data[:4])
    qdcount = struct.unpack(">H", data[4:6])[0]
    if qdcount < 1:
        raise DnsWireError("no question in packet")
    name, offset = decode_name(data, 12)
    if offset + 4 > len(data):
        raise DnsWireError("question runs past end of packet")
    qtype, qclass = struct.unpack(">HH", data[offset : offset + 4])
    return query_id, flags, name, qtype, qclass, offset + 4


def stable_hash_mod(name: str, modulus: int) -> int:
    """A deterministic (non-randomized) hash for picking fake answer addresses.

    Python's built-in `hash()` is salted per-process (PYTHONHASHSEED) so two
    runs of stub_upstream.py would answer the same name differently -- fine
    for the stub in isolation, but it would make "did the server relay what
    the stub actually sent" comparisons in run.py non-reproducible. CRC32 is
    not cryptographic and does not need to be; it just needs to be the same
    number every time for the same name.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    return zlib.crc32(name.lower().encode("utf-8")) % modulus


def build_answer_rr(name_pointer_offset: int, rtype: int, ttl: int, rdata: bytes) -> bytes:
    """Encode one answer RR whose owner name is a compression pointer.

    `name_pointer_offset` is almost always 0x0C (12): the question name
    starts right after the fixed 12-byte header, so pointing back at it is
    both correct and the cheapest possible encoding -- no name bytes repeated.
    """
    name = struct.pack(">H", 0xC000 | (name_pointer_offset & 0x3FFF))
    return name + struct.pack(">HHIH", rtype, QCLASS_IN, ttl, len(rdata)) + rdata


def build_answer_rr_for_name(name: str, rtype: int, ttl: int, rdata: bytes) -> bytes:
    """Encode one answer RR with a fully spelled-out owner name (no compression).

    Used when the owner isn't the packet's question name and pointing at some
    other RR we just wrote would need us to track its offset -- for a two-RR
    stub response, spelling the name out again is simpler and the extra bytes
    don't matter on loopback.
    """
    return encode_qname(name) + struct.pack(">HHIH", rtype, QCLASS_IN, ttl, len(rdata)) + rdata


def build_response_header(query_id: int, request_flags: int, rcode: int, ancount: int) -> bytes:
    """Header for a response with 1 question and `ancount` answers, 0 NS/AR."""
    flags = FLAG_QR | FLAG_RA | (request_flags & FLAG_RD) | (rcode & RCODE_MASK)
    return struct.pack(">HHHHHH", query_id & 0xFFFF, flags, 1, ancount, 0, 0)


def a_rdata(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET, ip)


def aaaa_rdata(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip)
