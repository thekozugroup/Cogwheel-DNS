#!/usr/bin/env python3
"""Unit tests for the parsing/statistics helpers, no network involved.

`python3 -m unittest discover -s scripts/bench` runs this file. It exists
because dnsproto.py and stats.py are exactly the pieces of the bench harness
that CAN be tested without a live server or even a live stub -- everything
else in scripts/bench/ is validated by actually running it against
stub_upstream.py (see the README), which this suite deliberately does not do.
"""

from __future__ import annotations

import unittest

import dnsproto
import stats


class EncodeDecodeNameTests(unittest.TestCase):
    def test_round_trip_simple_name(self):
        encoded = dnsproto.encode_qname("example.com")
        name, offset = dnsproto.decode_name(encoded, 0)
        self.assertEqual(name, "example.com.")
        self.assertEqual(offset, len(encoded))

    def test_trailing_dot_is_equivalent(self):
        self.assertEqual(dnsproto.encode_qname("example.com"), dnsproto.encode_qname("example.com."))

    def test_root_name(self):
        encoded = dnsproto.encode_qname(".")
        self.assertEqual(encoded, b"\x00")
        name, offset = dnsproto.decode_name(encoded, 0)
        self.assertEqual(name, ".")
        self.assertEqual(offset, 1)

    def test_label_over_63_bytes_rejected(self):
        with self.assertRaises(dnsproto.DnsWireError):
            dnsproto.encode_qname("a" * 64 + ".com")

    def test_compression_pointer_is_followed(self):
        # Hand-build: [question name at 12][some RR whose name is a pointer to 12]
        header = b"\x00" * 12
        question_name = dnsproto.encode_qname("cname.test")
        pointer_rr_name = bytes([0xC0, 0x0C])  # pointer to offset 12
        packet = header + question_name + pointer_rr_name
        name, offset = dnsproto.decode_name(packet, 12)
        self.assertEqual(name, "cname.test.")
        self.assertEqual(offset, 12 + len(question_name))  # consumed the labels + terminator, no pointer here

        # Now decode the pointer RR's name and confirm it resolves to the same name.
        pointer_offset = 12 + len(question_name)
        name2, offset2 = dnsproto.decode_name(packet, pointer_offset)
        self.assertEqual(name2, "cname.test.")
        # Decoding through a pointer must report the offset right after the
        # 2-byte pointer, not wherever the pointer led -- otherwise a caller
        # parsing the rest of that RR's fixed fields would read from the
        # wrong place.
        self.assertEqual(offset2, pointer_offset + 2)

    def test_pointer_loop_is_rejected_not_infinite(self):
        # offset 12 points at itself.
        packet = b"\x00" * 12 + bytes([0xC0, 0x0C])
        with self.assertRaises(dnsproto.DnsWireError):
            dnsproto.decode_name(packet, 12)

    def test_truncated_name_is_rejected(self):
        with self.assertRaises(dnsproto.DnsWireError):
            dnsproto.decode_name(b"\x05short", 0)


class QueryBuildTests(unittest.TestCase):
    def test_query_has_one_question_and_edns_by_default(self):
        packet = dnsproto.build_query("example.com", dnsproto.QTYPE_A, 0xABCD)
        msg = dnsproto.parse_message(packet, parse_answers=False)
        self.assertEqual(msg.query_id, 0xABCD)
        self.assertEqual(msg.qdcount, 1)
        self.assertEqual(msg.arcount, 1)  # the OPT pseudo-RR
        self.assertEqual(msg.questions[0].name, "example.com.")
        self.assertEqual(msg.questions[0].qtype, dnsproto.QTYPE_A)
        self.assertTrue(msg.flags & dnsproto.FLAG_RD)

    def test_query_without_edns(self):
        packet = dnsproto.build_query("example.com", dnsproto.QTYPE_AAAA, 1, edns=False)
        msg = dnsproto.parse_message(packet, parse_answers=False)
        self.assertEqual(msg.arcount, 0)

    def test_query_id_is_masked_to_16_bits(self):
        packet = dnsproto.build_query("example.com", dnsproto.QTYPE_A, 0x1FFFF)
        msg = dnsproto.parse_message(packet, parse_answers=False)
        self.assertEqual(msg.query_id, 0xFFFF)


class ResponseRoundTripTests(unittest.TestCase):
    """Build a response the way stub_upstream.py does, then parse it back."""

    def _query_and_question_bytes(self, name: str, qtype: int) -> tuple[bytes, bytes]:
        query = dnsproto.build_query(name, qtype, 42, edns=False)
        _, _, _, _, _, question_end = dnsproto.parse_question_only(query)
        return query, query[12:question_end]

    def test_a_response_round_trips(self):
        query, question = self._query_and_question_bytes("example.com", dnsproto.QTYPE_A)
        rr = dnsproto.build_answer_rr(0x0C, dnsproto.QTYPE_A, 300, dnsproto.a_rdata("203.0.113.7"))
        header = dnsproto.build_response_header(42, dnsproto.FLAG_RD, dnsproto.RCODE_NOERROR, 1)
        response = header + question + rr

        msg = dnsproto.parse_message(response)
        self.assertEqual(msg.query_id, 42)
        self.assertTrue(msg.is_response)
        self.assertEqual(msg.rcode, dnsproto.RCODE_NOERROR)
        self.assertEqual(len(msg.answers), 1)
        answer = msg.answers[0]
        self.assertEqual(answer.rtype, dnsproto.QTYPE_A)
        self.assertEqual(answer.text, "203.0.113.7")
        self.assertEqual(answer.name, "example.com.")
        self.assertEqual(answer.ttl, 300)

    def test_aaaa_response_carries_no_a_records(self):
        # This is the shape of the AAAA-after-A correctness check run.py
        # performs against the real server: the cache key must include
        # qtype, or an AAAA query after a cached A query would wrongly
        # return the A answer.
        query, question = self._query_and_question_bytes("example.com", dnsproto.QTYPE_AAAA)
        rr = dnsproto.build_answer_rr(0x0C, dnsproto.QTYPE_AAAA, 300, dnsproto.aaaa_rdata("2001:db8::1"))
        header = dnsproto.build_response_header(42, dnsproto.FLAG_RD, dnsproto.RCODE_NOERROR, 1)
        response = header + question + rr

        msg = dnsproto.parse_message(response)
        self.assertEqual(msg.questions[0].qtype, dnsproto.QTYPE_AAAA)
        self.assertEqual(msg.answers_of_type(dnsproto.QTYPE_A), [])
        self.assertEqual(len(msg.answers_of_type(dnsproto.QTYPE_AAAA)), 1)

    def test_cname_chain_round_trips(self):
        query, question = self._query_and_question_bytes("probe.cname.test", dnsproto.QTYPE_A)
        cname_rr = dnsproto.build_answer_rr(0x0C, dnsproto.QTYPE_CNAME, 300, dnsproto.encode_qname("target-1.blocked.test"))
        a_rr = dnsproto.build_answer_rr_for_name("target-1.blocked.test", dnsproto.QTYPE_A, 300, dnsproto.a_rdata("203.0.113.9"))
        header = dnsproto.build_response_header(42, dnsproto.FLAG_RD, dnsproto.RCODE_NOERROR, 2)
        response = header + question + cname_rr + a_rr

        msg = dnsproto.parse_message(response)
        self.assertEqual(len(msg.answers), 2)
        cname_answer, a_answer = msg.answers
        self.assertEqual(cname_answer.rtype, dnsproto.QTYPE_CNAME)
        self.assertEqual(cname_answer.text, "target-1.blocked.test.")
        self.assertEqual(a_answer.rtype, dnsproto.QTYPE_A)
        self.assertEqual(a_answer.name, "target-1.blocked.test.")
        self.assertEqual(a_answer.text, "203.0.113.9")

    def test_nxdomain_response_has_no_answers(self):
        query, question = self._query_and_question_bytes("blocked.example", dnsproto.QTYPE_A)
        header = dnsproto.build_response_header(42, dnsproto.FLAG_RD, dnsproto.RCODE_NXDOMAIN, 0)
        response = header + question
        msg = dnsproto.parse_message(response)
        self.assertEqual(msg.rcode, dnsproto.RCODE_NXDOMAIN)
        self.assertEqual(msg.answers, [])

    def test_truncated_packet_raises_rather_than_returns_garbage(self):
        query, question = self._query_and_question_bytes("example.com", dnsproto.QTYPE_A)
        rr = dnsproto.build_answer_rr(0x0C, dnsproto.QTYPE_A, 300, dnsproto.a_rdata("203.0.113.7"))
        header = dnsproto.build_response_header(42, dnsproto.FLAG_RD, dnsproto.RCODE_NOERROR, 1)
        response = (header + question + rr)[:-2]  # chop off the last 2 bytes of rdata
        with self.assertRaises(dnsproto.DnsWireError):
            dnsproto.parse_message(response)


class StableHashTests(unittest.TestCase):
    def test_deterministic_across_calls(self):
        self.assertEqual(dnsproto.stable_hash_mod("example.com", 250), dnsproto.stable_hash_mod("example.com", 250))

    def test_case_insensitive(self):
        self.assertEqual(dnsproto.stable_hash_mod("Example.COM", 250), dnsproto.stable_hash_mod("example.com", 250))

    def test_stays_in_range(self):
        for name in ("a.com", "b.com", "very-long-subdomain-name.example.org", ""):
            value = dnsproto.stable_hash_mod(name, 250)
            self.assertTrue(0 <= value < 250)

    def test_rejects_non_positive_modulus(self):
        with self.assertRaises(ValueError):
            dnsproto.stable_hash_mod("example.com", 0)


class StubResponseBuilderTests(unittest.TestCase):
    """Exercises stub_upstream.build_response directly (no socket involved)."""

    def setUp(self):
        # Imported lazily so a bug that breaks module import in
        # stub_upstream.py (e.g. only reachable via argparse/CLI code) still
        # lets the rest of this suite run.
        import stub_upstream

        self.stub_upstream = stub_upstream

    def test_a_query_gets_one_a_answer_in_test_net_3(self):
        query = dnsproto.build_query("example.com", dnsproto.QTYPE_A, 7)
        response = self.stub_upstream.build_response(query)
        msg = dnsproto.parse_message(response)
        self.assertEqual(msg.query_id, 7)
        self.assertEqual(len(msg.answers), 1)
        answer = msg.answers[0]
        self.assertEqual(answer.rtype, dnsproto.QTYPE_A)
        self.assertTrue(answer.text.startswith("203.0.113."))
        self.assertEqual(answer.ttl, 300)

    def test_same_name_gets_same_answer_every_time(self):
        query = dnsproto.build_query("stable.example", dnsproto.QTYPE_A, 1)
        first = dnsproto.parse_message(self.stub_upstream.build_response(query)).answers[0].text
        second = dnsproto.parse_message(self.stub_upstream.build_response(query)).answers[0].text
        self.assertEqual(first, second)

    def test_aaaa_query_gets_documentation_prefix(self):
        query = dnsproto.build_query("example.com", dnsproto.QTYPE_AAAA, 7)
        response = self.stub_upstream.build_response(query)
        msg = dnsproto.parse_message(response)
        self.assertEqual(len(msg.answers), 1)
        answer = msg.answers[0]
        self.assertEqual(answer.rtype, dnsproto.QTYPE_AAAA)
        self.assertTrue(answer.text.startswith("2001:db8::"))

    def test_cname_test_name_gets_cname_plus_a_target(self):
        query = dnsproto.build_query("probe.cname.test", dnsproto.QTYPE_A, 9)
        response = self.stub_upstream.build_response(query)
        msg = dnsproto.parse_message(response)
        self.assertEqual(len(msg.answers), 2)
        cname, a_record = msg.answers
        self.assertEqual(cname.rtype, dnsproto.QTYPE_CNAME)
        self.assertTrue(cname.text.startswith("target-"))
        self.assertTrue(cname.text.endswith(".blocked.test."))
        self.assertEqual(a_record.rtype, dnsproto.QTYPE_A)
        self.assertEqual(a_record.name, cname.text)

    def test_apex_cname_test_itself_is_also_cloaked(self):
        query = dnsproto.build_query("cname.test", dnsproto.QTYPE_A, 9)
        response = self.stub_upstream.build_response(query)
        msg = dnsproto.parse_message(response)
        self.assertEqual(msg.answers[0].rtype, dnsproto.QTYPE_CNAME)

    def test_unhandled_qtype_gets_empty_noerror(self):
        query = dnsproto.build_query("example.com", 16, 5)  # TXT
        response = self.stub_upstream.build_response(query)
        msg = dnsproto.parse_message(response)
        self.assertEqual(msg.rcode, dnsproto.RCODE_NOERROR)
        self.assertEqual(msg.answers, [])

    def test_garbage_input_is_dropped_not_raised(self):
        self.assertIsNone(self.stub_upstream.build_response(b"not a dns packet"))

    def test_response_echoes_the_question_verbatim(self):
        query = dnsproto.build_query("example.com", dnsproto.QTYPE_A, 3, edns=True)
        response = self.stub_upstream.build_response(query)
        msg = dnsproto.parse_message(response)
        self.assertEqual(msg.questions[0].name, "example.com.")
        self.assertEqual(msg.questions[0].qtype, dnsproto.QTYPE_A)


class PercentileTests(unittest.TestCase):
    def test_known_values_nearest_rank(self):
        # 1..100: the 50th percentile by nearest-rank (ceil(0.50*100)=50th
        # smallest, 1-indexed) is 50; the 99th is 99.
        samples = list(range(1, 101))
        self.assertEqual(stats.percentile(samples, 50), 50)
        self.assertEqual(stats.percentile(samples, 99), 99)
        self.assertEqual(stats.percentile(samples, 100), 100)
        self.assertEqual(stats.percentile(samples, 0), 1)

    def test_single_sample(self):
        self.assertEqual(stats.percentile([42.0], 50), 42.0)
        self.assertEqual(stats.percentile([42.0], 99), 42.0)

    def test_unsorted_input_is_handled(self):
        self.assertEqual(stats.percentile([5, 1, 3, 2, 4], 50), 3)

    def test_rejects_empty_input(self):
        with self.assertRaises(ValueError):
            stats.percentile([], 50)

    def test_rejects_out_of_range_percentile(self):
        with self.assertRaises(ValueError):
            stats.percentile([1, 2, 3], 101)
        with self.assertRaises(ValueError):
            stats.percentile([1, 2, 3], -1)

    def test_small_sample_p99_is_the_max(self):
        # With only 3 samples, ceil(0.99*3) = 3 -- the 99th percentile of a
        # tiny sample is its worst observation, which is the honest answer.
        self.assertEqual(stats.percentile([10, 20, 30], 99), 30)


class SummarizeTests(unittest.TestCase):
    def test_summary_fields(self):
        summary = stats.summarize([1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertEqual(summary.count, 5)
        self.assertEqual(summary.min, 1.0)
        self.assertEqual(summary.max, 5.0)
        self.assertEqual(summary.mean, 3.0)
        self.assertEqual(summary.p50, 3.0)

    def test_to_dict_round_trips_through_json(self):
        import json

        summary = stats.summarize([1.0, 2.0, 3.0])
        encoded = json.dumps(summary.to_dict())
        decoded = json.loads(encoded)
        self.assertEqual(decoded["count"], 3)
        self.assertIn("p99", decoded)

    def test_rejects_empty_input(self):
        with self.assertRaises(ValueError):
            stats.summarize([])

    def test_scaled_converts_units(self):
        self.assertEqual(stats.scaled([1.0, 2.0], 1000.0), [1000.0, 2000.0])


if __name__ == "__main__":
    unittest.main()
