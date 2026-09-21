import concurrent.futures
import socket
import struct
import sys
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proxy_server as proxy


def wire_name(name):
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"


def dns_response(host="example.org", qtype=1, records=None, flags=0x8180):
    records = records if records is not None else [(host, 1, 60, socket.inet_aton("192.0.2.1"))]
    data = b"\x12\x34" + struct.pack("!HHHHH", flags, 1, len(records), 0, 0)
    data += wire_name(host) + struct.pack("!HH", qtype, 1)
    for name, kind, ttl, body in records:
        data += (b"\xc0\x0c" if name == host else wire_name(name))
        data += struct.pack("!HHIH", kind, 1, ttl, len(body)) + body
    return data


class DNSAnswerTests(unittest.TestCase):
    def parse(self, packet, qtype=1):
        return proxy._parse_dns_answer(packet, b"\x12\x34", "example.org", qtype)

    def test_a_and_aaaa_preserve_ttl(self):
        self.assertEqual(self.parse(dns_response()), ("192.0.2.1", 60))
        ipv6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        packet = dns_response(qtype=28, records=[("example.org", 28, 17, ipv6)])
        self.assertEqual(self.parse(packet, 28), ("2001:db8::1", 17))

    def test_cname_ttl_caps_final_answer_and_ignores_unrelated_answers(self):
        packet = dns_response(records=[
            ("unrelated.org", 1, 300, socket.inet_aton("203.0.113.3")),
            ("example.org", 5, 11, wire_name("alias.org")),
            ("alias.org", 5, 7, wire_name("target.org")),
            ("target.org", 1, 90, socket.inet_aton("192.0.2.2")),
        ])
        self.assertEqual(self.parse(packet), ("192.0.2.2", 7))

    def test_rrset_uses_shortest_ttl(self):
        packet = dns_response(records=[
            ("example.org", 1, 300, socket.inet_aton("192.0.2.1")),
            ("example.org", 1, 5, socket.inet_aton("192.0.2.2")),
        ])
        self.assertEqual(self.parse(packet), ("192.0.2.1", 5))

    def test_bad_response_not_accepted(self):
        for packet in [
            dns_response(flags=0x8380),  # TC / truncated
            dns_response(flags=0x8183),  # NXDOMAIN
            dns_response(flags=0x0180),  # not a response
            dns_response(host="wrong.org"),
            dns_response()[:-1],
            b"\x99\x99" + dns_response()[2:],
            dns_response(records=[("other.org", 1, 60, socket.inet_aton("192.0.2.1"))]),
        ]:
            with self.subTest(packet=packet):
                self.assertIsNone(self.parse(packet))

    def test_cname_and_compression_loops_do_not_hang(self):
        packet = dns_response(records=[("example.org", 5, 30, wire_name("example.org"))])
        self.assertIsNone(self.parse(packet))
        with self.assertRaises(ValueError):
            proxy._read_dns_name(b"\xc0\x00", 0)

    def test_high_bit_ttl_treated_as_zero(self):
        packet = dns_response(records=[("example.org", 1, 0xFFFFFFFF, socket.inet_aton("192.0.2.1"))])
        self.assertEqual(self.parse(packet), ("192.0.2.1", 0))

    def test_wire_query_still_binds_to_tunnel_and_expected_resolver(self):
        sock = MagicMock()
        packet = dns_response()
        sock.recv.return_value = packet
        with patch.object(proxy.socket, "socket", return_value=sock):
            with patch.object(proxy.socket, "SO_BINDTODEVICE", 25, create=True):
                with patch.object(proxy.secrets, "token_bytes", return_value=b"\x12\x34"):
                    self.assertEqual(proxy._query_dns_over_tun0("example.org", 1, "8.8.8.8", 3),
                                     ("192.0.2.1", 60))
        sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, 25, b"tun0")
        sock.connect.assert_called_once_with(("8.8.8.8", 53))
        sock.close.assert_called_once()

    def test_wire_query_does_not_send_if_tunnel_binding_fails(self):
        sock = MagicMock()
        sock.setsockopt.side_effect = OSError("binding failed")
        with patch.object(proxy.socket, "socket", return_value=sock):
            with patch.object(proxy.socket, "SO_BINDTODEVICE", 25, create=True):
                self.assertIsNone(proxy._query_dns_over_tun0("example.org", 1, "8.8.8.8", 3))
        sock.connect.assert_not_called()
        sock.send.assert_not_called()
        sock.close.assert_called_once()


class DNSFingerprintTests(unittest.TestCase):
    def test_fingerprint_includes_namespace_interface_flags_and_addresses(self):
        def ioctl(fd, operation, request):
            if operation == 0x8913:
                return bytes(16) + struct.pack("H", 1) + bytes(238)
            return bytes(20) + socket.inet_aton("10.0.0.2") + bytes(232)
        namespace = types.SimpleNamespace(st_dev=7, st_ino=44)
        fake_fcntl = types.SimpleNamespace(ioctl=ioctl)
        ipv6 = "20010db8000000000000000000000001 05 40 00 80 tun0\n"
        with patch.dict(sys.modules, {"fcntl": fake_fcntl}):
            with patch.object(proxy.os, "stat", return_value=namespace):
                with patch.object(proxy.socket, "if_nametoindex", return_value=5, create=True):
                    with patch.object(proxy.socket, "socket", return_value=MagicMock()):
                        with patch("builtins.open", mock_open(read_data=ipv6)):
                            scope = proxy._dns_cache_scope()
        self.assertEqual(scope[1:], (7, 44, 5, 1, socket.inet_aton("10.0.0.2"),
                                     ("20010db8000000000000000000000001",)))

    def test_interface_down_disables_cache(self):
        fake_fcntl = types.SimpleNamespace(ioctl=lambda *args: bytes(256))
        with patch.dict(sys.modules, {"fcntl": fake_fcntl}):
            with patch.object(proxy.os, "stat", return_value=types.SimpleNamespace(st_dev=7, st_ino=44)):
                with patch.object(proxy.socket, "if_nametoindex", return_value=5, create=True):
                    with patch.object(proxy.socket, "socket", return_value=MagicMock()):
                        self.assertIsNone(proxy._dns_cache_scope())


class DNSCacheTests(unittest.TestCase):
    def setUp(self):
        self.cache = proxy._DNSCache(2, 300)
        self.scope = (100, "namespace-a", 5, b"10.0.0.1")
        self.cache_patch = patch.object(proxy, "_dns_cache", self.cache)
        self.scope_patch = patch.object(proxy, "_dns_cache_scope", return_value=self.scope)
        self.cache_patch.start()
        self.scope_mock = self.scope_patch.start()
        self.addCleanup(self.cache_patch.stop)
        self.addCleanup(self.scope_patch.stop)

    def query(self, host="example.org", qtype=1, server="8.8.8.8"):
        return proxy.dns_query_over_tun0(host, qtype, server, 0.5)

    def test_cache_hit_case_normalization_and_expiry(self):
        with patch.object(proxy, "_query_dns_over_tun0", return_value=("192.0.2.1", 5)) as query:
            with patch.object(proxy.time, "monotonic", return_value=100):
                self.assertEqual(self.query(), "192.0.2.1")
            with patch.object(proxy.time, "monotonic", return_value=104):
                self.assertEqual(self.query("EXAMPLE.ORG."), "192.0.2.1")
                self.assertEqual(query.call_count, 1)
            with patch.object(proxy.time, "monotonic", return_value=105):
                self.query()
                self.assertEqual(query.call_count, 2)

    def test_ttl_is_capped_and_lru_capacity_bounded(self):
        with patch.object(proxy, "_query_dns_over_tun0", return_value=("192.0.2.1", 7200)) as query:
            with patch.object(proxy.time, "monotonic", return_value=100):
                for host in ("a.org", "b.org", "a.org", "c.org"):
                    self.query(host)
                self.assertEqual(len(self.cache.entries), 2)
                self.assertNotIn(("b.org", 1, "8.8.8.8"), self.cache.entries)
                self.assertEqual({v[0] for v in self.cache.entries.values()}, {400})
            with patch.object(proxy.time, "monotonic", return_value=400):
                self.query("a.org")
                self.assertEqual(query.call_count, 4)

    def test_failures_and_zero_ttl_are_not_cached(self):
        for answer in (None, ("192.0.2.1", 0)):
            with patch.object(proxy, "_query_dns_over_tun0", return_value=answer) as query:
                self.query()
                self.query()
                self.assertEqual(query.call_count, 2)
                self.assertFalse(self.cache.entries)

    def test_namespace_address_change_and_missing_tunnel_clear_cache(self):
        with patch.object(proxy, "_query_dns_over_tun0", return_value=("192.0.2.1", 300)) as query:
            self.query()
            self.scope_mock.return_value = (100, "namespace-b", 5, b"10.0.0.1")
            self.query()
            self.scope_mock.return_value = (100, "namespace-b", 5, b"10.0.0.2")
            self.query()
            self.scope_mock.return_value = None
            self.query()
            self.query()
            self.assertEqual(query.call_count, 5)
            self.assertFalse(self.cache.entries)

    def test_result_during_exit_change_is_not_cached(self):
        def query(*args):
            self.scope_mock.return_value = (101, "namespace-b", 8, b"10.0.1.1")
            return "192.0.2.1", 300
        with patch.object(proxy, "_query_dns_over_tun0", side_effect=query):
            self.query()
            self.assertFalse(self.cache.entries)

    def test_dns_servers_are_isolated(self):
        with patch.object(proxy, "_query_dns_over_tun0", return_value=("192.0.2.1", 30)) as query:
            self.query()
            self.query(server="1.1.1.1")
            self.assertEqual(query.call_count, 2)

    def test_cached_aaaa_avoids_repeating_failed_a_query(self):
        def query(host, qtype, *args):
            return ("2001:db8::1", 60) if qtype == 28 else None
        with patch.object(proxy, "_query_dns_over_tun0", side_effect=query) as query_mock:
            self.assertEqual(proxy.resolve_dns_over_tun0("example.org"), "2001:db8::1")
            self.assertEqual(proxy.resolve_dns_over_tun0("example.org"), "2001:db8::1")
            self.assertEqual(query_mock.call_count, 2)

    def test_literal_ips_need_no_dns(self):
        with patch.object(proxy, "_query_dns_over_tun0") as query:
            self.assertEqual(proxy.resolve_dns_over_tun0("192.0.2.1"), "192.0.2.1")
            self.assertEqual(proxy.resolve_dns_over_tun0("2001:db8::1"), "2001:db8::1")
            query.assert_not_called()

    def test_zero_cache_size_bypasses_cache_and_fingerprint(self):
        with patch.object(proxy, "DNS_CACHE_MAX_ENTRIES", 0), \
             patch.object(proxy, "_dns_cache_scope", side_effect=AssertionError("cache fingerprint used")), \
             patch.object(proxy, "_query_dns_over_tun0", return_value=("192.0.2.1", 300)) as query:
            self.assertEqual(proxy.resolve_dns_over_tun0("example.org"), "192.0.2.1")
            self.assertEqual(proxy.resolve_dns_over_tun0("example.org"), "192.0.2.1")
            self.assertEqual(query.call_count, 2)

    def test_simultaneous_requests_share_one_wire_query(self):
        started = threading.Event()
        release = threading.Event()
        reserved = threading.Event()
        original_begin = self.cache.begin
        def begin(*args):
            result = original_begin(*args)
            if result[1] is not None and not result[2]:
                reserved.set()
            return result
        def query(*args):
            started.set()
            self.assertTrue(release.wait(2))
            return "192.0.2.1", 30
        with patch.object(proxy, "_query_dns_over_tun0", side_effect=query) as query_mock:
            with patch.object(self.cache, "begin", side_effect=begin):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(self.query)
                    self.assertTrue(started.wait(2))
                    second = pool.submit(self.query)
                    self.assertTrue(reserved.wait(2))
                    release.set()
                    self.assertEqual(first.result(), "192.0.2.1")
                    self.assertEqual(second.result(), "192.0.2.1")
            self.assertEqual(query_mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()
