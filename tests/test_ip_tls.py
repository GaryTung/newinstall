import ast
import json
import re
import unittest
import urllib.parse
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "vpngate_manager.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCTION = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
                and node.name == "normalize_ip_literal_client_tls")
NAMESPACE = {"re": re, "json": json, "urllib": urllib}
exec(compile(ast.Module(body=[FUNCTION], type_ignores=[]), "ip-tls-test", "exec"), NAMESPACE)
normalize = NAMESPACE[FUNCTION.name]


class IPLiteralTLSTests(unittest.TestCase):
    def test_trojan_removes_ech_preserves_credentials_port_name_and_pin(self):
        original = "trojan://p%40ss%3Aword@161.33.194.236:11488?security=tls&ech=config%2Bvalue&alpn=h2%2Chttp%2F1.1&pinSHA256=ABC%2BDEF&sni=&allowInsecure=0#236.%E6%97%A5%E6%9C%AC"
        expected = "trojan://p%40ss%3Aword@161.33.194.236:11488?security=tls&alpn=h2%2Chttp%2F1.1&pinSHA256=ABC%2BDEF&allowInsecure=0&sni=161.33.194.236#236.%E6%97%A5%E6%9C%AC"
        self.assertEqual(normalize(original, "universal", "161.33.194.236"), expected)

    def test_vless_tls_missing_sni_gets_ip_without_disabling_verification(self):
        original = "vless://UUID@161.33.194.236:35262?security=tls&encryption=none&ech=broken#name"
        result = normalize(original, "universal", "161.33.194.236")
        self.assertEqual(result, "vless://UUID@161.33.194.236:35262?security=tls&encryption=none&sni=161.33.194.236#name")
        self.assertNotIn("insecure", result.lower())

    def test_existing_nonempty_sni_preserved(self):
        original = "trojan://secret@161.33.194.236:443?ech=bad&sni=cert.example&alpn=h2"
        self.assertEqual(normalize(original, "universal", "161.33.194.236"), original.replace("ech=bad&", ""))

    def test_ipv6_brackets_and_port_preserved(self):
        original = "vless://UUID@[2001:db8::12]:443?security=tls&ECH=bad&sni=#ipv6"
        result = normalize(original, "universal", "[2001:db8::12]")
        self.assertEqual(result, "vless://UUID@[2001:db8::12]:443?security=tls&sni=2001%3Adb8%3A%3A12#ipv6")

    def test_domain_reality_non_tls_other_protocol_and_malformed_unchanged(self):
        for original in (
            "trojan://secret@vpn.example:443?ech=config&sni=",
            "vless://UUID@161.33.194.236:443?security=reality&ech=config&sni=example.org&pbk=key",
            "vless://UUID@161.33.194.236:443?security=none&ech=config",
            "vless://UUID@161.33.194.236:443?ech=config",
            "trojan://secret@161.33.194.236:443?security=none&ech=config",
            "hysteria2://secret@161.33.194.236:443?ech=config",
            "trojan://secret@[malformed:443?ech=config",
        ):
            with self.subTest(original=original):
                self.assertEqual(normalize(original, "universal", "161.33.194.236"), original)

    def test_universal_preserves_newlines_whitespace_and_already_normalized(self):
        value = "  trojan://secret@161.33.194.236:443?sni=161.33.194.236  \r\n\r\n"
        self.assertEqual(normalize(value, "universal", "161.33.194.236"), value)

    def test_encoded_case_variant_ech_is_removed(self):
        value = "trojan://secret@161.33.194.236:443?%65CH=bad&ech=also-bad&sni="
        self.assertEqual(normalize(value, "universal", "161.33.194.236"), "trojan://secret@161.33.194.236:443?sni=161.33.194.236")

    def test_clash_removes_only_ech_subtree_and_preserves_other_nesting(self):
        value = '''proxies:
  - name: "236.jp"
    type: trojan
    server: 161.33.194.236
    port: 11488
    password: "secret:password"
    skip-cert-verify: false
    sni: ""
    ech-opts:
      enable: true
      config: "broken-config"
      nested:
        item: bad
    alpn:
      - h2
    ws-opts:
      path: /test
      headers:
        Host: example.org
    fingerprint: ABC
proxy-groups:
  - name: Proxy
    proxies: ["236.jp"]
'''
        result = normalize(value, "clash", "161.33.194.236")
        self.assertNotIn("ech-opts", result)
        self.assertNotIn("broken-config", result)
        self.assertNotIn("item: bad", result)
        self.assertIn('    sni: "161.33.194.236"\n', result)
        self.assertIn('    password: "secret:password"\n', result)
        self.assertIn("    skip-cert-verify: false\n", result)
        self.assertIn("    alpn:\n      - h2\n", result)
        self.assertIn("    ws-opts:\n      path: /test\n      headers:\n        Host: example.org\n", result)
        self.assertTrue(result.endswith('    proxies: ["236.jp"]\n'))

    def test_clash_vless_ipv6_direct_ech_and_inline_opts(self):
        value = '''proxies:
- name: node
  type: vless
  server: "2001:db8::1"
  port: 443
  uuid: unchanged
  tls: true
  servername: ''
  ech: broken
  ech-opts: {enable: true, config: broken}
  certificate: preserved
'''
        result = normalize(value, "clash", "[2001:db8::1]")
        self.assertNotIn("ech", result)
        self.assertIn('  servername: "2001:db8::1"\n', result)
        self.assertIn("  uuid: unchanged\n", result)
        self.assertIn("  certificate: preserved\n", result)

    def test_clash_domain_reality_non_tls_and_flow_yaml_unchanged(self):
        for value in (
            "proxies:\n- name: node\n  type: trojan\n  server: vpn.example\n  ech: config\n",
            "proxies:\n- name: node\n  type: vless\n  server: 161.33.194.236\n  tls: true\n  reality-opts:\n    public-key: key\n  ech: config\n",
            "proxies:\n- name: node\n  type: vless\n  server: 161.33.194.236\n  tls: false\n  ech: config\n",
            "proxies: [{name: node, type: trojan, server: 161.33.194.236, ech: config}]\n",
            "proxies:\n- name: node\n  type: trojan\n  server: *address\n  ech: config\n",
        ):
            with self.subTest(value=value):
                self.assertEqual(normalize(value, "clash", "161.33.194.236"), value)

    def test_clash_multiple_blocks_leave_domain_block_byte_identical(self):
        domain = '- name: domain\n  type: trojan\n  server: vpn.example\n  ech-opts:\n    enable: true\n    config: preserved\n'
        value = "proxies:\n- name: ip\n  type: trojan\n  server: 161.33.194.236\n  ech: bad\n" + domain
        result = normalize(value, "clash", "161.33.194.236")
        self.assertTrue(result.endswith(domain))
        self.assertNotIn("  ech: bad", result)

    def test_clash_existing_sni_pin_and_verification_values_preserved(self):
        value = "proxies:\n- name: ip\n  type: trojan\n  server: 161.33.194.236\n  sni: cert.example\n  skip-cert-verify: false\n  pinSHA256: ABC\n  ech: bad\n"
        self.assertEqual(normalize(value, "clash", "161.33.194.236"), value.replace("  ech: bad\n", ""))

    def test_clash_ambiguous_structure_is_left_unchanged(self):
        prefix = "proxies:\n- name: ip\n  type: trojan\n  server: 161.33.194.236\n"
        for suffix in (
            "  ech-opts: &opts\n    enable: true\n  ws-opts: *opts\n",
            "  ech: bad\n  <<: *settings\n",
            "  ech: bad\n  certificate: |\n    preserved cert text\n",
            "  ech: bad\n  alpn:\n  - h2\n",
            "  ech: bad\n  server: vpn.example\n",
        ):
            with self.subTest(suffix=suffix):
                value = prefix + suffix
                self.assertEqual(normalize(value, "clash", "161.33.194.236"), value)

    def test_clash_crlf_and_quoted_server_comment_preserved(self):
        value = 'proxies:\r\n- name: ip\r\n  type: trojan\r\n  server: "161.33.194.236" # endpoint\r\n  ech-opts:\r\n    enable: true\r\n    config: bad\r\n  sni: "cert.example" # unchanged\r\n'
        expected = value.replace("  ech-opts:\r\n    enable: true\r\n    config: bad\r\n", "")
        self.assertEqual(normalize(value, "clash", "161.33.194.236"), expected)

    def test_xui_applies_ip_tls_normalization_after_hysteria_normalization(self):
        node = next(item for item in TREE.body if isinstance(item, ast.FunctionDef) and item.name == "xui_node_content")
        calls = [item.func.id for item in ast.walk(node) if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)]
        self.assertLess(calls.index("normalize_hysteria2_client_tls"), calls.index("normalize_ip_literal_client_tls"))


if __name__ == "__main__":
    unittest.main()
