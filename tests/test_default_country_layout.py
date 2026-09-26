import ast
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DefaultCountryLayoutTests(unittest.TestCase):
    def test_fresh_install_defaults_to_japan_and_korea_hy2(self):
        source = (ROOT / "install-multi-exit.sh").read_text(encoding="utf-8")
        match = re.search(r"cat > \"\$\{CHANNEL_FILE\}\" <<EOF\n(.*?)\nEOF", source, re.S)
        self.assertIsNotNone(match)
        rendered = match.group(1).replace("${install_date}", "20260926").replace("${install_epoch}", "1790380800")
        config = json.loads(rendered)
        channels = config["channels"]
        self.assertEqual([item["country"] for item in channels], ["日本", "韩国"])
        self.assertEqual([item["protocol"] for item in channels], ["hysteria", "hysteria"])
        self.assertEqual([item["inbound_port"] for item in channels], [7866, 7888])

    def test_manager_fallback_matches_fresh_install(self):
        tree = ast.parse((ROOT / "multi_exit_manager.py").read_text(encoding="utf-8"))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "default_config")
        returned = next(node.value for node in function.body if isinstance(node, ast.Return))
        config = ast.literal_eval(returned)
        channels = config["channels"]
        self.assertEqual([(item["country"], item["protocol"], item["inbound_port"]) for item in channels], [
            ("日本", "hysteria", 7866),
            ("韩国", "hysteria", 7888),
        ])


if __name__ == "__main__":
    unittest.main()
