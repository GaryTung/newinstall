import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CreateChannelResponseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "vpngate_manager.py").read_text(encoding="utf-8")

    def test_create_reads_text_before_parsing_json(self):
        match = re.search(
            r"async function createMultiExitChannel\(\)\{(.*?)\n\}",
            self.source,
            re.S,
        )
        self.assertIsNotNone(match)
        function = match.group(1)
        self.assertIn("const responseText=await r.text()", function)
        self.assertNotIn("await r.json()", function)

    def test_empty_or_interrupted_response_reconciles_server_state(self):
        self.assertIn("async function confirmCreatedChannel(id,port)", self.source)
        self.assertGreaterEqual(self.source.count("await confirmCreatedChannel(id,port)"), 2)
        self.assertIn("c.id===id||Number(c.inbound_port||0)===port", self.source)

    def test_http_response_is_flushed(self):
        send_bytes = re.search(
            r"def send_bytes\(.*?\n\s+def send_json",
            self.source,
            re.S,
        )
        self.assertIsNotNone(send_bytes)
        self.assertIn("self.wfile.flush()", send_bytes.group(0))


if __name__ == "__main__":
    unittest.main()
