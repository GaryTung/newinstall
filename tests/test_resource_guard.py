import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import resource_guard as guard


def meminfo(total_mib=954, available_mib=371):
    return (
        f"MemTotal:       {int(total_mib * 1024)} kB\n"
        "MemFree:        100 kB\n"
        f"MemAvailable:   {int(available_mib * 1024)} kB\n"
        "Buffers:        100 kB\n"
    )


class ResourceGuardTests(unittest.TestCase):
    def test_uses_memavailable_not_free_or_used(self):
        allowed, reason = guard.background_work_allowed(meminfo_text=meminfo())
        self.assertTrue(allowed)
        self.assertIn("371.0 MiB", reason)

    def test_default_admission_boundary(self):
        for available, expected in ((191, False), (192, True), (193, True)):
            with self.subTest(available=available):
                allowed, _ = guard.background_work_allowed(meminfo_text=meminfo(954, available))
                self.assertEqual(allowed, expected)

    def test_custom_admission_boundary(self):
        self.assertFalse(guard.background_work_allowed(384, meminfo_text=meminfo())[0])
        self.assertTrue(guard.background_work_allowed(256, meminfo_text=meminfo())[0])

    def test_low_memory_reason_preserves_health_checks(self):
        allowed, reason = guard.background_work_allowed(meminfo_text=meminfo(954, 100))
        self.assertFalse(allowed)
        self.assertIn("100.0 MiB", reason)
        self.assertIn("192 MiB", reason)
        self.assertIn("现有出口健康检查不受影响", reason)

    def test_low_memory_probe_concurrency_is_one(self):
        for total in (512, 954, 1024, 1536):
            for requested in (1, 2, 5, 100):
                with self.subTest(total=total, requested=requested):
                    self.assertEqual(guard.recommended_probe_workers(requested, meminfo_text=meminfo(total, 200)), 1)

    def test_large_memory_probe_concurrency_honors_bounded_request(self):
        for requested, expected in ((0, 1), (1, 1), (2, 2), (5, 5), (100, 5)):
            with self.subTest(requested=requested):
                self.assertEqual(guard.recommended_probe_workers(requested, meminfo_text=meminfo(1537)), expected)

    def test_invalid_requested_workers_default_to_two_on_large_host(self):
        for requested in (None, "bad", float("inf")):
            with self.subTest(requested=requested):
                self.assertEqual(guard.recommended_probe_workers(requested, meminfo_text=meminfo(4096)), 2)

    def test_default_workers_two_on_large_host(self):
        self.assertEqual(guard.recommended_probe_workers(meminfo_text=meminfo(4096)), 2)

    def test_unreadable_meminfo_denies_optional_work_and_caps_workers(self):
        with patch.object(Path, "read_text", side_effect=OSError("access denied")):
            allowed, reason = guard.background_work_allowed()
            self.assertFalse(allowed)
            self.assertIn("无法可靠读取可用内存", reason)
            self.assertIn("access denied", reason)
            self.assertEqual(guard.recommended_probe_workers(5), 1)

    def test_real_reader_uses_expected_path_and_encoding(self):
        with patch.object(Path, "read_text", return_value=meminfo()) as reader:
            self.assertTrue(guard.background_work_allowed()[0])
            reader.assert_called_once_with(encoding="ascii")
        self.assertEqual(str(guard.MEMINFO_PATH).replace("\\", "/"), "/proc/meminfo")

    def test_missing_invalid_duplicate_or_inconsistent_values_fail_closed(self):
        invalid = [
            "", "MemTotal: 1000 kB\n", "MemAvailable: 100 kB\n",
            "MemTotal: many kB\nMemAvailable: 100 kB\n",
            "MemTotal: 1000 MB\nMemAvailable: 100 kB\n",
            "MemTotal: 1000 kB\nMemAvailable: 100 kB extra\n",
            "MemTotal: 0 kB\nMemAvailable: 0 kB\n",
            "MemTotal: 1000 kB\nMemAvailable: -1 kB\n",
            "MemTotal: 1000 kB\nMemAvailable: 1001 kB\n",
            meminfo() + "MemAvailable: 100 kB\n",
        ]
        for text in invalid:
            with self.subTest(text=text):
                self.assertFalse(guard.background_work_allowed(meminfo_text=text)[0])
                self.assertEqual(guard.recommended_probe_workers(5, meminfo_text=text), 1)

    def test_zero_available_is_valid_but_denied(self):
        allowed, reason = guard.background_work_allowed(meminfo_text=meminfo(954, 0))
        self.assertFalse(allowed)
        self.assertIn("低于安全门槛", reason)

    def test_invalid_memory_threshold_fails_closed(self):
        for value in (-1, 0, None, "bad", float("nan"), float("inf")):
            with self.subTest(value=value):
                allowed, reason = guard.background_work_allowed(value, meminfo_text=meminfo())
                self.assertFalse(allowed)
                self.assertIn("内存门槛无效", reason)

    def test_injected_text_does_not_touch_filesystem(self):
        with patch.object(Path, "read_text", side_effect=AssertionError("unexpected IO")):
            self.assertTrue(guard.background_work_allowed(meminfo_text=meminfo())[0])
            self.assertEqual(guard.recommended_probe_workers(5, meminfo_text=meminfo()), 1)


if __name__ == "__main__":
    unittest.main()
