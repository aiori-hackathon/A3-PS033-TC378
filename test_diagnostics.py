"""Validate real measurements and the response trust boundary."""
import io
import json
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import diagnostics
import lab


class Response(io.BytesIO):
    def __init__(self, raw, headers=None):
        super().__init__(raw)
        self.headers = {"Content-Type": "application/json", **(headers or {})}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


class HealthTests(unittest.TestCase):
    def test_actual_measurement_is_bounded_and_contains_no_inventory(self):
        start = time.monotonic()
        data = diagnostics.collect_health()
        self.assertGreaterEqual(time.monotonic() - start, 0.1)
        self.assertIs(data["mock"], False)
        self.assertEqual(data["result"]["status"], "observed")
        self.assertGreater(data["result"]["memory_total_bytes"], 0)
        self.assertGreaterEqual(data["result"]["uptime_seconds"], 0)
        self.assertEqual(diagnostics.validate_health(data), data)
        self.assertLess(len(json.dumps(data)), 2048)
        for private_field in ("hostname", "processes", "username", "ip_address"):
            self.assertNotIn(private_field, json.dumps(data))

    def test_os_error_and_impossible_samples_fail_closed(self):
        with patch("diagnostics.psutil.cpu_percent", side_effect=OSError("private path")):
            with self.assertRaisesRegex(diagnostics.HealthCollectionError, "temporarily unavailable"):
                diagnostics.collect_health()
        memory = SimpleNamespace(percent=50, total=1000, available=500)
        for cpu in (float("nan"), float("inf"), -1, 101, True):
            with self.subTest(cpu=cpu), patch("diagnostics.psutil.cpu_percent", return_value=cpu), patch("diagnostics.psutil.virtual_memory", return_value=memory):
                with self.assertRaises(diagnostics.HealthCollectionError):
                    diagnostics.collect_health()

    def test_cpu_uses_blocking_sample_and_memory_has_portable_definition(self):
        memory = SimpleNamespace(percent=25.0, total=1000, available=750, used=999)
        with patch("diagnostics.psutil.cpu_percent", return_value=12.0) as cpu, patch("diagnostics.psutil.virtual_memory", return_value=memory), patch("diagnostics.psutil.boot_time", return_value=time.time() - 123):
            data = diagnostics.collect_health()
        cpu.assert_called_once_with(interval=0.25)
        self.assertEqual(data["result"]["memory_used_bytes"], 250)
        self.assertAlmostEqual(data["result"]["uptime_seconds"], 123, delta=2)


class ResponseTests(unittest.TestCase):
    def test_rejects_oversize_body_with_and_without_content_length(self):
        raw = b"x" * (lab.MAX_RESPONSE_BYTES + 1)
        for headers in ({}, {"Content-Length": str(len(raw))}):
            with self.subTest(headers=headers), self.assertRaises(lab.LabError) as raised:
                lab.read_diagnostic_response(Response(raw, headers), "health")
            self.assertEqual(raised.exception.code, "SERVICE_RESPONSE_INVALID")

    def test_rejects_wrong_service_nonfinite_values_and_false_provenance(self):
        payloads = [
            {"service": "traceroute", "mock": True, "result": {"hops": ["192.0.2.1"]}},
            {"service": "latency", "mock": True, "result": {"round_trip_ms": float("nan"), "packet_loss_percent": 0}},
            {"service": "latency", "mock": False, "result": {"round_trip_ms": 1, "packet_loss_percent": 0}},
        ]
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(lab.LabError):
                lab.read_diagnostic_response(Response(json.dumps(payload).encode()), "latency")

    def test_rejects_wrong_media_type_truncation_and_private_fields(self):
        payload = {"service": "latency", "mock": True, "result": {"round_trip_ms": 1, "packet_loss_percent": 0}}
        raw = json.dumps(payload).encode()
        for headers in ({"Content-Type": "text/html"}, {"Content-Length": str(len(raw) + 1)}):
            with self.subTest(headers=headers), self.assertRaises(lab.LabError):
                lab.read_diagnostic_response(Response(raw, headers), "latency")
        payload["hostname"] = "must-not-leak"
        with self.assertRaises(lab.LabError):
            lab.read_diagnostic_response(Response(json.dumps(payload).encode()), "latency")


if __name__ == "__main__":
    unittest.main(verbosity=2)
