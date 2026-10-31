"""Exercise the browser API against real DNS, DNSSEC, TLS and HTTP servers."""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch

import dashboard
import lab


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = dashboard.DemoServer(("127.0.0.1", 0))
        cls.context = lab.running(cls.server)
        cls.context.__enter__()
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)

    def request(self, path, method="GET", payload=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            connection.request(method, path, body=json.dumps(payload) if payload is not None else None,
                headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def post(self, scenario, service="all"):
        return self.request("/api/run", "POST", {"scenario": scenario, "service": service},
            {"Content-Type": "application/json", "X-Demo-Token": self.server.request_token})

    def test_all_scenarios_through_api(self):
        for scenario in dashboard.SCENARIOS:
            with self.subTest(scenario=scenario):
                status, body, _ = self.post(scenario)
                self.assertEqual(status, 200, body)
                data = json.loads(body)
                self.assertEqual(len(data["results"]), 3)
                self.assertTrue(all(r["matches_expected"] for r in data["results"]), data)
                for row in data["results"]:
                    self.assertEqual(len(row["trace"]), 6)
                    if row["status"] == "SUCCESS":
                        self.assertTrue(row["invocation_attempted"])
                        self.assertTrue(all(s["status"] == "passed" for s in row["trace"]))
                    else:
                        self.assertEqual(sum(s["status"] == "failed" for s in row["trace"]), 1)
                        self.assertEqual(row["invocation_attempted"], scenario == "unauthorized")
                    self.assertGreater(row["elapsed_ms"], 0)
                for secret in (b"PRIVATE KEY", b"Bearer ", b"tokens.json"):
                    self.assertNotIn(secret, body)

    def test_fault_targets_the_selected_service(self):
        for service in ("traceroute", "health"):
            for scenario in ("bogus", "malformed", "unauthorized", "unavailable"):
                with self.subTest(service=service, scenario=scenario):
                    status, body, _ = self.post(scenario, service)
                    self.assertEqual(status, 200, body)
                    result = json.loads(body)["results"]
                    self.assertEqual(len(result), 1)
                    self.assertTrue(result[0]["matches_expected"], result)
                    self.assertEqual(result[0]["service"], service)

    def test_only_public_assets_are_served(self):
        for route in ("/", "/app.js", "/style.css"):
            status, body, headers = self.request(route)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertIn("Content-Security-Policy", headers)
        for route in ("/.runtime/tokens.json", "/../lab.py", "/lab.py"):
            self.assertEqual(self.request(route)[0], 404)

    def test_loading_assets_and_readiness_does_not_exhaust_operation_limit(self):
        for _ in range(25):
            status, _, headers = self.request("/api/health")
            self.assertEqual(status, 200)
            self.assertNotIn("Strict-Transport-Security", headers)
            self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_another_dashboard_cannot_claim_active_port(self):
        with self.assertRaises(OSError):
            dashboard.DemoServer(("127.0.0.1", self.port))

    def test_rejects_cross_origin_and_missing_token(self):
        self.assertEqual(self.request("/api/config", headers={"Host": "attacker.example"})[0], 403)
        self.assertEqual(self.request("/api/config", headers={"Origin": "https://attacker.example"})[0], 403)
        self.assertEqual(self.request("/api/run", "POST", {"scenario": "valid", "service": "all"})[0], 403)
        self.assertEqual(self.request("/api/run", "POST", {"scenario": "valid", "service": "all"},
            {"Origin": "https://attacker.example", "Content-Type": "application/json", "X-Demo-Token": self.server.request_token})[0], 403)

    def test_rejects_invalid_parameters_and_busy_lab(self):
        self.assertEqual(self.post("unknown")[0], 400)
        self.assertEqual(self.post("valid", "https://example.com")[0], 400)
        with self.server.run_lock:
            self.assertEqual(self.post("valid")[0], 409)

    def test_automatic_dns_port_retries_a_tcp_collision(self):
        original = lab.socketserver.ThreadingTCPServer.server_bind
        attempts = []
        def bind(server):
            attempts.append(server.server_address)
            if len(attempts) == 1:
                raise OSError("Simulated TCP port reservation")
            return original(server)
        with patch.object(lab.socketserver.ThreadingTCPServer, "server_bind", bind):
            result = dashboard.run_demo("valid", "latency")
        self.assertEqual(result["results"][0]["status"], "SUCCESS")
        self.assertGreaterEqual(len(attempts), 2)

    def test_live_and_sample_health_api(self):
        for mode in ("live", "sample"):
            status, body, _ = self.request("/api/run", "POST",
                {"scenario": "valid", "service": "health", "health_mode": mode},
                {"Content-Type": "application/json", "X-Demo-Token": self.server.request_token})
            self.assertEqual(status, 200, body)
            data = json.loads(body)
            self.assertEqual(data["health_mode"], mode)
            result = data["results"][0]["data"]
            self.assertEqual(result["mock"], mode == "sample")
            if mode == "live":
                self.assertGreater(result["result"]["memory_total_bytes"], 0)
                self.assertIn("measured_at", result["provenance"])

    def test_inventory_only_queries_signed_dns(self):
        with patch.object(lab, "service_server", side_effect=AssertionError("Must not start services")), \
                patch.object(lab, "discover", side_effect=AssertionError("Must not invoke services")):
            status, body, _ = self.request("/api/inventory", "POST", {},
                {"Content-Type": "application/json", "X-Demo-Token": self.server.request_token})
        self.assertEqual(status, 200, body)
        inventory = json.loads(body)["inventory"]
        self.assertEqual(inventory["status"], "VERIFIED")
        self.assertFalse(inventory["invocation_attempted"])
        self.assertEqual({entry["service"] for entry in inventory["entries"]}, set(lab.SERVICES))
        self.assertTrue(all(entry["status"] == "READY" for entry in inventory["entries"]))

    def test_inventory_requires_token_and_cannot_select_external_domain(self):
        self.assertEqual(self.request("/api/inventory", "POST", {})[0], 403)
        self.assertEqual(self.request("/api/inventory", "POST", {},
            {"Content-Type": "application/json", "X-Demo-Token": "é"})[0], 403)
        headers = {"Content-Type": "application/json", "X-Demo-Token": self.server.request_token}
        self.assertEqual(self.request("/api/inventory", "POST", {"domain": "example.com"}, headers)[0], 400)
        with self.server.run_lock:
            self.assertEqual(self.request("/api/inventory", "POST", {}, headers)[0], 409)
        self.assertEqual(self.request("/api/run", "POST", {"scenario": "valid", "service": "health", "health_mode": "invalid"}, headers)[0], 400)

    def test_udp_collision_releases_tcp_before_retry(self):
        original = lab.socketserver.ThreadingUDPServer.server_bind
        attempts = []
        def bind(server):
            attempts.append(server.server_address)
            if len(attempts) == 1:
                raise OSError("Simulated UDP reservation")
            return original(server)
        with patch.object(lab.socketserver.ThreadingUDPServer, "server_bind", bind):
            self.assertEqual(dashboard.run_demo("valid", "latency")["results"][0]["status"], "SUCCESS")
        with lab.socket.socket() as probe:
            probe.bind(attempts[0])

    def test_rejects_ambiguous_http_framing_and_duplicate_host(self):
        for extra, body in (("Content-Length: 2\r\nContent-Length: 3\r\n", b"{}"),
                            ("Content-Length: 2\r\nTransfer-Encoding: chunked\r\n", b"{}"),
                            (f"Host: localhost:{self.port}\r\nContent-Length: 2\r\n", b"{}")):
            connection = lab.socket.create_connection(("127.0.0.1", self.port), timeout=3)
            with connection:
                wire = (f"POST /api/inventory HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                    f"X-Demo-Token: {self.server.request_token}\r\nContent-Type: application/json\r\n{extra}\r\n").encode() + body
                connection.sendall(wire)
                self.assertIn(connection.recv(4096).split(b" ")[1], (b"400", b"403"))


class DashboardConfigurationTests(unittest.TestCase):
    @staticmethod
    def request(server, path="/api/health", *, method="GET", headers=None, body=None, context=None, host="127.0.0.1"):
        if context:
            connection = http.client.HTTPSConnection(host, server.server_port, context=context, timeout=3)
        else:
            connection = http.client.HTTPConnection(host, server.server_port, timeout=3)
        try:
            connection.request(method, path, headers=headers or {}, body=body)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def test_rate_limit_returns_json_and_recovers_without_blocking_readiness(self):
        now = [0.0]
        with dashboard.DemoServer(("127.0.0.1", 0)) as server:
            server.rate_limiter = dashboard.OperationLimiter(rate=1, burst=1, clock=lambda: now[0])
            headers = {"Content-Type": "application/json", "X-Demo-Token": server.request_token}
            body = json.dumps({"scenario": "valid", "service": "health"})
            with lab.running(server), patch.object(dashboard, "run_demo", return_value={"result": "ok"}) as run:
                self.assertEqual(self.request(server, "/api/run", method="POST", headers=headers, body=body)[0], 200)
                status, response, response_headers = self.request(server, "/api/run", method="POST", headers=headers, body=body)
                self.assertEqual(status, 429)
                self.assertIn("error", json.loads(response))
                self.assertEqual(response_headers["Retry-After"], "1")
                self.assertEqual(run.call_count, 1)
                self.assertEqual(self.request(server)[0], 200)
                now[0] = 1.0
                self.assertEqual(self.request(server, "/api/run", method="POST", headers=headers, body=body)[0], 200)
                self.assertEqual(run.call_count, 2)

    def test_invalid_environment_tokens_fail_cleanly_and_valid_token_is_used(self):
        for token in ("", "short", "é"*32, "a"*31+"\n", "a"*257):
            with self.subTest(length=len(token)), patch.dict(os.environ, {"DEMO_TOKEN": token}):
                with self.assertRaisesRegex(ValueError, "DEMO_TOKEN"):
                    dashboard.DemoServer(("127.0.0.1", 0))
        with patch.dict(os.environ, {"DEMO_TOKEN": "a"*32}):
            with dashboard.DemoServer(("127.0.0.1", 0)) as server:
                self.assertEqual(server.request_token, "a"*32)

    def test_https_verifies_local_identities_and_enforces_https_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            context = dashboard.local_tls_context(directory)
            certificate = Path(directory) / "https_cert.pem"
            original = certificate.read_bytes()
            dashboard.local_tls_context(directory)
            self.assertEqual(certificate.read_bytes(), original)
            client = ssl.create_default_context(cafile=str(certificate))
            with dashboard.DemoServer(("127.0.0.1", 0), tls_context=context) as server, lab.running(server):
                port = server.server_port
                for host in ("localhost", "127.0.0.1"):
                    self.assertEqual(self.request(server, context=client, host=host)[0], 200)
                headers = {"Origin": f"https://127.0.0.1:{port}", "Content-Type": "application/json",
                    "X-Demo-Token": server.request_token}
                with patch.object(dashboard, "run_inventory", return_value={"inventory": "verified"}):
                    self.assertEqual(self.request(server, "/api/inventory", method="POST", headers=headers, body="{}", context=client)[0], 200)
                headers["Origin"] = f"http://127.0.0.1:{port}"
                self.assertEqual(self.request(server, "/api/inventory", method="POST", headers=headers, body="{}", context=client)[0], 403)
                # A connected peer that never begins TLS must not stall accept().
                with socket.create_connection(("127.0.0.1", port), timeout=3):
                    self.assertEqual(self.request(server, context=client)[0], 200)

    def test_partial_tls_files_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "https_key.pem"
            key.write_text("keep the original key", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "Incomplete dashboard TLS"):
                dashboard.local_tls_context(directory)
            self.assertEqual(key.read_text(encoding="ascii"), "keep the original key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
