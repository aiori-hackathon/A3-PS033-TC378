"""Integration tests use actual DNS packets, signatures, TLS, and HTTP."""
import socket
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import dns.message
import dns.query
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec

import lab
from diagnostics import HealthCollectionError


def available_ports():
    # Hold three consecutive TCP sockets until we have found a free block.
    for base in range(23000, 30000, 4):
        sockets = []
        try:
            for port in range(base, base+4):
                sock = socket.socket()
                sockets.append(sock)
                sock.bind(("127.0.0.1", port))
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockets.append(udp)
            udp.bind(("127.0.0.1", base))
            return base, base+1
        except OSError:
            continue
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError("No test ports available")


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        lab.provision(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def scenario(self, name, expected):
        dns_port, base_port = available_ports()
        with lab.laboratory(self.root, name, dns_port, base_port):
            result = lab.discover("latency", self.root, dns_port, name == "unauthorized")
        self.assertEqual(result["status"], expected, result)
        return result

    def test_all_three_services_over_real_dns_and_tls(self):
        dns_port, base_port = available_ports()
        with lab.laboratory(self.root, "valid", dns_port, base_port):
            for service in lab.SERVICES:
                with self.subTest(service=service):
                    result = lab.discover(service, self.root, dns_port)
                    self.assertEqual(result["status"], "SUCCESS", result)
                    self.assertEqual(result["data"]["mock"], service != "health")
                    self.assertEqual(result["data"]["service"], service)
                    if service == "health":
                        self.assertEqual(result["data"]["provenance"]["scope"], "diagnostic_service_host")
                        self.assertGreater(result["data"]["result"]["memory_total_bytes"], 0)
            # Independent TCP query verifies the DNS listener's second transport.
            reply = dns.query.tcp(dns.message.make_query(lab.owner("latency"), "SVCB", want_dnssec=True),
                "127.0.0.1", port=dns_port, timeout=2)
            self.assertEqual(len(reply.answer), 2)

    def test_modified_record_fails_before_invocation(self):
        self.assertEqual(self.scenario("bogus", "DNSSEC_BOGUS")["events"], [])

    def test_sample_health_preserves_three_mock_service_demo_without_collection(self):
        dns_port, base_port = available_ports()
        with patch("lab.collect_health") as collect:
            with lab.laboratory(self.root, "valid", dns_port, base_port, health_mode="sample"):
                for service in lab.SERVICES:
                    result = lab.discover(service, self.root, dns_port)
                    self.assertEqual(result["status"], "SUCCESS", result)
                    self.assertIs(result["data"]["mock"], True)
                    self.assertEqual(result["data"]["result"], lab.RESULTS[service])
            collect.assert_not_called()

    def test_health_authentication_failure_never_collects(self):
        dns_port, base_port = available_ports()
        with patch("lab.collect_health") as collect:
            with lab.laboratory(self.root, "valid", dns_port, base_port):
                result = lab.discover("health", self.root, dns_port, bad_token=True)
            collect.assert_not_called()
        self.assertEqual(result["status"], "AUTHENTICATION_DENIED", result)
        self.assertEqual(result["trace"][-1]["status"], "not_run")

    def test_unverified_health_dns_never_collects(self):
        dns_port, base_port = available_ports()
        with patch("lab.collect_health") as collect:
            with lab.laboratory(self.root, "expired", dns_port, base_port):
                result = lab.discover("health", self.root, dns_port)
            collect.assert_not_called()
        self.assertEqual(result["status"], "DNSSEC_BOGUS", result)
        self.assertFalse(result["invocation_attempted"])

    def test_health_collection_failure_is_clean_and_retryable(self):
        dns_port, base_port = available_ports()
        with patch("lab.collect_health", side_effect=HealthCollectionError("private OS path")) as collect:
            with lab.laboratory(self.root, "valid", dns_port, base_port):
                result = lab.discover("health", self.root, dns_port)
            collect.assert_called_once_with()
        self.assertEqual(result["status"], "SERVICE_ERROR", result)
        self.assertEqual(result["trace"][-2]["status"], "passed")
        self.assertEqual(result["trace"][-1]["status"], "failed")
        self.assertNotIn("private OS path", json.dumps(result))
        self.assertNotIn("data", result)

    def test_signed_malformed_metadata_is_not_a_dnssec_failure(self):
        result = self.scenario("malformed", "METADATA_INVALID")
        self.assertEqual(len(result["events"]), 1)

    def test_unavailable_service_after_valid_discovery(self):
        result = self.scenario("unavailable", "SERVICE_UNAVAILABLE")
        self.assertEqual(len(result["events"]), 3)

    def test_dns_discovery_does_not_grant_authorization(self):
        result = self.scenario("unauthorized", "AUTHENTICATION_DENIED")
        self.assertEqual(len(result["events"]), 4)

    def test_expired_signature_rejected(self):
        self.scenario("expired", "DNSSEC_BOGUS")

    def test_unsigned_response_rejected(self):
        self.scenario("unsigned", "DNSSEC_UNVERIFIED")

    def test_wrong_trust_anchor_rejected(self):
        dns_port, base_port = available_ports()
        anchor_path = self.root / "trust-anchor.txt"
        original = anchor_path.read_text()
        with lab.laboratory(self.root, "valid", dns_port, base_port):
            try:
                key = ec.generate_private_key(ec.SECP256R1())
                anchor_path.write_text(lab.dns.dnssec.make_dnskey(key.public_key(), "ECDSAP256SHA256", flags=257).to_text())
                self.assertEqual(lab.discover("latency", self.root, dns_port)["status"], "DNSSEC_BOGUS")
            finally:
                anchor_path.write_text(original)

    def test_signed_address_tampering_is_rejected(self):
        dns_port, _ = available_ports()
        zone = lab.publish(self.root)
        zone.replace_rdataset(lab.owner("latency"),
            dns.rrset.from_text(lab.owner("latency"), 30, "IN", "A", "127.0.0.2"))
        with lab.dns_servers(zone, "valid", dns_port):
            result = lab.discover("latency", self.root, dns_port)
        self.assertEqual(result["status"], "DNSSEC_BOGUS", result)
        self.assertEqual(len(result["events"]), 2)

    def test_unknown_mandatory_parameter_rejected(self):
        record = dns.rrset.from_text(lab.owner("latency"), 30, "IN", "SVCB",
            '1 . mandatory=alpn,port,key65280,key65281,key65282 alpn="http/1.1" '
            'port=18443 key65280="latency" key65281="/invoke" key65282="x"')
        with self.assertRaises(lab.LabError) as raised:
            lab.metadata(record, "latency")
        self.assertEqual(raised.exception.code, "METADATA_INVALID")

    def test_a_different_services_token_cannot_invoke_latency(self):
        dns_port, base_port = available_ports()
        token_path = self.root / "tokens.json"
        original = token_path.read_text()
        with lab.laboratory(self.root, "valid", dns_port, base_port):
            try:
                tokens = json.loads(original)
                tokens["latency"] = tokens["health"]
                token_path.write_text(json.dumps(tokens))
                result = lab.discover("latency", self.root, dns_port)
                self.assertEqual(result["status"], "AUTHENTICATION_DENIED", result)
            finally:
                token_path.write_text(original)

    def test_untrusted_tls_certificate_blocks_credentials(self):
        dns_port, base_port = available_ports()
        certificate_path = self.root / "tls-cert.pem"
        original = certificate_path.read_bytes()
        with tempfile.TemporaryDirectory() as other:
            lab.provision(Path(other))
            with lab.laboratory(self.root, "valid", dns_port, base_port):
                try:
                    certificate_path.write_bytes((Path(other) / "tls-cert.pem").read_bytes())
                    result = lab.discover("latency", self.root, dns_port)
                    self.assertEqual(result["status"], "TLS_REJECTED", result)
                    self.assertEqual(len(result["events"]), 3)
                finally:
                    certificate_path.write_bytes(original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
