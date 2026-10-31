"""Private inventory integration tests: real DNS, signed enumeration, no HTTP."""
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
import dns.dnssec
import dns.rrset
import dns.zone

import dns_inventory as inventory
import lab


class InventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        lab.provision(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def zone(self, services=lab.SERVICES, *, targets=None, expired=False, replacements=None):
        lines = [f"$ORIGIN {lab.ZONE}", "$TTL 30",
                 f"@ IN SOA ns.{lab.ZONE} hostmaster.{lab.ZONE} 1 60 30 3600 30",
                 f"@ IN NS ns.{lab.ZONE}", "ns IN A 127.0.0.1"]
        for index, service in enumerate(services):
            lines.append(f'{service} IN SVCB 1 . mandatory=alpn,port,key65280,key65281 '
                         f'alpn="http/1.1" port={18443+index} key65280="{service}" key65281="/invoke"')
        zone = dns.zone.from_text("\n".join(lines), origin=lab.ZONE, relativize=False)
        if replacements:
            for service, text in replacements.items():
                zone.replace_rdataset(lab.owner(service), dns.rrset.from_text(lab.owner(service), 30, "IN", "SVCB", text))
        if targets is None:
            inventory.add_index(zone)
        else:
            zone.replace_rdataset(inventory.INDEX_NAME,
                                  dns.rrset.from_text(inventory.INDEX_NAME, 30, "IN", "PTR", *targets))
        key = serialization.load_pem_private_key((self.root / "zone-key.pem").read_bytes(), password=None)
        dnskey = dns.dnssec.make_dnskey(key.public_key(), "ECDSAP256SHA256", flags=257)
        now = int(time.time())
        dns.dnssec.sign_zone(zone, keys=[(key, dnskey)], inception=now-3600,
                            expiration=now-60 if expired else now+86400)
        return zone

    def inspect(self, zone, scenario="valid"):
        with lab.dns_servers(zone, scenario, 0) as port:
            with patch("lab.validated_query", wraps=lab.validated_query) as queries:
                with patch("lab.http.client.HTTPSConnection") as http:
                    result = inventory.discover_index(self.root, port)
                    http.assert_not_called()
                return result, queries.call_args_list

    def test_signed_enumeration_and_supported_services_without_invocation(self):
        result, queries = self.inspect(self.zone())
        self.assertEqual(result["status"], "VERIFIED", result)
        self.assertIs(result["invocation_attempted"], False)
        self.assertEqual({item["service"] for item in result["entries"]}, set(lab.SERVICES))
        self.assertTrue(all(item["status"] == "READY" for item in result["entries"]))
        self.assertEqual(len(queries), 4)
        self.assertEqual([call.args[1] for call in queries], ["PTR", "SVCB", "SVCB", "SVCB"])
        for entry in result["entries"]:
            self.assertIn("have not been checked", entry["detail"])
            self.assertIn(entry["name"], entry["record"])
        tokens = json.loads((self.root / "tokens.json").read_text())
        self.assertFalse(any(token in json.dumps(result) for token in tokens.values()))

    def test_new_service_is_enumerated_but_never_given_an_invocation_endpoint(self):
        result, queries = self.inspect(self.zone((*lab.SERVICES, "bandwidth")))
        entry = next(item for item in result["entries"] if item["service"] == "bandwidth")
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(entry["status"], "UNSUPPORTED")
        self.assertEqual(entry["capability"], "bandwidth")
        self.assertNotIn("endpoint", entry)
        self.assertEqual(len(queries), 5)

    def test_tampered_index_fails_closed_before_target_queries(self):
        zone = self.zone()
        zone.replace_rdataset(inventory.INDEX_NAME,
                              dns.rrset.from_text(inventory.INDEX_NAME, 30, "IN", "PTR", "health.diag.test."))
        result, queries = self.inspect(zone)
        self.assertEqual(result["status"], "DNSSEC_BOGUS")
        self.assertEqual(result["entries"], [])
        self.assertIsNone(result["record"])
        self.assertEqual(len(queries), 1)

    def test_unsigned_and_expired_indexes_fail_closed(self):
        for scenario, expired, status in [("unsigned", False, "DNSSEC_UNVERIFIED"),
                                          ("valid", True, "DNSSEC_BOGUS")]:
            with self.subTest(scenario=scenario):
                result, queries = self.inspect(self.zone(expired=expired), scenario)
                self.assertEqual(result["status"], status)
                self.assertEqual(result["entries"], [])
                self.assertEqual(len(queries), 1)

    def test_invalid_signed_index_targets_are_rejected_before_any_target_query(self):
        for bad_target in ["health.other.test.", "nested.health.diag.test.", "diag.test.", "_health.diag.test.", "."]:
            with self.subTest(target=bad_target):
                zone = self.zone(targets=["latency.diag.test.", bad_target])
                result, queries = self.inspect(zone)
                self.assertEqual(result["status"], "INVENTORY_INVALID", result)
                self.assertEqual(result["entries"], [])
                self.assertEqual(len(queries), 1)

    def test_target_deduplication_uses_case_insensitive_dns_names(self):
        result, queries = self.inspect(self.zone(targets=["health.diag.test.", "HEALTH.DIAG.TEST."]))
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(len(result["entries"]), 1)
        self.assertEqual(result["entries"][0]["status"], "READY")
        self.assertEqual(len(queries), 2)

    def test_index_and_publisher_enforce_service_limit(self):
        services = [f"service-{index}" for index in range(inventory.MAX_SERVICES + 1)]
        with self.assertRaisesRegex(ValueError, "limited to 32"):
            self.zone(services)
        result, queries = self.inspect(self.zone(targets=[lab.owner(service) for service in services]))
        self.assertEqual(result["status"], "INVENTORY_LIMIT")
        self.assertEqual(result["entries"], [])
        self.assertEqual(len(queries), 1)

    def test_bad_service_does_not_hide_other_verified_entries(self):
        zone = self.zone()
        zone.replace_rdataset(lab.owner("health"),
                              dns.rrset.from_text(lab.owner("health"), 30, "IN", "SVCB", '1 . alpn="http/1.1" port=19999'))
        result, queries = self.inspect(zone)
        statuses = {item["service"]: item["status"] for item in result["entries"]}
        self.assertEqual(result["status"], "VERIFIED")
        self.assertEqual(statuses, {"health": "DNSSEC_BOGUS", "latency": "READY", "traceroute": "READY"})
        self.assertEqual(len(queries), 4)

    def test_exactly_32_services_fit_the_query_budget(self):
        services = [f"service-{index}" for index in range(inventory.MAX_SERVICES)]
        result, queries = self.inspect(self.zone(services))
        self.assertEqual(result["status"], "VERIFIED", result)
        self.assertEqual(len(result["entries"]), 32)
        self.assertTrue(all(entry["status"] == "UNSUPPORTED" for entry in result["entries"]))
        self.assertEqual(len(queries), 33)

    def test_signed_invalid_metadata_is_not_ready_or_unsupported(self):
        bad_records = {
            "health": '1 . mandatory=alpn,port,key65280,key65281 alpn="http/1.1" port=18443 key65280="latency" key65281="/invoke"',
            "bandwidth": '1 external.example. mandatory=alpn,port,key65280,key65281 alpn="http/1.1" port=18444 key65280="bandwidth" key65281="/invoke"',
        }
        result, _ = self.inspect(self.zone(["health", "bandwidth"], replacements=bad_records))
        self.assertTrue(all(entry["status"] == "METADATA_INVALID" for entry in result["entries"]))
        self.assertTrue(all("endpoint" not in entry for entry in result["entries"]))

    def test_total_deadline_stops_further_queries(self):
        index = dns.rrset.from_text(inventory.INDEX_NAME, 30, "IN", "PTR", *[lab.owner(s) for s in lab.SERVICES])
        clock = Mock()
        clock.monotonic.side_effect = [0, 0, 0, 9, 9, 9]
        with patch("dns_inventory.time", clock), patch("lab.validated_query", return_value=index) as query:
            result = inventory.discover_index(self.root, 15353)
        self.assertEqual(result["status"], "INVENTORY_LIMIT")
        self.assertEqual(query.call_count, 1)
        self.assertTrue(all(entry["status"] == "INVENTORY_LIMIT" for entry in result["entries"]))
        self.assertLessEqual(query.call_args.kwargs["timeout"], inventory.TOTAL_TIMEOUT_SECONDS / 2)

    def test_query_budget_never_sends_additional_dns_requests(self):
        with patch("dns_inventory.MAX_QUERIES", 2):
            result, queries = self.inspect(self.zone())
        self.assertEqual(result["status"], "INVENTORY_LIMIT")
        self.assertEqual(len(queries), 2)
        self.assertEqual(sum(entry["status"] == "READY" for entry in result["entries"]), 1)

    def test_publisher_hook_signs_the_dynamic_index(self):
        result, _ = self.inspect(lab.publish(self.root))
        self.assertEqual(result["status"], "VERIFIED", result)
        self.assertEqual(len(result["entries"]), len(lab.SERVICES))


if __name__ == "__main__":
    unittest.main(verbosity=2)
