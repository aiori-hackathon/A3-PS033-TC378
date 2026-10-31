"""Bounded, signed inventory for the private ``diag.test.`` laboratory.

This is a project-specific PTR-to-SVCB profile: ``_diagnostics.diag.test.``
contains PTRs to single-label SVCB owners in the same provisioned zone. It is
NOT RFC 6763 DNS-SD, which uses service-type PTRs with instance SRV/TXT records,
and cannot enumerate arbitrary diagnostic services on the Internet or LAN.

Only DNS is queried, always through lab.validated_query and its loopback
transport / locally installed trust anchor. Inventory readiness means that
the signed SVCB and local metadata policy passed; address, TLS, credentials,
service availability, and diagnostic results remain untested here.
"""
from __future__ import annotations

import re
import time

import dns.name
import dns.exception
import dns.rdatatype
import dns.rrset


ZONE_NAME = dns.name.from_text("diag.test.")
INDEX_NAME = "_diagnostics.diag.test."
MAX_SERVICES = 32
MAX_QUERIES = 1 + MAX_SERVICES
TOTAL_TIMEOUT_SECONDS = 8.0
MAX_RECORD_TEXT = 4096
_LABEL = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)


def _service_label(name):
    """Reject delegates, arbitrary domains, nested labels and escaped names."""
    if not name.is_absolute() or len(name.labels) != len(ZONE_NAME.labels) + 1 or name.parent() != ZONE_NAME:
        raise ValueError("Index targets must be single-label owners inside diag.test.")
    try:
        label = name.labels[0].decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Index target label must be an ASCII service name") from exc
    if not _LABEL.fullmatch(label):
        raise ValueError("Index target label is outside the local service-name profile")
    return label


def add_index(zone):
    """Publish every SVCB owner, before signing; reject oversized/invalid zones."""
    if zone.origin != ZONE_NAME:
        raise ValueError("The private inventory profile requires the diag.test. zone")
    targets = set()
    for name, node in zone.nodes.items():
        if node.get_rdataset(zone.rdclass, dns.rdatatype.SVCB):
            absolute = name.derelativize(zone.origin).canonicalize()
            _service_label(absolute)
            targets.add(absolute.to_text())
            if len(targets) > MAX_SERVICES:
                raise ValueError(f"The private inventory is limited to {MAX_SERVICES} services")
    if not targets:
        raise ValueError("A diagnostic inventory requires at least one SVCB service")
    index = dns.rrset.from_text(INDEX_NAME, 30, "IN", "PTR", *sorted(targets))
    zone.replace_rdataset(INDEX_NAME, index)
    return index


def discover_index(root, dns_port):
    """Verify an index, then inspect its entries without invoking any service.

    At most 33 signed queries and eight seconds of DNS transport are allowed.
    dnspython can spend its timeout once on UDP and once on TCP fallback, so
    each query receives at most half the remaining total time. Each signature
    is validated before its contents influence subsequent queries.
    """
    # Local imports avoid a publisher -> inventory -> lab import cycle.
    from lab import LabError, SERVICES, metadata, validated_query

    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    queries = 0
    result = {
        "status": "VERIFIED",
        "detail": "Signed private index verified; entries inspect DNS metadata only. No service was invoked.",
        "index_name": INDEX_NAME,
        "record": None,
        "entries": [],
        "invocation_attempted": False,
    }

    def query(name, rdtype):
        nonlocal queries
        remaining = deadline - time.monotonic()
        if queries >= MAX_QUERIES or remaining <= 0:
            raise LabError("INVENTORY_LIMIT", "The inventory query or time budget was exhausted")
        queries += 1
        answer = validated_query(name, rdtype, root, dns_port, timeout=min(2.0, remaining / 2))
        if time.monotonic() > deadline:
            raise LabError("INVENTORY_LIMIT", "The inventory time budget was exhausted")
        return answer

    try:
        index = query(INDEX_NAME, "PTR")
        # Never follow a partial or malformed index, even if its signature passed.
        if not 1 <= len(index) <= MAX_SERVICES:
            raise LabError("INVENTORY_LIMIT", f"The index must contain 1–{MAX_SERVICES} service targets")
        result["record"] = index.to_text()
        names = {}
        for record in index:
            label = _service_label(record.target)
            name = record.target.canonicalize().to_text()
            names[name] = label
    except LabError as exc:
        result.update(status=exc.code, detail=exc.detail)
        return result
    except (ValueError, AttributeError, UnicodeError):
        result.update(status="INVENTORY_INVALID", detail="The signed index contains a target outside the local service-name policy")
        return result
    except (OSError, dns.exception.DNSException):
        result.update(status="SETUP_ERROR", detail="The locally provisioned inventory trust material could not be read")
        return result

    for name, service in sorted(names.items()):
        entry = {"name": name, "service": service, "capability": None,
                 "status": "METADATA_INVALID", "detail": "", "record": None}
        result["entries"].append(entry)
        try:
            record = query(name, "SVCB")
            public_record = record.to_text()
            if len(public_record) > MAX_RECORD_TEXT:
                raise LabError("METADATA_INVALID", "The service metadata exceeds the local size limit")
            entry["record"] = public_record
            # This applies the same ServiceMode, mandatory key, ALPN, endpoint,
            # port and capability/name checks used before normal invocation.
            host, port, path = metadata(record, service)
            entry["capability"] = service
            if service not in SERVICES:
                entry.update(status="UNSUPPORTED", detail="Signed metadata is valid, but this application has no invocation adapter for this capability")
                continue
            entry.update(status="READY", detail="Signed metadata accepted; address, TLS, authentication and measurements have not been checked",
                         endpoint=f"https://{host.rstrip('.')}:{port}{path}")
        except LabError as exc:
            entry.update(status=exc.code, detail=exc.detail)
        except (ValueError, AttributeError, UnicodeError):
            entry.update(status="METADATA_INVALID", detail="Service metadata is outside the private inventory profile")
        except (OSError, dns.exception.DNSException):
            entry.update(status="SETUP_ERROR", detail="The locally provisioned inventory trust material could not be read")
    if any(entry["status"] == "INVENTORY_LIMIT" for entry in result["entries"]):
        result.update(status="INVENTORY_LIMIT", detail="The signed index was verified, but the query or time budget prevented a complete inventory")
    return result
