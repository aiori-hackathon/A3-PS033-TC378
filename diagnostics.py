"""Minimal host measurements; no process, user, address, or hostname inventory."""
from datetime import datetime, timezone
import math
import time

import psutil


CPU_SAMPLE_SECONDS = 0.25


class HealthCollectionError(Exception):
    """An operating-system measurement was unavailable or inconsistent."""


def bounded_number(value, minimum, maximum):
    return (type(value) in (int, float) and math.isfinite(value)
            and minimum <= value <= maximum)


def validate_health(data):
    """Check the complete profile so neither invalid values nor inventory leaks pass."""
    if set(data) != {"service", "mock", "schema_version", "provenance", "result"}:
        raise ValueError("Unexpected health response fields")
    if data["service"] != "health" or data["mock"] is not False or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unexpected health response profile")
    metrics = data["result"]
    fields = {"status", "cpu_percent", "memory_percent", "memory_total_bytes",
              "memory_available_bytes", "memory_used_bytes", "uptime_seconds"}
    if not isinstance(metrics, dict) or set(metrics) != fields or metrics["status"] != "observed":
        raise ValueError("Invalid health measurement fields")
    if not all(bounded_number(metrics[key], 0, 100) for key in ("cpu_percent", "memory_percent")):
        raise ValueError("Invalid health percentage")
    for key in ("memory_total_bytes", "memory_available_bytes", "memory_used_bytes"):
        if type(metrics[key]) is not int or not 0 <= metrics[key] <= 2**63-1:
            raise ValueError("Invalid memory measurement")
    total = metrics["memory_total_bytes"]
    available = metrics["memory_available_bytes"]
    if total <= 0 or available > total or metrics["memory_used_bytes"] != total - available:
        raise ValueError("Inconsistent memory measurement")
    if abs(metrics["memory_percent"] - (total - available) / total * 100) > 0.2:
        raise ValueError("Inconsistent memory percentage")
    if not bounded_number(metrics["uptime_seconds"], 0, 100 * 366 * 24 * 3600):
        raise ValueError("Invalid host uptime")
    provenance = data["provenance"]
    if (not isinstance(provenance, dict) or set(provenance) !=
            {"source", "scope", "measured_at", "cpu_sample_seconds"}):
        raise ValueError("Missing measurement provenance")
    if provenance["source"] != "psutil" or provenance["scope"] != "diagnostic_service_host":
        raise ValueError("Unsupported measurement source")
    if not bounded_number(provenance["cpu_sample_seconds"], 0.1, 1):
        raise ValueError("Invalid CPU sample interval")
    timestamp = provenance["measured_at"]
    if not isinstance(timestamp, str) or len(timestamp) > 40 or not timestamp.endswith("Z"):
        raise ValueError("Invalid measurement timestamp")
    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return data


def collect_health():
    """Take one bounded CPU sample and a memory/uptime snapshot on the service host.

    `used` is defined as total minus available across operating systems. This
    matches psutil's percentage, rather than platform-dependent `vm.used`.
    CPU load is an observation, not a hardware or application health verdict.
    In Docker these are the operating-system/VM counters exposed by psutil,
    not container cgroup usage or quota and not necessarily the physical laptop.
    """
    try:
        cpu = psutil.cpu_percent(interval=CPU_SAMPLE_SECONDS)
        memory = psutil.virtual_memory()
        uptime = time.time() - psutil.boot_time()
        data = {
            "service": "health", "mock": False, "schema_version": 1,
            "provenance": {
                "source": "psutil", "scope": "diagnostic_service_host",
                "measured_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "cpu_sample_seconds": CPU_SAMPLE_SECONDS,
            },
            "result": {
                "status": "observed", "cpu_percent": cpu,
                "memory_percent": memory.percent,
                "memory_total_bytes": memory.total,
                "memory_available_bytes": memory.available,
                "memory_used_bytes": memory.total - memory.available,
                "uptime_seconds": round(uptime, 3),
            },
        }
        return validate_health(data)
    except (psutil.Error, OSError, ValueError, TypeError, AttributeError, OverflowError) as exc:
        # Callers return a stable error; OS messages can contain sensitive paths.
        raise HealthCollectionError("Host measurements are temporarily unavailable") from exc
