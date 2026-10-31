"""Local browser demo backed by the real PS-033 DNS/TLS laboratory."""
from __future__ import annotations
import argparse
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
import socket
import ssl
import tempfile
import threading
import time
from urllib.parse import urlsplit

from logging_config import configure_logging
import lab
import dns_inventory

WEB = Path(__file__).parent / "web"
SCENARIOS = {
    "valid": {"label": "Normal discovery", "description": "Discover the signed endpoint, verify its identity and invoke the service.", "expected": "SUCCESS"},
    "bogus": {"label": "Tampered DNS record", "description": "Change the selected service's record after signing. DNSSEC should stop discovery.", "expected": "DNSSEC_BOGUS"},
    "unauthorized": {"label": "Wrong access token", "description": "Discover a valid endpoint, then present an incorrect credential. The service should refuse access.", "expected": "AUTHENTICATION_DENIED"},
    "malformed": {"label": "Invalid service metadata", "description": "Sign a record with the wrong capability. A valid signature does not make its contents usable.", "expected": "METADATA_INVALID"},
    "unavailable": {"label": "Service offline", "description": "Keep valid DNS records but leave the selected service offline. Discovery alone cannot ensure availability.", "expected": "SERVICE_UNAVAILABLE"},
    "expired": {"label": "Expired signatures", "description": "Expire the zone's signatures. All services should be rejected before invocation.", "expected": "DNSSEC_BOGUS"},
    "unsigned": {"label": "Missing signatures", "description": "Omit signatures from DNS answers. All services should be rejected before invocation.", "expected": "DNSSEC_UNVERIFIED"},
    "tls": {"label": "Untrusted TLS certificate", "description": "Use a different certificate as the client's trust anchor. TLS should fail before a token is sent.", "expected": "TLS_REJECTED"},
}


def run_demo(scenario="valid", service="all", health_mode="live"):
    if scenario not in SCENARIOS or service not in (*lab.SERVICES, "all") or health_mode not in ("live", "sample"):
        raise ValueError("Choose a supported scenario and service")
    started = time.perf_counter()
    selected = lab.SERVICES if service == "all" else (service,)
    fault_service = "latency" if service == "all" else service
    # Each run owns its keys, sockets and zone. Existing CLI runtime stays intact.
    with tempfile.TemporaryDirectory(prefix="ps033-demo-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        lab.provision(root)
        ports = {}
        for name in lab.SERVICES:
            if scenario == "unavailable" and name == fault_service:
                reserved = stack.enter_context(socket.socket())
                reserved.bind(("127.0.0.1", 0))
                ports[name] = reserved.getsockname()[1]
            else:
                server = lab.service_server(name, 0, root, health_mode=health_mode)
                ports[name] = server.server_address[1]
                stack.enter_context(lab.running(server))
        if scenario == "tls":
            other = root / "different-trust"
            lab.provision(other)
            (root / "tls-cert.pem").write_bytes((other / "tls-cert.pem").read_bytes())
        zone = lab.publish(root, scenario, service_ports=ports, fault_service=fault_service)
        dns_port = stack.enter_context(lab.dns_servers(zone, scenario, 0))
        rows = []
        for name in selected:
            row = lab.discover(name, root, dns_port,
                bad_token=scenario == "unauthorized" and name == fault_service)
            affected = name == fault_service or scenario in ("expired", "unsigned", "tls")
            row["expected_status"] = SCENARIOS[scenario]["expected"] if affected else "SUCCESS"
            row["matches_expected"] = row["status"] == row["expected_status"]
            rows.append(row)
        # Only public DNS material is returned. No keys, tokens or filesystem paths.
        records = [{"service": name, "record": zone.get_rdataset(lab.owner(name), "SVCB").to_text(lab.dns.name.from_text(lab.owner(name)))}
            for name in selected]
        result = {"run_id": secrets.token_hex(4), "scenario": scenario, "selection": service, "health_mode": health_mode,
            "fault_service": fault_service, "completed_at": datetime.now(timezone.utc).isoformat(),
            "dns_port": dns_port, "zone": lab.ZONE, "results": rows, "published_records": records,
            "duration_ms": round((time.perf_counter()-started)*1000, 2),
            "scope": "Local trust anchor; real DNS, DNSSEC and TLS. Health uses live OS/VM counters when selected; latency and traceroute remain sample data."}
    return result


def run_inventory():
    """Browse published metadata without starting or invoking diagnostic services."""
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="ps033-index-") as temporary:
        root = Path(temporary)
        lab.provision(root)
        zone = lab.publish(root)
        with lab.dns_servers(zone, "valid", 0) as dns_port:
            inventory = dns_inventory.discover_index(root, dns_port)
    return {"zone": lab.ZONE, "dns_port": dns_port,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": round((time.perf_counter()-started)*1000, 2),
        "scope": "Published entries in this run's local diag.test zone. Metadata only; no service was invoked. Endpoints describe a disposable catalogue and are not running services.",
        "inventory": inventory}


class OperationLimiter:
    """Bound authenticated diagnostic runs without background refill threads."""

    def __init__(self, rate=10, burst=10, clock=time.monotonic):
        self.rate, self.burst, self.clock = rate, burst, clock
        self.tokens, self.updated = float(burst), clock()
        self.lock = threading.Lock()

    def allow(self):
        with self.lock:
            now = self.clock()
            self.tokens = min(self.burst, self.tokens + max(0, now-self.updated)*self.rate)
            self.updated = now
            if self.tokens < 1:
                return False
            self.tokens -= 1
            return True


def local_tls_context(directory):
    """Create a local certificate with both DNS and IP identities; no openssl CLI."""
    directory = Path(directory)
    cert_file, key_file = directory / "https_cert.pem", directory / "https_key.pem"
    if cert_file.exists() != key_file.exists():
        raise ValueError("Incomplete dashboard TLS files; choose a fresh --tls-dir or restore the matching pair")
    if not cert_file.exists():
        directory.mkdir(parents=True, exist_ok=True)
        key = lab.ec.generate_private_key(lab.ec.SECP256R1())
        name = lab.x509.Name([lab.x509.NameAttribute(lab.NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(timezone.utc)
        cert = (lab.x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(lab.x509.random_serial_number())
            .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=30))
            .add_extension(lab.x509.SubjectAlternativeName([
                lab.x509.DNSName("localhost"), lab.x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(lab.x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, lab.hashes.SHA256()))
        lab.write_private(key_file, key.private_bytes(lab.serialization.Encoding.PEM,
            lab.serialization.PrivateFormat.PKCS8, lab.serialization.NoEncryption()))
        cert_file.write_bytes(cert.public_bytes(lab.serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    return context


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = not hasattr(socket, "SO_EXCLUSIVEADDRUSE")

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def __init__(self, address, public_port=None, *, tls_context=None):
        token = os.getenv("DEMO_TOKEN")
        if token is not None and (not 32 <= len(token) <= 256 or
                any(not 33 <= ord(char) <= 126 for char in token)):
            raise ValueError("DEMO_TOKEN must contain 32-256 printable ASCII characters without spaces")
        super().__init__(address, Handler)
        self.public_port = public_port or self.server_port
        # This browser session token is returned by /api/config, not a login secret.
        self.request_token = token if token is not None else secrets.token_urlsafe(32)
        self.tls_context = tls_context
        self.scheme = "https" if tls_context else "http"
        self.run_lock = threading.Lock()
        self.request_slots = threading.BoundedSemaphore(16)
        self.rate_limiter = OperationLimiter()

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            if self.tls_context:
                request.settimeout(10)
                # Handshake runs in a bounded worker, so a stalled peer cannot
                # block the listening thread or every other client.
                try:
                    request = self.tls_context.wrap_socket(request, server_side=True)
                except OSError:
                    self.shutdown_request(request)
                    return
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "PS033Demo/1.0"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def send_content(self, code, body, content_type="application/json", *, retry_after=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if retry_after is not None:
            self.send_header("Retry-After", str(retry_after))
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def local_request(self):
        port = self.server.server_port
        allowed = {f"{host}:{number}" for host in ("127.0.0.1", "localhost")
            for number in (port, self.server.public_port)}
        if port == (443 if self.server.scheme == "https" else 80):
            allowed.update(("127.0.0.1", "localhost"))
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        if len(self.headers.get_all("Host", [])) != 1 or len(self.headers.get_all("Origin", [])) > 1 or host not in allowed or (origin and origin != f"{self.server.scheme}://{host}"):
            self.send_content(403, {"error": "Open this demo using its local address."})
            return False
        return True

    def do_GET(self):
        if not self.local_request():
            return
        route = urlsplit(self.path).path
        if route == "/api/health":
            self.send_content(200, {"status": "ready", "scope": "local"})
            return
        if route == "/api/config":
            self.send_content(200, {"token": self.server.request_token, "scenarios": SCENARIOS,
                "services": list(lab.SERVICES), "team": "A3-PS033-TC378"})
            return
        assets = {"/": ("index.html", "text/html; charset=utf-8"),
            "/experience.css": ("experience.css", "text/css; charset=utf-8"),
            "/diagnostics.css": ("diagnostics.css", "text/css; charset=utf-8"),
            "/experience.js": ("experience.js", "text/javascript; charset=utf-8"),
            "/hero.png": ("hero.png", "image/png"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/style.css": ("style.css", "text/css; charset=utf-8")}
        if route not in assets:
            self.send_content(404, {"error": "Not found"})
            return
        filename, content_type = assets[route]
        self.send_content(200, (WEB / filename).read_bytes(), content_type)

    def do_POST(self):
        if not self.local_request():
            return
        if self.path not in ("/api/run", "/api/inventory"):
            self.send_content(404, {"error": "Not found"})
            return
        if len(self.headers.get_all("X-Demo-Token", [])) != 1 or not secrets.compare_digest(
                self.headers.get("X-Demo-Token", "").encode("utf-8"), self.server.request_token.encode("ascii")):
            self.send_content(403, {"error": "Refresh the page to reconnect to the demo."})
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self.send_content(415, {"error": "Send application/json"})
            return
        try:
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise ValueError()
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                raise ValueError()
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError()
            if self.path == "/api/inventory":
                if data:
                    raise ValueError()
            else:
                if set(data) not in ({"scenario", "service"}, {"scenario", "service", "health_mode"}):
                    raise ValueError()
                scenario, service = data["scenario"], data["service"]
                health_mode = data.get("health_mode", "live")
                if not all(isinstance(value, str) for value in (scenario, service, health_mode)):
                    raise ValueError()
                if scenario not in SCENARIOS or service not in (*lab.SERVICES, "all") or health_mode not in ("live", "sample"):
                    raise ValueError()
        except (ValueError, UnicodeError, OSError, RecursionError):
            self.send_content(400, {"error": "Send valid local discovery options."})
            return
        if not self.server.run_lock.acquire(blocking=False):
            self.send_content(409, {"error": "A discovery operation is already running. Please wait and retry."})
            return
        try:
            if not self.server.rate_limiter.allow():
                self.send_content(429, {"error": "Too many diagnostic runs. Please retry in a second."}, retry_after=1)
                return
            self.send_content(200, run_inventory() if self.path == "/api/inventory" else run_demo(scenario, service, health_mode))
        except Exception:
            logging.getLogger("diagdiscover.dashboard").exception("Laboratory setup or execution failed")
            self.send_content(500, {"error": "The local lab could not start. Check available ports and restart the demo."})
        finally:
            self.server.run_lock.release()

    def log_message(self, *_):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", choices=("127.0.0.1", "0.0.0.0"), default="127.0.0.1")
    parser.add_argument("--public-port", type=int, help="Explicit loopback host port when Docker maps a different port")
    parser.add_argument("--enable-https", action="store_true", help="Enable local HTTPS with a self-signed certificate")
    parser.add_argument("--tls-dir", type=Path, default=lab.RUNTIME / "dashboard-tls",
        help="Directory for the optional dashboard certificate and key")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Choose a port between 1024 and 65535")
    if args.public_port is not None and not 1024 <= args.public_port <= 65535:
        parser.error("Choose a public port between 1024 and 65535")
    configure_logging()
    try:
        context = local_tls_context(args.tls_dir) if args.enable_https else None
        with DemoServer((args.host, args.port), public_port=args.public_port, tls_context=context) as server:
            print(f"PS-033 demo: {server.scheme}://127.0.0.1:{server.public_port}  |  Ctrl+C to stop", flush=True)
            if context:
                print(f"Local TLS certificate (requires explicit client trust): {args.tls_dir / 'https_cert.pem'}", flush=True)
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Could not start demo: {exc}.")


if __name__ == "__main__":
    main()
