"""PS-033: a bounded DNS-AID-style lab, not a production DNS server."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import socketserver
import ssl
import struct
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.zone

from diagnostics import HealthCollectionError, bounded_number, collect_health, validate_health

ZONE = "diag.test."
SERVICES = ("latency", "traceroute", "health")
RUNTIME = Path(__file__).parent / ".runtime"
SCENARIOS = ("valid", "bogus", "malformed", "unavailable", "unauthorized", "expired", "unsigned")
RESULTS = {
    "latency": {"round_trip_ms": 12.5, "packet_loss_percent": 0},
    "traceroute": {"hops": ["192.0.2.1", "192.0.2.2", "192.0.2.3"]},
    "health": {"status": "healthy", "cpu_percent": 23, "memory_percent": 41},
}
MAX_RESPONSE_BYTES = 65536


class LabError(Exception):
    def __init__(self, code, detail):
        self.code, self.detail = code, detail
        super().__init__(detail)


def owner(service):
    return f"{service}.{ZONE}"


def write_private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)  # Windows uses inherited ACLs; keep this directory private.


def provision(root=RUNTIME):
    """Explicit local provisioning is the trust bootstrap; never learn keys from DNS."""
    root.mkdir(parents=True, exist_ok=True)
    key_path = root / "zone-key.pem"
    if key_path.exists():
        required = ("trust-anchor.txt", "tls-key.pem", "tls-cert.pem", "tokens.json")
        if not all((root / name).exists() for name in required):
            raise LabError("SETUP_ERROR", "Incomplete runtime; restore its files or use a fresh runtime directory.")
        return
    key = ec.generate_private_key(ec.SECP256R1())
    write_private(key_path, key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    dnskey = dns.dnssec.make_dnskey(key.public_key(), "ECDSAP256SHA256", flags=257)
    (root / "trust-anchor.txt").write_text(dnskey.to_text(), encoding="ascii")

    tls_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PS033 local lab")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName(owner(s).rstrip(".")) for s in SERVICES]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(tls_key, hashes.SHA256()))
    write_private(root / "tls-key.pem", tls_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root / "tls-cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    write_private(root / "tokens.json", json.dumps({s: secrets.token_urlsafe(32) for s in SERVICES}).encode())


def publish(root=RUNTIME, scenario="valid", base_port=18443, service_ports=None, fault_service="latency"):
    """Publisher: produce an actual signed zone, including DNSKEY and NSEC."""
    key = serialization.load_pem_private_key((root / "zone-key.pem").read_bytes(), password=None)
    dnskey = dns.dnssec.make_dnskey(key.public_key(), "ECDSAP256SHA256", flags=257)
    lines = [f"$ORIGIN {ZONE}", "$TTL 30",
        f"@ IN SOA ns.{ZONE} hostmaster.{ZONE} {int(time.time())} 60 30 3600 30",
        f"@ IN NS ns.{ZONE}", "ns IN A 127.0.0.1"]
    for i, service in enumerate(SERVICES):
        # Private-use metadata keys are part of our lab profile, not IANA assignments.
        capability = "invalid-capability" if scenario == "malformed" and service == fault_service else service
        port = service_ports[service] if service_ports else base_port+i
        lines += [f"{service} IN A 127.0.0.1",
            f'{service} IN SVCB 1 . mandatory=alpn,port,key65280,key65281 '
            f'alpn="http/1.1" port={port} key65280="{capability}" key65281="/invoke"']
    zone = dns.zone.from_text("\n".join(lines), origin=ZONE, relativize=False)
    # Publish the local profile's enumeration index before signing, so clients
    # verify the advertised service list under the same provisioned zone key.
    from dns_inventory import add_index
    add_index(zone)
    now = int(time.time())
    dns.dnssec.sign_zone(zone, keys=[(key, dnskey)],
        inception=now-3600, expiration=now-60 if scenario == "expired" else now+86400)
    if scenario == "bogus":
        # Change signed data WITHOUT re-signing: this must fail cryptographic validation.
        record = dns.rrset.from_text(owner(fault_service), 30, "IN", "SVCB",
            f'1 . alpn="http/1.1" port=19999 key65280="{fault_service}" key65281="/invoke"')
        zone.replace_rdataset(owner(fault_service), record)
    zone.to_file(str(root / "zone.signed"), relativize=False)
    return zone


def dns_answer(data, zone, scenario):
    query = dns.message.from_wire(data)
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA
    if len(query.question) != 1 or query.question[0].rdclass != 1:
        response.set_rcode(dns.rcode.FORMERR)
        return response.to_wire()
    q = query.question[0]
    records = zone.get_rdataset(q.name, q.rdtype)
    if not records:
        # Deliberately refuse unsupported queries; do not fabricate validated absence.
        response.set_rcode(dns.rcode.REFUSED)
    else:
        response.answer.append(dns.rrset.from_rdata_list(q.name, records.ttl, list(records)))
        sig = zone.get_rdataset(q.name, "RRSIG", covers=q.rdtype)
        if sig and scenario != "unsigned" and query.ednsflags & dns.flags.DO:
            response.answer.append(dns.rrset.from_rdata_list(q.name, sig.ttl, list(sig)))
    return response.to_wire(max_size=65535)


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def read_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length-len(data))
        if not chunk:
            raise EOFError("Truncated DNS TCP frame")
        data += chunk
    return data


@contextmanager
def dns_servers(zone, scenario, port):
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                data = dns_answer(self.request[0], zone, scenario)
                self.request[1].sendto(data, self.client_address)
            except (dns.exception.DNSException, ValueError):
                return

    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                size = struct.unpack("!H", read_exact(self.request, 2))[0]
                data = dns_answer(read_exact(self.request, size), zone, scenario)
                self.request.sendall(struct.pack("!H", len(data))+data)
            except (dns.exception.DNSException, ValueError, OSError, EOFError):
                return

    class TCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    # Let TCP allocate first: Windows/Docker may reserve whole TCP ranges that
    # UDP's independent ephemeral allocator would repeatedly choose.
    # Bind both transports before starting threads; retry only automatic ports.
    for attempt in range(20):
        tcp_server = None
        try:
            tcp_server = TCPServer(("127.0.0.1", port), TCP)
            actual_port = tcp_server.server_address[1]
            udp_server = socketserver.ThreadingUDPServer(("127.0.0.1", actual_port), UDP)
        except OSError:
            if tcp_server is not None:
                tcp_server.server_close()
            if port or attempt == 19:
                raise
            continue
        break
    with ExitStack() as stack:
        stack.enter_context(running(udp_server))
        stack.enter_context(running(tcp_server))
        yield actual_port


def service_server(service, port, root, *, health_mode="live"):
    if health_mode not in ("live", "sample"):
        raise ValueError("Health mode must be live or sample")
    expected = json.loads((root / "tokens.json").read_text())[service]

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def do_POST(self):
            if self.path != "/invoke":
                self.send_error(404)
                return
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied.encode(), f"Bearer {expected}".encode()):
                self.send_error(401, "Authentication required")
                return
            # The invocation profile takes no body. Do not leave an unbounded
            # request body to be interpreted as another HTTP request.
            if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
                self.close_connection = True
                self.send_error(400, "This service accepts an empty request only")
                return
            try:
                payload = collect_health() if service == "health" and health_mode == "live" else {
                    "service": service, "mock": True, "result": RESULTS[service]}
                body = json.dumps(payload, allow_nan=False).encode()
            except HealthCollectionError:
                self.send_response(503)
                self.send_header("X-Diagnostic-Authenticated", "true")
                self.send_header("Content-Length", "0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(root / "tls-cert.pem", root / "tls-key.pem")
        context.set_alpn_protocols(["http/1.1"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    except Exception:
        server.server_close()
        raise
    return server


@contextmanager
def laboratory(root=RUNTIME, scenario="valid", dns_port=15353, base_port=18443, *, health_mode="live"):
    if health_mode not in ("live", "sample"):
        raise ValueError("Health mode must be live or sample")
    zone = publish(root, scenario, base_port)
    with ExitStack() as stack:
        stack.enter_context(dns_servers(zone, scenario, dns_port))
        for i, service in enumerate(SERVICES):
            if scenario == "unavailable" and i == 0:
                continue
            stack.enter_context(running(service_server(service, base_port+i, root, health_mode=health_mode)))
        yield


def validated_query(name, rdtype, root, dns_port, *, timeout=2):
    query = dns.message.make_query(name, rdtype, want_dnssec=True)
    try:
        response, _ = dns.query.udp_with_fallback(query, "127.0.0.1", port=dns_port, timeout=timeout)
    except (dns.exception.DNSException, OSError) as exc:
        raise LabError("DNS_UNAVAILABLE", "DNS transport failed or timed out") from exc
    if response.rcode() != dns.rcode.NOERROR:
        raise LabError("DNS_QUERY_FAILED", dns.rcode.to_text(response.rcode()))
    target = dns.name.from_text(name)
    kind = dns.rdatatype.from_text(rdtype)
    rrsets = [r for r in response.answer if r.name == target and r.rdtype == kind]
    signatures = [r for r in response.answer if r.name == target and
        r.rdtype == dns.rdatatype.RRSIG and r.covers == kind]
    if len(rrsets) != 1 or len(signatures) != 1:
        raise LabError("DNSSEC_UNVERIFIED", "Required signed answer is missing; invocation blocked")
    # Trust only a key installed locally, never a DNSKEY supplied by this response.
    anchor = dns.rrset.from_text(ZONE, 30, "IN", "DNSKEY",
        (root / "trust-anchor.txt").read_text(encoding="ascii"))
    try:
        dns.dnssec.validate(rrsets[0], signatures[0], {dns.name.from_text(ZONE): anchor})
    except dns.exception.DNSException as exc:
        raise LabError("DNSSEC_BOGUS", "Signature is invalid, expired, or not yet valid; invocation blocked") from exc
    return rrsets[0]


def metadata(rrset, service):
    if len(rrset) != 1:
        raise LabError("METADATA_INVALID", "Lab profile requires one ServiceMode record")
    record = rrset[0]
    params = record.params
    required = {0, 1, 3, 65280, 65281}
    try:
        if record.priority < 1 or not required.issubset(params):
            raise ValueError("Missing required ServiceMode metadata")
        mandatory = set(params[0].keys)
        if not {1, 3, 65280, 65281}.issubset(mandatory) or not mandatory.issubset(required):
            raise ValueError("Unsupported or missing mandatory parameters")
        if params[1].ids != (b"http/1.1",):
            raise ValueError("Unsupported transport")
        capability = params[65280].value.decode("ascii")
        path = params[65281].value.decode("ascii")
        host = rrset.name.to_text() if record.target == dns.name.root else record.target.to_text()
        if capability != service or path != "/invoke" or host != owner(service):
            raise ValueError("Capability, path, or target violates local lab policy")
        port = params[3].port
        if not 1024 <= port <= 65535:
            raise ValueError("Port violates local lab policy")
        return host, port, path
    except (ValueError, KeyError, AttributeError, UnicodeError) as exc:
        raise LabError("METADATA_INVALID", str(exc)) from exc


def discover(service, root=RUNTIME, dns_port=15353, bad_token=False):
    events = []
    connection = None
    started = time.perf_counter()
    stages = ["dnssec", "metadata", "address", "tls", "authentication", "result"]
    trace = [{"stage": stage, "status": "not_run"} for stage in stages]
    stage_index = 0
    stage_started = started
    evidence = {}
    invocation_attempted = False

    def passed(detail):
        nonlocal stage_index, stage_started
        now = time.perf_counter()
        trace[stage_index].update(status="passed", detail=detail,
            duration_ms=round((now-stage_started)*1000, 3))
        stage_index += 1
        stage_started = now

    def outcome(status, detail=None, **extra):
        if status != "SUCCESS" and stage_index < len(trace):
            trace[stage_index].update(status="failed", detail=detail or status,
                duration_ms=round((time.perf_counter()-stage_started)*1000, 3))
        result = {"service": service, "status": status, "events": events, "trace": trace,
            "evidence": evidence, "invocation_attempted": invocation_attempted,
            "elapsed_ms": round((time.perf_counter()-started)*1000, 3), **extra}
        if detail:
            result["detail"] = detail
        return result

    try:
        record = validated_query(owner(service), "SVCB", root, dns_port)
        events.append("SVCB signature verified against provisioned zone key")
        evidence["svcb"] = record.to_text()
        passed(events[-1])
        host, port, path = metadata(record, service)
        events.append("Metadata and local endpoint policy accepted")
        evidence["endpoint"] = f"https://{host.rstrip('.')}:{port}{path}"
        passed(events[-1])
        addresses = validated_query(host, "A", root, dns_port)
        if len(addresses) != 1 or addresses[0].address != "127.0.0.1":
            raise LabError("POLICY_DENIED", "This demo permits only loopback endpoints")
        events.append("Address signature verified")
        evidence["address"] = addresses.to_text()
        passed(events[-1])
        tls = ssl.create_default_context(cafile=str(root / "tls-cert.pem"))
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.set_alpn_protocols(["http/1.1"])
        connection = http.client.HTTPSConnection(host.rstrip("."), port, timeout=2, context=tls)
        raw = socket.create_connection((addresses[0].address, port), timeout=2)
        try:
            connection.sock = tls.wrap_socket(raw, server_hostname=host.rstrip("."))
        except Exception:
            raw.close()
            raise
        events.append("TLS certificate and hostname verified")
        evidence["tls_version"] = connection.sock.version()
        passed(events[-1])
        tokens = json.loads((root / "tokens.json").read_text())
        token = "deliberately-invalid" if bad_token else tokens[service]
        invocation_attempted = True
        connection.request("POST", path, body=b"", headers={"Authorization": f"Bearer {token}"})
        response = connection.getresponse()
        if response.status == 401:
            raise LabError("AUTHENTICATION_DENIED", "Service rejected credentials despite valid DNS discovery")
        if response.status == 503 and response.getheader("X-Diagnostic-Authenticated") == "true":
            passed("Service accepted its separately provisioned bearer token")
            raise LabError("SERVICE_ERROR", "The authenticated service could not collect host measurements; try again")
        if response.status != 200:
            raise LabError("SERVICE_ERROR", f"HTTP {response.status}")
        passed("Service accepted its separately provisioned bearer token")
        result = read_diagnostic_response(response, service)
        live = result["mock"] is False
        events.append("Service-specific bearer token accepted; " + ("live host measurement received" if live else "sample result received"))
        passed("Received " + ("measured host data" if live else "diagnostic sample data") + " from the HTTPS service")
        return outcome("SUCCESS", endpoint=evidence["endpoint"], data=result)
    except LabError as exc:
        return outcome(exc.code, exc.detail)
    except ssl.SSLError:
        return outcome("TLS_REJECTED", "TLS identity verification failed; credentials were not sent")
    except (OSError, http.client.HTTPException):
        return outcome("SERVICE_UNAVAILABLE", "Could not complete the connection to the diagnostic service")
    except (ValueError, KeyError):
        return outcome("SERVICE_RESPONSE_INVALID", "The service response or local configuration could not be read")
    finally:
        if connection:
            connection.close()


def read_diagnostic_response(response, service):
    """Bound and validate an HTTPS result before returning it to the UI/export."""
    try:
        media_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json" or response.getheader("Content-Encoding", "identity") != "identity":
            raise ValueError("Unsupported diagnostic response encoding")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isascii() or not length.isdecimal() or not 0 < int(length) <= MAX_RESPONSE_BYTES):
            raise ValueError("Invalid diagnostic response length")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES or (length is not None and len(raw) != int(length)):
            raise ValueError("Diagnostic response exceeds limits or is truncated")

        def reject_constant(value):
            raise ValueError("Non-finite JSON number")

        data = json.loads(raw, parse_constant=reject_constant)
        if not isinstance(data, dict) or data.get("service") != service or type(data.get("mock")) is not bool or not isinstance(data.get("result"), dict):
            raise ValueError("Unexpected diagnostic result profile")
        if service == "health" and data["mock"] is False:
            return validate_health(data)
        if set(data) != {"service", "mock", "result"} or data["mock"] is not True:
            raise ValueError("Unsupported sample response profile")
        result = data["result"]
        if service == "health":
            if (set(result) != {"status", "cpu_percent", "memory_percent"}
                    or result["status"] != "healthy"
                    or not all(bounded_number(result[key], 0, 100)
                               for key in ("cpu_percent", "memory_percent"))):
                raise ValueError("Invalid health sample")
        elif service == "latency":
            if (set(result) != {"round_trip_ms", "packet_loss_percent"}
                    or not bounded_number(result["round_trip_ms"], 0, 60000)
                    or not bounded_number(result["packet_loss_percent"], 0, 100)):
                raise ValueError("Invalid latency sample")
        elif service == "traceroute":
            import ipaddress
            hops = result.get("hops")
            if set(result) != {"hops"} or not isinstance(hops, list) or not 1 <= len(hops) <= 64:
                raise ValueError("Invalid traceroute sample")
            for hop in hops:
                if not isinstance(hop, str) or len(hop) > 45:
                    raise ValueError("Invalid traceroute address")
                ipaddress.ip_address(hop)
        else:
            raise ValueError("Unsupported service response")
        return data
    except (ValueError, KeyError, TypeError, OverflowError, RecursionError) as exc:
        raise LabError("SERVICE_RESPONSE_INVALID", "The diagnostic response failed its size, encoding, or data validation checks") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "demo", "serve", "discover"))
    parser.add_argument("--scenario", choices=SCENARIOS, default="valid")
    parser.add_argument("--service", choices=(*SERVICES, "all"), default="all")
    parser.add_argument("--dns-port", type=int, default=15353)
    parser.add_argument("--base-port", type=int, default=18443)
    parser.add_argument("--bad-token", action="store_true")
    parser.add_argument("--health-mode", choices=("live", "sample"), default="sample",
        help="Health service measurement mode (default: sample, for the three-mock-service hackathon demo). "
             "live measures the diagnostic service's OS/VM; Docker metrics are not cgroup quota metrics. "
             "Applies to demo and serve; discover uses the running service's mode.")
    args = parser.parse_args()
    if not 1024 <= args.dns_port <= 65535 or not 1024 <= args.base_port <= 65533:
        parser.error("Use DNS port 1024-65535 and base port 1024-65533")
    if args.dns_port in range(args.base_port, args.base_port+3):
        parser.error("DNS and service ports must differ")
    selected = SERVICES if args.service == "all" else (args.service,)
    if args.command in ("init", "demo", "serve"):
        provision()
    if args.command == "init":
        publish()
        print("Local test keys, service credentials, TLS certificate and signed zone prepared in .runtime/")
        return 0
    if args.command == "serve":
        with laboratory(scenario=args.scenario, dns_port=args.dns_port, base_port=args.base_port, health_mode=args.health_mode):
            print(f"Lab running on loopback; DNS UDP/TCP {args.dns_port}. Ctrl+C to stop.", flush=True)
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                pass
        return 0

    def results():
        return [discover(s, dns_port=args.dns_port,
            bad_token=args.bad_token or args.scenario == "unauthorized") for s in selected]

    if args.command == "demo":
        with laboratory(scenario=args.scenario, dns_port=args.dns_port, base_port=args.base_port, health_mode=args.health_mode):
            output = results()
    else:
        if not RUNTIME.exists():
            parser.error("Run init or serve first to provision trust material")
        output = results()
    print(json.dumps(output, indent=2))
    return 0 if all(row["status"] == "SUCCESS" for row in output) else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (LabError, OSError) as error:
        raise SystemExit(f"Lab setup failed: {error}")
