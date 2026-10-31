# Local operation and deployment boundaries

The supported target is this laptop and a self-contained Docker environment.
This release is a local prototype with additional validation and resource
bounds. It has not been approved for an internet-facing or multi-tenant service.

## Demonstrate the new functionality

1. Open the Windows app or http://127.0.0.1:8765/#lab.
2. Browse DNS services. The application verifies the `_diagnostics.diag.test.`
   PTR index, then each SVCB record. This uses real signed DNS queries. Browsing
   starts no HTTPS diagnostic services and sends no invocation tokens.
3. Select System health, Live system health, Normal discovery, then Run discovery.
   CPU is measured over 250 ms; memory and uptime are snapshots from the service
   host. The timestamp and scope are included in the export. There is no
   automatic polling or generic healthy/unhealthy verdict.
4. Repeat after opening another application to obtain a fresh snapshot.
5. Select Wrong access token or Tampered DNS record. Rejection prevents health
   collection. Select All sample data to demonstrate the three mock services
   specified in PS-033; this mode never reads OS health counters.

## What discovery covers

The publisher builds the private index from all same-zone SVCB owners, rather
than a separate hardcoded inventory list. The client accepts at most 32 entries,
33 DNS queries and an eight-second DNS-transport budget. It validates the index
before following any target, refuses out-of-zone names and inspects each service
record separately. Unknown capabilities can be listed but need an implemented,
reviewed invocation adapter before use. The built-in zone currently publishes
latency, traceroute and health.

This private PTR-to-SVCB convention is not the complete RFC 6763 DNS-SD protocol
or the DNS-AID draft's organization-index protocol. It cannot find unadvertised
services, query arbitrary domains or scan all devices on a LAN. Authentic
metadata does not prove authorization, service availability or benevolent behavior.

## Containers

```powershell
# Run from the cloned A3-PS033-TC378 repository directory.
docker compose up --build -d dashboard
docker compose ps
# Open http://127.0.0.1:8766/#lab
docker compose run --rm --entrypoint python lab -m unittest discover -v
docker compose run --rm lab demo --service health --health-mode live
docker compose stop dashboard
```

Docker uses the host OS/VM counters visible to psutil. These are not necessarily
physical Windows laptop counters or container cgroup usage/limits. To see the
Windows laptop measurements, run the Windows app or local Python browser server.

The Compose deployment exposes only a loopback web port. It runs as UID 10001
with a read-only image, writable temporary directories, no capabilities,
no-new-privileges, 128 processes, 512 MiB memory and one CPU. The read-only
readiness endpoint `/api/health` checks the web listener; it is not a diagnostic
result. A run and a catalogue browse cannot execute concurrently in one server.
HTTP body sizes, response sizes, socket timeouts and active web handler threads
are bounded. Malformed or cross-origin requests are rejected.

## Logging, request limits and optional dashboard HTTPS

Dashboard and desktop startup configure JSON application logs. Docker captures
stream logs; inspect them with `docker compose logs dashboard`. File logging is
optional: set `DIAGDISCOVER_LOG_DIR` to an absolute writable folder before
starting the application. Each file is limited to 5 MiB with three backups.
The default never writes into the application directory. `LOG_LEVEL` accepts
DEBUG, INFO, WARNING, ERROR or CRITICAL; invalid values fall back to INFO.
Avoid putting credentials or request bodies in log messages.

Authenticated diagnostic operations share a token bucket with a burst of ten
and a refill of ten operations per second. Excess operations receive JSON HTTP
429 with Retry-After. Assets and readiness requests do not consume this budget.
Only one diagnostic operation runs at a time; a concurrent operation receives
HTTP 409. The existing sixteen-worker limit also covers TLS handshakes.

The dashboard remains local HTTP by default. Diagnostic-service connections
already use verified TLS independently of the dashboard's transport. For an
optional local HTTPS dashboard:

```powershell
.\.venv\Scripts\python.exe dashboard.py --port 8770 --enable-https
```

This generates a thirty-day self-signed certificate for `localhost` and
`127.0.0.1` in `.runtime/dashboard-tls`, using the existing Python cryptography
dependency. OpenSSL's separate command-line program is not required. A client
must explicitly trust the certificate; ordinary browsers will not automatically
trust it. No system trust settings are modified. `--tls-dir` selects another
certificate directory. The normal browser and desktop launchers keep HTTP.

`DEMO_TOKEN` can optionally set the browser-session request token to 32-256
printable ASCII characters without spaces. Leave it unset for a fresh random
token. This value is intentionally returned by `/api/config`, so it is not an
operator login or a secret to reuse elsewhere. Diagnostic-service credentials
remain separate and never appear in that endpoint.

## Development checks

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m unittest discover -v
```

The GitHub workflow runs these checks and tests inside the restricted Docker
container after the files are committed and pushed. Ruff checks selected syntax
and undefined-name errors; this is not full static type checking. Runtime
dependencies are pinned, but the base image and transitive dependencies are
not a complete immutable dependency lock.

## Before a production deployment

An actual deployment still needs an agreed domain and record profile, an
established authoritative DNS server and validating resolver, separated service
and client credentials, durable key/certificate rotation, operator authentication,
audit retention, monitoring, recovery procedures and testing on the target
network. Current trust is provisioned locally; no public-root DNSSEC chain or
authenticated negative-answer validation is implemented. Python's local HTTP/DNS
harness should not be exposed as a public service.

The protocol base is pinned in `PROTOCOL.md`. The catalogue and live-health mode
are optional local extensions; the original mock-service mode remains available.

Sources: [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763),
[RFC 9460](https://www.rfc-editor.org/rfc/rfc9460),
[psutil API](https://psutil.io/api/).
