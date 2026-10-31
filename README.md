# DiagDiscover — A3-PS033-TC378

**AIORI-3 · PS-033: DNS-Based Discovery of Diagnostic Services**<br>
**Submission:** 31 October 2026 · Cloud Computing and IoT

**Students:** Chris Itty Biju and Alan Jayan Joseph<br>
**Faculty mentor:** Revathi BS<br>
**Institution:** Karunya University of Technology and Sciences

DiagDiscover is a working local laboratory that publishes diagnostic service
endpoints in signed DNS records, discovers them, checks their metadata and
identity, and invokes them with a separate service credential. The browser
dashboard and Windows application expose each decision and its result.

## Start here

| Material | Link |
| --- | --- |
| Product demonstration — 4:21, 1080p, English narration and captions | [Download the MP4](demo/DiagDiscover-Product-Film-1080p.mp4?raw=true) |
| Windows application | [Download DiagDiscover.exe](desktop/DiagDiscover.exe?raw=true) |
| Reproduction steps, expected outcomes and test evidence | [Evaluator guide](docs/EVALUATION.md) |
| Original team introduction video | [Watch on YouTube](https://youtu.be/JQJZaydyBgI) |
| Original Level 1 proposal | [PDF](A3-PS033-TC378-Level1.pdf) · [Editable PowerPoint](A3-PS033-TC378-Level1.pptx) |
| Product video supporting files | [English captions](demo/DiagDiscover-English.srt) · [Narration script](demo/Narration-script.txt) |

The Level 1 slides document the original proposal, including its mock-only
measurement plan. This README and the evaluator guide describe the submitted
implementation, which also supports live system health. The runnable files and
recorded demonstration are supplied directly for local evaluator review; there
is no public hosted demo URL.

## What is implemented

- A publisher and a signed private DNS zone, `diag.test.`.
- Actual DNS queries and DNSSEC signature validation against a locally
  provisioned public trust anchor.
- SVCB metadata checks, signed address validation, verified HTTPS identity,
  and service-specific bearer-token authentication before invocation.
- Three diagnostic services: latency and traceroute return labelled sample
  data; health can return either sample data or a live CPU, memory and uptime
  snapshot. **All sample data** preserves the three mock-service demonstration.
- A signed service catalogue that lists advertised metadata without invoking
  diagnostics, plus eight dashboard scenarios with visible rejection stages.
- A browser interface, a packaged Windows application, Docker configuration,
  automated tests and technical documentation.

**DNSSEC integrity, TLS identity and permission to invoke a service are separate
checks.** Valid DNS metadata neither grants access nor guarantees benevolent
service behaviour.

## Run the Windows application

Download [DiagDiscover.exe](desktop/DiagDiscover.exe?raw=true), then open it.
The executable includes Python and application dependencies. Windows and the
Microsoft Edge WebView2 Runtime are required. It starts its own local backend;
closing the application stops that instance. From a checkout, `Launch-App.cmd`
opens the bundled executable as well.

## Run from source — Python 3.12

Clone this repository, or download and extract its source archive:

```sh
git clone https://github.com/aiori-hackathon/A3-PS033-TC378.git
cd A3-PS033-TC378
```

**Windows PowerShell:**

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe dashboard.py
```

**macOS or Linux:**

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python dashboard.py
```

Open **http://127.0.0.1:8765**, enter the laboratory, and run **Normal discovery**.
Keep the terminal open; press Ctrl+C to stop. If that port is occupied, append
`--port 8767` and open port 8767 instead. These are local addresses on the
reviewer's own computer. No hosts-file changes or purchased domain are needed.

On Windows, the optional desktop source/build dependencies are installed with
`-r requirements-desktop.txt`; run `desktop_app.py` or rebuild with
`Build-App.ps1` after creating the environment above.

## Run with Docker

With Docker Engine and Docker Compose available, run from the repository root:

```sh
docker compose up --build -d dashboard
docker compose ps
```

Open **http://127.0.0.1:8766**. To stop this dashboard:

```sh
docker compose stop dashboard
```

For the self-contained command-line demonstration:

```sh
docker compose run --build --rm lab
```

The Docker dashboard binds only to host loopback. Components share one local
lab container. Live health describes the OS/VM visible to the diagnostic service;
it is not necessarily the physical Windows host or container quota usage.

## Suggested demonstration

1. **Browse DNS services:** inspect the three signed catalogue entries. This
   verifies metadata only; it does not start or invoke those endpoints.
2. Select **System health**, **Live system health**, **Normal discovery**, then
   **Run discovery**. Inspect all six checks and the timestamped measurement.
3. Try **Tampered DNS record**: the signature fails and invocation is blocked.
4. Try **Invalid service metadata**: the signature passes but the profile fails.
5. Try **Wrong access token**: DNS and TLS pass, but the service rejects access.
6. Select **All sample data** to reproduce the original three mock services.
   **Export run** saves evidence without diagnostic service credentials.

See [the evaluator guide](docs/EVALUATION.md) for every scenario and CLI commands.

## Validation and technical documentation

The local Python test suite passed **60 tests on 31 October 2026**. To reproduce
the checks after source setup, use the appropriate environment Python executable:

```sh
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m unittest discover -v
```

Here `python` means `.\.venv\Scripts\python.exe` on Windows or
`.venv/bin/python` on macOS/Linux; environment activation is not required.
The [CI workflow](.github/workflows/ci.yml) also defines Linux and Docker checks.

- [Evaluation and architecture](docs/EVALUATION.md)
- [Implemented record profile and trust model](docs/PROTOCOL.md)
- [Operation, logging, resource limits and deployment boundaries](docs/OPERATIONS.md)
- [Organizer problem statement](reference-materials/PS-033.pdf)

## Scope

This is a controlled local prototype using a documented **DNS-AID draft -02
subset** and private catalogue conventions. It has no public-root DNSSEC chain,
Internet-wide registry, arbitrary-domain discovery or LAN scanning. Latency and
traceroute are fixtures, not measured network performance. Health is a snapshot,
not a health certification. Production deployment, broader interoperability,
public trust-chain validation and durable key rotation remain future work.

Generated keys, tokens, virtual environments and temporary runtime files are
excluded from the repository. See [the protocol notes](docs/PROTOCOL.md) for the
precise trust and interoperability boundaries.
