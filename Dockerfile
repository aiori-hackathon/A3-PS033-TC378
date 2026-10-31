## ---------- Build stage ----------
FROM python:3.12-slim AS builder
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/python -m pip install --no-cache-dir -r requirements.txt && \
    /opt/venv/bin/python -m pip check

## ---------- Runtime stage ----------
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY lab.py diagnostics.py dns_inventory.py dashboard.py logging_config.py ./
COPY test_*.py ./
COPY web ./web
# Create non‑root user and minimal runtime dir
RUN useradd --uid 10001 --create-home lab && \
    mkdir /app/.runtime && chown lab:lab /app/.runtime
USER lab
ENTRYPOINT ["python", "lab.py"]
CMD ["demo"]

# The default command is a one-shot CLI demo. The dashboard's HTTP healthcheck
# belongs to the dashboard service in compose.yaml.
