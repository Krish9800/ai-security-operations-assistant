# Rootless container build for AI Security Operations Assistant
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

# Install build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc python3-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /build/
COPY src/ /build/src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Production runtime stage
FROM python:3.12-slim-bookworm AS runtime

# Create dedicated non-root user and group
RUN groupadd -g 10001 secops && \
    useradd -u 10001 -g secops -s /bin/false -m -d /home/secops secops

WORKDIR /app

# Copy installed python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /build/src /app/src

# Create and grant permissions for database/data directory
RUN mkdir -p /app/data && \
    chown -R secops:secops /app

USER 10001:10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECOPS_DATABASE_PATH=/app/data/secops.db \
    SECOPS_API_HOST=0.0.0.0 \
    SECOPS_API_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["uvicorn", "ai_secops.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
