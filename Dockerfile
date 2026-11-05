# CanaryGuard - honeypot + host IDS control stack
# The honeypot itself (OpenCanary) can run beside this in docker-compose.yml.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CANARYGUARD_HOME=/data

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY . .
RUN pip install -e .

# all runtime state (db, secret.key, state files) lives here, outside the image
RUN mkdir -p /data && chmod 700 /data
VOLUME ["/data"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD python -c "import socket,sys; s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1',8080)); s.close()" || exit 1

# config.json must be mounted to /data/config.json or baked via CANARYGUARD_HOME=/app
CMD ["python", "main.py"]
