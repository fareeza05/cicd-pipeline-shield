# Slim base keeps the image small and reduces attack surface.
FROM python:3.11-slim

LABEL maintainer="shield-pipe"
LABEL description="Lightweight DevSecOps scanner: secret detection + permission audit"

WORKDIR /app

# Non-root user. UID 1000 lines up with the default Jenkins agent UID,
# which makes host-mounted volume writes Just Work in the common case.
RUN groupadd -g 1000 scanner && \
    useradd -u 1000 -g scanner -M -s /bin/sh scanner

# Install dependencies first so this layer is cached unless requirements change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner source and entrypoint script.
COPY scanner/ ./scanner/
COPY deployment/entrypoint.sh /app/entrypoint.sh

# Reports dir + ownership in a single layer.
RUN chmod +x /app/entrypoint.sh && \
    mkdir -p /app/reports && \
    chown -R scanner:scanner /app

USER scanner

# Send Python output straight to the terminal (no buffering) so Jenkins
# logs reflect scan progress in real time.
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/data"]
