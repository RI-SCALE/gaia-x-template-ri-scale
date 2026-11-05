# gx automation tool. Built and run through docker compose (service `gx`):
#   docker compose run --rm gx status
#   docker compose run --rm gx run -i
FROM python:3.12-slim

WORKDIR /opt/gx
COPY pyproject.toml ./
COPY gx ./gx
RUN pip install --no-cache-dir .

# Compose mounts the repository's static/ and automation/config/ under /repo.
WORKDIR /repo
ENV GX_CONFIG_DIR=/repo/automation/config \
    GX_HOSTING_DIR=/repo \
    PYTHONUNBUFFERED=1
# No USER on purpose: in dev, gx reads Caddy's key and certificate, which are root-owned
# 0600 files in the caddy_data volume.
ENTRYPOINT ["gx"]
