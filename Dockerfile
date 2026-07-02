# Minimal container for hono-desktop (portable compute provider web UI)
# Build binary first on host:
#   deno compile --allow-net --allow-read --allow-write --allow-env --allow-run \
#     --target x86_64-unknown-linux-gnu --output hono-desktop hono-desktop/mod.ts
# Then build image:
#   container build -t pdr-desktop .

FROM debian:bookworm-slim

# Install only what's needed at runtime (curl for xdg-open fallback, ca-certs for TLS)
RUN apt-get update && apt-get install -y \
    curl ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY hono-desktop/hono-desktop-bin /usr/local/bin/hono-desktop

RUN mkdir -p /data
ENV STORAGE_DIR=/data
ENV STATE_PATH=/data/compute-provider-state.json
ENV HOSTNAME=0.0.0.0
ENV PORT=8080
ENV SKIP_MARKET=true

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/hono-desktop"]
