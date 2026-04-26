# xtop hub deployment

One-node hub + Postgres via docker-compose. Default port is **9898** (env-overridable).

## Quick start

```bash
export XTOP_PG_PASSWORD=$(openssl rand -hex 16)
export XTOP_HUB_TOKEN=$(openssl rand -hex 24)
export XTOP_HUB_PORT=9898          # optional — defaults to 9898 if unset

# Build the hub image (run from repo root)
docker build -f packaging/hub/Dockerfile -t xtop-hub:latest .

# Start Postgres + hub
docker compose -f packaging/hub/docker-compose.yml up -d

# Agents point at the hub
sudo xtop --fleet-hub=http://hub.example:${XTOP_HUB_PORT:-9898} \
          --fleet-token=$XTOP_HUB_TOKEN
```

Open the dashboard at `http://hub.example:9898/`.

## Standalone (no Docker)

Install Postgres 14+ yourself, then:

```bash
createdb xtopfleet
createuser xtop --pwprompt

# Option A — config file
cat > ~/.xtop/hub.json <<EOF
{
  "listen_addr": ":9898",
  "auth_token": "<random token>",
  "postgres_dsn": "postgres://xtop:<password>@localhost:5432/xtopfleet?sslmode=disable"
}
EOF
sudo xtop hub

# Option B — env vars (no config file needed)
sudo XTOP_HUB_LISTEN=:9898 \
     XTOP_HUB_TOKEN=<token> \
     XTOP_HUB_POSTGRES="postgres://xtop:<pw>@localhost:5432/xtopfleet?sslmode=disable" \
     xtop hub

# Option C — pure CLI
sudo xtop hub --listen=:9898 --token=<token> \
              --postgres="postgres://xtop:<pw>@localhost:5432/xtopfleet?sslmode=disable"
```

## Configuration precedence

From highest priority to lowest:

1. **CLI flags**        — `--listen`, `--postgres`, `--token`, `--tls-cert`, `--tls-key`, `--config`
2. **Environment**      — `XTOP_HUB_LISTEN`, `XTOP_HUB_POSTGRES`, `XTOP_HUB_TOKEN`,
                         `XTOP_HUB_TLS_CERT`, `XTOP_HUB_TLS_KEY`, `XTOP_HUB_SQLITE_CACHE_PATH`
3. **JSON config**      — `~/.xtop/hub.json` or `--config <path>`
4. **Built-in default** — listen `:9898`

## Endpoints

| Method | Path                       | Purpose                       |
|--------|----------------------------|-------------------------------|
| GET    | `/`                        | Web dashboard                 |
| POST   | `/v1/heartbeat`            | Agent → hub, per-tick         |
| POST   | `/v1/incident`             | Agent → hub, on incidents     |
| GET    | `/v1/hosts`                | List known hosts (JSON)       |
| GET    | `/v1/host/{hostname}`      | One host (JSON)               |
| GET    | `/v1/incidents?hours=24`   | Recent incidents (JSON)       |
| GET    | `/v1/stream`               | SSE live event feed           |
| GET    | `/health`                  | Health check                  |

All agent endpoints (`/v1/heartbeat`, `/v1/incident`) and read endpoints require
the `X-XTop-Token` header when the hub is started with an auth token.
