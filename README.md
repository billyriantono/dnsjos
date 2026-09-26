# DnsJos

Control panel for a fleet of [dnsdist](https://dnsdist.org) resolvers. One panel
monitors and configures every node, builds the TrustPositif blocklist once into a CDB
file, and every node's agent downloads the finished CDB (checksum-verified).

- **Panel** (`cmd/dnsjos`): one static Go binary — REST API, embedded React UI,
  blocklist builder, PostgreSQL storage. Idle RSS target < 40 MB.
- **Agent** (`cmd/dnsjos-agent`): one static Go binary per node — pulls desired config,
  renders and validates `dnsdist.conf`, applies with rollback, downloads the blocklist,
  reports metrics. Outbound HTTPS only; the panel never connects to nodes.
- **Web** (`web/`): React 19, Vite, Tailwind v4, shadcn/ui (Radix), react-icons.

The full design contract is [docs/SPEC.md](docs/SPEC.md).

## Quick start (development)

Requirements: Go 1.25, PostgreSQL ≥ 14, pnpm.

```sh
createdb dnsjos
export DNSJOS_DATABASE_URL="postgres://$USER@127.0.0.1:5432/dnsjos?sslmode=disable"
export DNSJOS_BOOTSTRAP_ADMIN_EMAIL=admin@example.com DNSJOS_BOOTSTRAP_ADMIN_PASSWORD=admin-password
make dev            # panel on :8080 + Vite dev server with /api proxy
```

Migrations run automatically at startup. Create more admins with
`dnsjos admin create --email E --password P [--name N]`.

## Build

```sh
make web            # web/dist
make agent          # internal/panel/install/bin/dnsjos-agent-linux-{amd64,arm64} (+ .sha256)
make panel          # bin/dnsjos, embeds the UI and agent binaries
make test           # go test ./... (+ web typecheck/lint); set DNSJOS_TEST_DATABASE_URL for DB tests
```

A plain `go build ./...` always works: placeholders are committed for the embedded assets.

## Deploy

1. Create a PostgreSQL database and user `dnsjos`.
2. Copy `bin/dnsjos` to `/usr/local/bin/`, `deploy/dnsjos.env.example` to
   `/etc/dnsjos/dnsjos.env` (edit it), `deploy/dnsjos.service` to `/etc/systemd/system/`,
   create the `dnsjos` system user, then `systemctl enable --now dnsjos`.
3. Put a TLS proxy in front (see `deploy/Caddyfile.example`) and set `DNSJOS_PUBLIC_URL`.
4. Add a node: **Nodes → Add node** shows a one-line installer:
   `curl -fsSL https://PANEL/install.sh | sudo sh -s -- --token T`.

## Layout

See [docs/SPEC.md §3](docs/SPEC.md#3-repository-layout). The panel CLI:
`dnsjos [serve] | migrate | admin create | version`.
