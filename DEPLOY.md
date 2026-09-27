# Deploying DnsJos

A step-by-step runbook for deploying DnsJos, written so that **an AI agent (or a human)
can follow it literally**. Every step has a command and a check. Do not start a step
until the previous check passed.

> **For AI agents:** read [Rules](#0-rules-read-first) and collect every value in
> [Inputs](#1-inputs) before you run anything. When a value is missing, **ask the operator**;
> never invent hostnames, addresses, prefixes or passwords. Report every failed check
> verbatim and stop.

---

## 0. Rules (read first)

**MUST**

1. Treat every resolver node as **production**: customers are resolving through it.
2. Change nodes **one at a time**. Before touching the next node, the previous one must be
   `online` in the panel and must answer `dig @NODE example.com`.
3. Adopt a server that **already runs dnsdist** with `--adopt --no-start`, review
   `dnsjos-agent plan`, and only then start the agent (§6.2).
4. Put the client ACL and upstreams into the profile **before** adding the first node
   (§5). A node with the default profile only serves private address space.
5. Keep secrets (database password, admin password, tokens) out of chat logs, commit
   messages and files in the repository. Show them to the operator once, then refer
   to them by name.
6. Keep the previous panel binary as `/usr/local/bin/dnsjos.prev` on every upgrade (§8.1).

**NEVER**

1. Never run the installer **without `--adopt`** on a server that already runs dnsdist.
   The agent would replace its configuration with the profile's.
2. Never restart or reconfigure several nodes at the same time.
3. Never commit deployment data to the DnsJos repository: real IPs, customer prefixes,
   hostnames, tokens, `.env` files or brand images. `make hooks` installs a check for
   this (it reads patterns from outside the repo).
4. Never edit files the agent renders (`/etc/dnsdist/dnsdist.conf`, `/etc/dnsdist/dnsjos/*.lua`).
   Change the profile or the node's overrides in the panel instead.
5. Never delete or edit an applied migration.

---

## 1. Inputs

Collect these from the operator before starting.

| Name | Example | Notes |
|---|---|---|
| `PANEL_HOST` | `root@198.51.100.20` | SSH access to the panel server (Debian 12/13 or Ubuntu 22.04/24.04) |
| `PANEL_DOMAIN` | `dnsjos.example.com` | DNS **A/AAAA record must already point to `PANEL_HOST`** (needed for TLS) |
| `ADMIN_EMAIL` | `ops@example.com` | First admin account |
| `CLIENT_ACL` | `198.51.100.0/22, 2001:db8::/32` | Prefixes allowed to query the resolvers |
| `UPSTREAMS` | `192.0.2.53:53 w40, 1.1.1.1:53 w10` | Recursive resolvers behind dnsdist, with weights |
| `BLOCKPAGE_V4/V6` | `192.0.2.10` / `2001:db8::10` | Where blocked names point (optional: blocking can be off) |
| `TRUSTED` | NAT pools, monitoring, office | Sources exempt from the per-client rate limits (shared NAT addresses belong here) |
| `NODES` | `dns1 root@203.0.113.10 (existing dnsdist)` | One line per node; state whether dnsdist is **already running** there |
| `DOH_DOT` | `yes: /etc/dnsdist/tls/{cert,key}.pem` | Only if the node has a TLS certificate for its hostname |

Ports:

| Where | Port | Direction | Purpose |
|---|---|---|---|
| Panel host | 80, 443 | inbound | Caddy (TLS + ACME) in front of the panel |
| Panel host | 127.0.0.1:8080 | local | `dnsjos serve`: never expose it directly |
| Nodes | 53 udp/tcp, 443, 853 | inbound | Do53, DoH, DoT for clients |
| Nodes | → `PANEL_DOMAIN`:443 | **outbound only** | Agent pulls config and the blocklist and sends heartbeats; the panel never connects to nodes |
| Nodes | 127.0.0.1:5199, :8083, :6000, :6001 | local | dnsdist console, webserver, dnstap (blocked + analytics) |

---

## 2. Build the release (workstation or CI)

Requirements: Go 1.25, pnpm, git.

```sh
git clone https://github.com/billyriantono/dnsjos.git && cd dnsjos
make web agent            # web/dist + static agents for linux/amd64 and linux/arm64
# The panel binary must be built for the PANEL HOST's OS/arch, not the workstation's:
rm -rf webdist/dist && cp -R web/dist webdist/dist
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags release -trimpath \
  -ldflags "-s -w -X main.version=$(git describe --tags --always)" -o bin/dnsjos-linux-amd64 ./cmd/dnsjos
```

**Check**

```sh
file bin/dnsjos-linux-amd64          # → ELF 64-bit LSB executable, x86-64, statically linked
cat internal/panel/install/bin/dnsjos-agent.version   # → the same version (agents are embedded)
```

> `make release` builds `bin/dnsjos` for the machine running make. On a Mac that is a
> Mach-O binary that will not start on Linux. Use the command above (or build on the server).

---

## 3. Panel host: PostgreSQL, user, configuration

```sh
ssh $PANEL_HOST
apt-get update && apt-get install -y postgresql caddy curl ca-certificates
```

Create the database with a generated password:

```sh
DBPASS=$(openssl rand -hex 24)
sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE ROLE dnsjos LOGIN PASSWORD '$DBPASS'" \
                                         -c "CREATE DATABASE dnsjos OWNER dnsjos"
useradd --system --home /var/lib/dnsjos --shell /usr/sbin/nologin dnsjos
install -d -m 0750 -o root -g dnsjos /etc/dnsjos
```

Write `/etc/dnsjos/dnsjos.env` (mode 0640, `root:dnsjos`), starting from
[`deploy/dnsjos.env.example`](deploy/dnsjos.env.example):

```sh
ADMINPASS=$(openssl rand -base64 18)
cat > /etc/dnsjos/dnsjos.env <<EOF
DNSJOS_LISTEN=127.0.0.1:8080
DNSJOS_DATABASE_URL=postgres://dnsjos:$DBPASS@127.0.0.1:5432/dnsjos?sslmode=disable
DNSJOS_DATA_DIR=/var/lib/dnsjos
DNSJOS_PUBLIC_URL=https://$PANEL_DOMAIN
DNSJOS_SECURE_COOKIES=auto
DNSJOS_LOG_LEVEL=info
DNSJOS_BOOTSTRAP_ADMIN_EMAIL=$ADMIN_EMAIL
DNSJOS_BOOTSTRAP_ADMIN_PASSWORD=$ADMINPASS
EOF
chown root:dnsjos /etc/dnsjos/dnsjos.env && chmod 0640 /etc/dnsjos/dnsjos.env
echo "admin password (give to the operator once): $ADMINPASS"
```

**Check**

```sh
sudo -u postgres psql -Atc "select 1" dnsjos     # → 1
stat -c '%a %U:%G' /etc/dnsjos/dnsjos.env         # → 640 root:dnsjos
```

---

## 4. Panel host: install and start the panel

From the workstation:

```sh
scp bin/dnsjos-linux-amd64 $PANEL_HOST:/tmp/dnsjos
scp deploy/dnsjos.service  $PANEL_HOST:/etc/systemd/system/dnsjos.service
```

On the panel host:

```sh
install -m 0755 /tmp/dnsjos /usr/local/bin/dnsjos && rm /tmp/dnsjos
systemctl daemon-reload && systemctl enable --now dnsjos
```

Migrations run automatically on start.

**Check**

```sh
systemctl is-active dnsjos                          # → active
curl -fsS http://127.0.0.1:8080/healthz; echo       # → {"status":"ok","version":"…"}
curl -fsS http://127.0.0.1:8080/readyz;  echo       # → {"status":"ready"} (database reachable)
journalctl -u dnsjos -n 20 --no-pager | grep -E 'migrations applied|panel listening'
```

### TLS with Caddy

```sh
cat > /etc/caddy/Caddyfile <<EOF
$PANEL_DOMAIN {
	encode zstd gzip
	reverse_proxy 127.0.0.1:8080 {
		flush_interval -1
	}
}
EOF
systemctl reload caddy
```

If Caddy already serves other sites, **add** this block instead of overwriting the file.
Keep Caddy on the same host: the panel trusts `X-Forwarded-For` only from loopback.

**Check**

```sh
curl -fsS https://$PANEL_DOMAIN/healthz; echo       # → {"status":"ok",…}, with a valid certificate
```

### First login

Open `https://$PANEL_DOMAIN`, sign in as `ADMIN_EMAIL`, change the password
(avatar → **Change password**), then remove the bootstrap variables:

```sh
sed -i '/^DNSJOS_BOOTSTRAP_ADMIN_/d' /etc/dnsjos/dnsjos.env && systemctl restart dnsjos
```

---

## 5. Configure before adding nodes

In the panel (or via the API, §9):

1. **Profiles → default**, then edit and save a version:
   - **ACL:** add `CLIENT_ACL`.
   - **Upstreams:** add `UPSTREAMS`. Policy `whashedLatency` is recommended: the same name
     goes to the same upstream, and a slow upstream gets fewer names.
   - **Blocking:** set `BLOCKPAGE_V4/V6`, or disable blocking.
   - **Abuse → Trusted:** add `TRUSTED`. Shared NAT addresses must be here, or the
     per-client limit will throttle everyone behind them.
   - **Cache:** keep **stale TTL** at 3600 s so answers keep coming during an upstream outage.
2. **Publish** the version.
3. **Blocklist → Build now** (or enable only your own sources first). Check the current
   build shows **Ok**.

DoH/DoT are enabled **per node** (Node → Config → overrides), because only nodes that
have a certificate can serve them.

---

## 6. Add nodes, one at a time

For each node in `NODES`, create a token: **Nodes → Add node**. Set the node name
(**required when adopting**), the profile and a TTL. Copy the install command.

### 6.1 New server (no dnsdist yet)

```sh
ssh NODE 'curl -fsSL https://$PANEL_DOMAIN/install.sh | sudo sh -s -- --token TOKEN'
```

The installer:
- installs dnsdist 2.0 from repo.powerdns.com (pinned);
- frees port 53 from the systemd-resolved stub;
- downloads the agent and verifies its sha256;
- enrolls the node and starts the agent.

### 6.2 Existing dnsdist server (adoption, zero downtime)

```sh
ssh NODE 'curl -fsSL https://$PANEL_DOMAIN/install.sh | sudo sh -s -- --token TOKEN --adopt --no-start'
ssh NODE 'dnsjos-agent plan'
```

Read the plan. It shows the listeners, ACL size, upstreams, blocking, abuse, webserver
and blocklist. It runs `dnsdist --check-config`, and diffs the result against `/etc/dnsdist`.

- **Plan looks wrong:** fix the profile or the node's overrides in the panel and run `plan`
  again. **Do not start the agent.**
- **Plan is correct:**

  ```sh
  ssh NODE 'systemctl enable --now dnsjos-agent'
  ```

  The first apply archives `/etc/dnsdist` and swaps in the rendered config. dnsdist
  restarts once, which takes about 1 s. If it does not come back, the agent restores the
  archive exactly. Manual rollback is in [docs/OPERATIONS.md](docs/OPERATIONS.md#manual-rollback).

### 6.3 Check every node before moving on

```sh
dig @NODE example.com +short                 # resolves
dig @NODE <a blocked domain> +short          # the blockpage address (if blocking is on)
ssh NODE 'journalctl -u dnsjos-agent -n 30 --no-pager | grep -E "config applied|blocklist installed|error"'
```

In the panel the node must be **online**, with **config in sync** and **blocklist in sync**.
Only then continue with the next node.

---

## 7. Final verification

| Check | Expected |
|---|---|
| `curl -fsS https://$PANEL_DOMAIN/readyz` | `{"status":"ready"}` |
| Overview | every node online; qps and cache hit populated after ~1 min |
| Reports → Blocked | a blocked test query appears within ~2 min |
| Analytics | top domains appear within ~2 min (if analytics is on) |
| `dig @NODE example.com` on every node | answers |
| DoH/DoT (nodes with certificates) | `kdig @NODE +https example.com` / `kdig @NODE +tls example.com` |

---

## 8. Day 2

### 8.1 Upgrade the panel

```sh
scp bin/dnsjos-linux-amd64 $PANEL_HOST:/tmp/dnsjos.new
ssh $PANEL_HOST 'cp -p /usr/local/bin/dnsjos /usr/local/bin/dnsjos.prev &&
  install -m 0755 /tmp/dnsjos.new /usr/local/bin/dnsjos && rm /tmp/dnsjos.new &&
  systemctl restart dnsjos && sleep 3 && curl -fsS http://127.0.0.1:8080/readyz'
```

New migrations apply on start. A migration cannot be undone by swapping the binary back,
so take a database backup before upgrades that add migrations
(`sudo -u postgres pg_dump -Fc dnsjos > dnsjos-$(date +%F).dump`).

### 8.2 Upgrade agents and dnsdist

**Upgrades → New run** (kind `agent` or `dnsdist`). It runs one node at a time, least busy
first. Each step waits until the node is online, reports the target version and its
traffic is back. A failure pauses the run.

### 8.3 Change configuration

Save a new profile version, then **Publish** with **One node at a time** (the default
with more than one node). Follow it on **Upgrades**. A failed node is returned to its
previous version and the rollout pauses. Turn the switch off only for urgent changes that
must reach all nodes within ~15 s.

### 8.4 Emergency unblock

**Blocklist → Allowlist → Allow**: every node picks it up within ~15 s, without a restart.
See [docs/OPERATIONS.md](docs/OPERATIONS.md#emergency-unblock-allowlist).

### 8.5 Backups

Back up the database daily: `pg_dump -Fc dnsjos`. Blocklist builds can be rebuilt; node
secrets live only on the nodes (`/var/lib/dnsjos/secrets.json`, 0600).

---

## 9. API cheat sheet (for automation)

Browser-style session auth: log in once and keep the cookie. **Every non-GET request needs
the header `X-Requested-With: dnsjos`** (CSRF protection).

```sh
P=https://$PANEL_DOMAIN/api/v1; H='X-Requested-With: dnsjos'
curl -c jar -H "$H" -H 'Content-Type: application/json' \
  -d '{"email":"ADMIN_EMAIL","password":"…"}' $P/auth/login

curl -b jar $P/nodes                                              # status of every node
curl -b jar $P/profiles                                           # profile ids, live versions
curl -b jar $P/profiles/PID/versions/LIVE                         # current spec (edit → new version)
curl -b jar -H "$H" -H 'Content-Type: application/json' \
  -d '{"spec":{…},"comment":"why"}' $P/profiles/PID/versions      # → {"version": N, …}
curl -b jar -H "$H" -X POST "$P/profiles/PID/versions/N/publish?staged=true"
curl -b jar $P/upgrades                                           # follow the rollout
curl -b jar -H "$H" -H 'Content-Type: application/json' \
  -d '{"node_name":"dns4","ttl_hours":24}' $P/enrollment-tokens   # → token + install_command
```

- **Publish the `version` the create call returned.** Never assume it is the latest+1:
  someone may be saving drafts in the UI at the same time.
- Node overrides (`PATCH /nodes/{id}` with `{"overrides": {…}}`) **replace** the whole
  override document, and arrays inside it replace the profile's arrays (JSON merge patch).
- Read-only integrations (Grafana, scripts) should use an API token instead of a login:
  **Settings → API tokens**, then send `Authorization: Bearer djt_…` on GET routes.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `exec format error` when starting the panel | The binary was built for the workstation. Rebuild with `GOOS=linux` (§2). |
| Login works on `http://` but not on `https://` (or vice versa) | `DNSJOS_SECURE_COOKIES=auto` follows `DNSJOS_PUBLIC_URL`; make them agree. |
| Install fails with `agent download failed` | The panel was built without `make agent`, so no agent is embedded. |
| Enroll fails: "a node with this name already exists" | Re-adopting needs a token **scoped to that node name**. |
| Node `degraded`, `apply_error` | Read the error on the node page. The agent already rolled back; fix the profile or overrides. |
| Node `offline` | The agent cannot reach the panel. Check outbound 443 from the node and `journalctl -u dnsjos-agent`. |
| Rollout refused: `nodes not ready` | A node is not online. Fix it first; rollouts never start on an unhealthy fleet. |
| Many clients hit the rate limit | They share NAT addresses; add those prefixes to **Abuse → Trusted**. |
| dnsdist warns about a plain-text password | Agent older than the panel; run an agent upgrade (§8.2). |

More background: [docs/OPERATIONS.md](docs/OPERATIONS.md) (runbooks) and
[docs/SPEC.md](docs/SPEC.md) (the full contract).
