# DnsJos — Specification (v1)

DnsJos is a control panel for a fleet of **dnsdist** resolvers run by an ISP that
must enforce the Indonesian TrustPositif blocklist. One panel manages N dnsdist
nodes. Every node runs a small agent that pulls its desired state from the panel.

This document is the contract every part of the code base follows. When code and
spec disagree, fix one of them in the same change.

---

## 1. Goals

1. **Monitor** every dnsdist node: up/down, qps, cache hit ratio, latency, backend
   health, blocked queries, abusive clients, CGK redirection state.
2. **Control** every node from one place: listeners (Do53/DoH/DoT), client ACL,
   upstreams + weights + policy, blockpage, abuse thresholds, CGK redirection.
   Changes are versioned, previewable, validated on the node and rolled back on failure.
3. **Build the blocklist once** in the panel (TrustPositif + custom lists), publish
   a CDB file, and have every node download the final CDB (checksum-verified).
4. **Add nodes easily**: `curl -fsSL https://PANEL/install.sh | sudo sh -s -- --token T`.
5. **Ministry reporting**: blocked-query totals and top blocked domains per
   period/node, exportable as CSV.
6. **Fast and small**: one static Go binary for the panel (idle RSS target < 40 MB),
   one static Go binary for the agent (idle RSS target < 25 MB).

Non-goals for v1: multi-tenant, IPv6-only fleets, Windows, non-Debian/Ubuntu nodes,
editing arbitrary raw dnsdist Lua (an "extra Lua" text field is allowed, see §6.4).

---

## 2. Architecture

```
            ┌───────────────────── Panel (dnsjos) ─────────────────────┐
 Browser ──►│ HTTP :8080  /api/v1/*  (session cookie)                   │
            │             /agent/v1/* (node bearer token)               │
            │             /install.sh, /dl/agent/{os}/{arch}            │
            │             /*  → embedded React SPA (web/dist)           │
            │ jobs: blocklist builder, retention, node-offline detector │
            │ PostgreSQL (pgx)                                          │
            └───────────────▲──────────────────────────────────────────┘
                            │ HTTPS, pull every 10-30 s (outbound only)
        ┌───────────────────┴───────────────────┐
        │ dnsjos-agent (root, systemd)           │   per node
        │  - GET desired config (ETag/version)   │
        │  - render /etc/dnsdist/dnsdist.conf    │
        │  - dnsdist --check-config, apply, roll │
        │  - GET blocklist CDB (ETag + sha256)   │
        │  - POST heartbeat (metrics, backends,  │
        │    dynblocks, versions, errors)        │
        │  - dnstap listener 127.0.0.1:6000 →    │
        │    aggregate blocked qnames → POST     │
        │  - CGK refresh every 6 h (local probe) │
        └───────────────┬───────────────────────┘
                        │ console 127.0.0.1:5199 / webserver 127.0.0.1:8083
                    dnsdist 2.x
```

* Panel never connects to nodes. Nodes only need outbound HTTPS to the panel.
* Panel is stateless apart from Postgres + the blocklist artifact directory.

---

## 3. Repository layout

```
DnsJos/
  go.mod                       module github.com/billyriantono/dnsjos  (Go 1.25)
  Makefile                     build, test, web, agent, release
  cmd/dnsjos/main.go           panel
  cmd/dnsjos-agent/main.go     agent
  internal/
    panel/
      config/        env config
      db/            pgx pool, migration runner (embeds ../../../migrations)
      httpx/         JSON helpers, errors, middleware (logging, recover, auth, CSRF)
      auth/          users, sessions, login, password hashing (bcrypt)
      nodes/         node CRUD, enrollment, agent API, heartbeat ingest, status
      configs/       desired-state CRUD, versioning, preview, publish
      blocklist/     sources, builder (fetch→normalize→CDB), artifacts, serving
      reports/       metrics timeseries, blocked-domain report, offenders, CSV
      audit/         audit log
      install/       install.sh template, agent binary download (embedded)
      jobs/          tiny scheduler (ticker goroutines, no external queue)
      server/        wiring, routes, SPA serving
    agent/
      client/        panel HTTP client (auth, ETag, retries)
      apply/         render → validate → swap → reload/restart → rollback
      dnsdist/       console client (dnsdist -c) + local webserver API client
      collect/       stats/backends/dynblocks collection → heartbeat
      dnstap/        framestream listener + blocked-qname aggregation
      cgk/           Cloudflare CGK prober (port of cgk-refresh)
      blocklist/     CDB download + atomic install
    shared/
      api/           JSON types shared by panel and agent (single source of truth)
      dnsconf/       renderer: DesiredConfig → dnsdist.conf (Lua) + Lua modules
      cdb/           CDB key encoding helpers (domain + IPv4 wire format)
  migrations/        NNNN_name.up.sql (forward-only, embedded)
  web/               React 19 + Vite + TS + Tailwind v4 + shadcn/ui + react-icons
  deploy/            systemd units, Caddyfile example, env example
  docs/              SPEC.md, INSTALL.md, OPERATIONS.md
```

---

## 4. Tech choices

| Area | Choice |
|---|---|
| Panel/agent language | Go 1.25, `CGO_ENABLED=0` static binaries |
| HTTP | stdlib `net/http` ServeMux (Go 1.22 method+path patterns). No web framework. |
| DB | PostgreSQL ≥ 14, `github.com/jackc/pgx/v5/pgxpool`, hand-written SQL. No ORM. |
| Migrations | embedded `migrations/*.up.sql`, applied in order at startup, tracked in `schema_migrations(version text pk, applied_at)`, each in a transaction. Forward-only. |
| Logging | `log/slog` JSON handler |
| Passwords | bcrypt (cost 12) |
| CDB | `github.com/colinmarc/cdb` (standard djb cdb, read by dnsdist's tinycdb) |
| dnstap | `github.com/dnstap/golang-dnstap`, `github.com/farsightsec/golang-framestream`, `github.com/miekg/dns` |
| Frontend | React 19, Vite, TypeScript strict, Tailwind v4, shadcn/ui (Radix), react-icons, TanStack Query v5, React Router v7, Recharts (shadcn charts) |
| Package manager | pnpm |

Keep dependencies minimal. Anything not listed needs a reason in the PR.

---

## 5. Database schema

The full initial schema is `migrations/0001_init.up.sql`. Summary:

* `users(id uuid, email citext unique, name, password_hash, role 'admin'|'viewer', disabled, created_at, last_login_at)`
* `sessions(id_hash bytea pk, user_id, created_at, expires_at, ip, user_agent)` — cookie holds
  a random 32-byte token; DB stores sha256(token).
* `nodes(id uuid, name unique, hostname, public_ip inet, labels jsonb, status
  'pending'|'online'|'degraded'|'offline', token_hash bytea, enrolled_at, last_seen_at,
  agent_version, dnsdist_version, os, applied_config_version int, applied_blocklist_sha256,
  last_error text, created_at, deleted_at, adopted bool, seeded_blocklist_sha256)` — the
  last two are added by `0002_adopt` (§17)
* `enrollment_tokens(id, token_hash, node_name, labels, created_by, expires_at, used_at, used_by_node)`
* `config_profiles(id uuid, name unique, description, created_at)` — a profile is a
  reusable desired state; each node references exactly one profile.
* `config_versions(id bigserial, profile_id, version int, spec jsonb, comment, created_by,
  created_at, published bool)` unique(profile_id, version). `spec` is `api.ConfigSpec`.
* `nodes.profile_id → config_profiles` and optional `nodes.overrides jsonb` (per-node
  values merged over the profile: listen IPs, weights, etc. — see §6.3).
* `blocklist_sources(id, name, kind 'trustpositif_domains'|'trustpositif_ips'|'url_domains'|'url_ips'|'manual_domains'|'manual_ips'|'whitelist', url, content text, enabled, etag, last_modified, last_fetch_at, last_status, entries int)`
* `blocklist_builds(id bigserial, started_at, finished_at, status 'running'|'ok'|'failed'|'skipped', domains int, ips int, whitelisted int, size_bytes bigint, sha256 text, error text, trigger 'schedule'|'manual')`
  — the newest `ok` build is "current". Artifact file: `$DATA_DIR/blocklist/<sha256>.cdb`.
* `metrics_minutely(node_id, ts timestamptz (minute), queries, responses, cache_hits,
  cache_misses, blocked, dyn_blocked, rule_drops, servfail, nxdomain, noerror,
  latency_avg_ms real, cgk_rewrites, pk(node_id, ts))` — retention 35 days.
* `backend_status(node_id, address, pool, state, weight, order, qps, latency_ms,
  queries bigint, drops bigint, updated_at, pk(node_id,address))`
* `blocked_daily(day date, node_id, qname text, qtype text, count bigint, pk(day,node_id,qname,qtype))` — retention 800 days.
* `offender_events(id bigserial, node_id, client inet/cidr text, stage 'warning'|'blocked', reason, first_seen, last_seen, blocks bigint)` — unique open event per (node, client, reason) until 10 min unseen.
* `audit_log(id bigserial, at, user_id, action, target_type, target_id, details jsonb, ip)`
* `settings(key text pk, value jsonb)` — panel-wide settings (builder schedule, retention, public URL,
  `blocklist_download_segments`).
* `ingested_batches(node_id, batch_key, at, pk(node_id,batch_key))` — `0005`: committed
  agent batch keys (§8 Idempotency-Key), pruned after 7 days by the hourly retention job.
* `allowlist(id uuid, kind 'domain'|'ip', value text, reason text, created_by → users (set null),
  created_at, expires_at null, unique(kind, value))` — `0006`: the emergency allowlist (§7.5).
  `value` is normalized (domain: lowercase, no trailing dot; ip: address or masked CIDR).
  Rows with `expires_at ≤ now()` are ignored everywhere and deleted by an hourly job.
* `api_tokens(id uuid, name, token_hash bytea unique (sha256), prefix (first 8 chars),
  created_by → users (set null), created_at, last_used_at, expires_at null, revoked_at null)`
  — `0007`: read-only API tokens (§10).

---

## 6. Desired config (ConfigSpec)

`internal/shared/api/config.go` defines `ConfigSpec` (JSON). All fields have safe
defaults (`api.DefaultConfigSpec()`). Validation (`spec.Validate() error`) runs in the
panel on save and in the agent before rendering.

```jsonc
{
  "listen": {
    "do53": {"enabled": true, "addresses": ["0.0.0.0:53", "[::]:53"], "reuse_port_listeners": 1},
    "doh":  {"enabled": false, "addresses": ["0.0.0.0:443", "[::]:443"], "path": "/dns-query"},
    "dot":  {"enabled": false, "addresses": ["0.0.0.0:853", "[::]:853"]},
    "tls":  {"cert_file": "/etc/dnsdist/tls/cert.pem", "key_file": "/etc/dnsdist/tls/key.pem"}
  },
  "acl": ["10.0.0.0/8", "100.64.0.0/10", "…"],            // client allowlist
  "upstreams": {
    "policy": "whashed",            // whashed | wrandom | leastOutstanding | roundrobin | firstAvailable
    "servers": [ {"address": "192.0.2.53:53", "weight": 40, "order": 1, "sockets": 4, "name": "resolver1"} ],
    "health_check_interval_s": 1
  },
  "cache": {"enabled": true, "max_entries": 500000, "min_ttl": 0, "max_ttl": 86400, "stale_ttl": 60},
  "blocking": {
    "enabled": true,
    "blockpage_ipv4": "192.0.2.10",
    "blockpage_ipv6": "2001:db8::10",
    "txt": "BLOCKED. UU No 19, pasal 40 (2a dan 2b). Permen Kominfo No 5 2020",
    "soa": "blocked.invalid. nobody.blocked.invalid. 1 3600 1200 604800 10800",
    "ns": "ns.blocked.invalid",
    "block_response_ips": false,    // opt-in: rewrite A answers whose IP is in the IP list (§6.4)
    "log_blocked": true             // dnstap → agent → blocked_daily
  },
  "abuse": {
    "enabled": true,
    "per_client_qps": 50, "per_client_burst": 250,
    "dyn_query_rate": 40, "dyn_nxdomain_rate": 15, "dyn_servfail_rate": 15,
    "dyn_window_s": 10, "dyn_block_s": 300, "dyn_action": "truncate",   // truncate | drop | refused
    "trusted": ["127.0.0.0/8", "::1/128"]
  },
  "cgk": {
    "enabled": true,
    "rewrite_pools": ["104.20.0.0/16", "…"],       // candidates; the agent measures which are non-CGK
    "alias_pools": ["104.16.0.0/16", "…"],
    "test_sites": ["kincir.com", "suara.com", "jagoanhosting.com", "dewaweb.com"],
    "exclude": ["argotunnel.com", "gitlab.com", "…"],
    "aliases_wanted": 8, "min_ok": 3, "refresh_interval_h": 6
  },
  "tuning": {"udp_buffer_bytes": 16777216, "tcp_workers": 0, "extra_lua": ""},
  "webserver": {"listen": "127.0.0.1:8083", "prometheus_acl": ["127.0.0.1/32"]},
  "analytics": {"enabled": true, "sample_rate": 1, "top_k": 5000, "stream_addr": "127.0.0.1:6001"}  // §19
}
```

Specs stored before a section existed decode with that section's defaults
(`ConfigSpec.UnmarshalJSON`; today only `analytics`). When `analytics.enabled`,
`sample_rate` must be 1..1000, `top_k` 100..50000 and `stream_addr` an ip:port.

### 6.1 Defaults

`api.DefaultConfigSpec()` returns exactly the production values currently in use
(see `docs/SPEC.md` §6 example and §12). The client ACL default is:
`10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16`.

### 6.2 Versioning

Saving a profile creates a new `config_versions` row (draft). **Publish** marks it
published; nodes on that profile get the newest *published* version. The panel shows a
diff between any two versions (JSON diff rendered in UI) and a rendered-Lua preview.

### 6.3 Per-node overrides

`nodes.overrides` is a JSON merge-patch (RFC 7396) applied over the profile spec.
Typical: a node-specific listen address, extra ACL entries, different weights.
The effective spec is computed by `api.MergeSpec(profile, overrides)`.

### 6.4 Renderer (`internal/shared/dnsconf`)

`Render(spec api.ConfigSpec, node api.NodeRuntime) (files map[string][]byte, err error)`
returns every file the agent writes under `/etc/dnsdist/` (paths relative to that dir):

* `dnsdist.conf` — generated, header comment `-- generated by dnsjos, do not edit`.
* `dnsjos/blocking.lua`, `dnsjos/abuse.lua`, `dnsjos/cgk.lua` — modules `dofile`d by
  dnsdist.conf (only when the feature is enabled).
* CGK data files `dnsjos/cgk-aliases.txt`, `dnsjos/cgk-rewrite.txt` are **not** rendered;
  the agent's CGK prober owns them (fallback lists are embedded in cgk.lua).

`NodeRuntime` carries node-specific secrets and paths the panel must not store in the
spec: `console_key` (base64 32 bytes), `web_password`, `web_api_key` (generated by the
agent on first run and persisted in `/var/lib/dnsjos/secrets.json`, mode 0600),
`cdb_path` (`/var/lib/dnsjos/blocklist/current.cdb`), `dnstap_addr` (`127.0.0.1:6000`),
`hostname`.

Rendering rules (must be byte-for-byte deterministic for the same input):

1. `setUDPSocketBufferSizes(n, n)` first (before listeners).
2. `setACL({...})` with spec.acl.
3. Do53: for each address, `addLocal(addr, {reusePort=true})` repeated
   `reuse_port_listeners` times (first one via `setLocal`).
4. DoH: `addDOHLocal(addr, cert, key, path)`; DoT: `addTLSLocal(addr, cert, key)`.
5. `controlSocket("127.0.0.1:5199")`, `setKey(console_key)`, `setConsoleACL("127.0.0.1/32")`.
6. `webserver(webserver.listen)`, `setWebserverConfig({password=…, apiKey=…, acl=…, statsRequireAuthentication=true})`.
7. Packet cache: `newPacketCache(max_entries, {minTTL=…, maxTTL=…, staleTTL=…})` on pool `""`.
8. Upstreams: `newServer({address=, name=, weight=, order=, sockets=, pool="", healthCheckMode="up"? no: default})`, `setServerPolicy(<policy>)`.
9. Blocking (blocking.lua):
   * `newCDBKVStore(cdb_path, 60)` (re-open when the file changes).
   * Query rule: `KeyValueStoreLookupRule(kvs, KeyValueLookupKeySuffix(0, true))` →
     `SetTagAction('dnsjos','blocked')`.
   * If `log_blocked`: `DnstapLogAction(hostname, newFrameStreamTcpLogger(dnstap_addr))`
     on the tag, **before** the answer actions.
   * Answers on the tag: A → `SpoofAction(blockpage_ipv4)`, AAAA → `SpoofAction(blockpage_ipv6)`,
     TXT → `SpoofRawAction` (txt), SOA/NS → raw SOA/NS, **every other qtype → NODATA**
     (`RCodeAction(DNSRCode.NOERROR)`), matching the production behaviour that blocks
     HTTPS/SVCB lookups.
   * If `block_response_ips`: response Lua rules that, when **any** A record's IP key
     (see §7.3) is in the KVS, rewrite **every** A record of the answer to
     `blockpage_ipv4` with TTL 60 (same-length in-place rewrite, so the client never gets
     a mix of blockpage and real addresses), count it once in
     `dnsjos-response-ip-blocked`, log it, and mark it `SetSkipCacheResponseAction()` so
     every blocked answer is counted/logged and CDB updates apply immediately. Only A
     answers are checked (the IP list is IPv4-only). This is a behaviour change from the
     legacy production rules, whose IP match never altered answers, so it is **off by
     default** (`DefaultConfigSpec`, the web profile defaults) and adoption sends
     `blocking.block_response_ips: false` explicitly in its node overrides. Profiles
     stored with `true` keep it.
   * Allowlist (§7.5): the agent-owned files `dnsjos/allowlist-domains.txt` and
     `dnsjos/allowlist-ips.txt` (one entry per line; missing file = empty list) are loaded
     at startup and by the global console function `dnsjosAllowReload()`, which rebuilds a
     `SuffixMatchNode` + `NetmaskGroup`, swaps them in, expunges the packet cache for every
     added/removed name (the whole cache when an IP entry is removed) and returns
     `allowlist: <n> domains, <n> ips, <n> invalid`. A query tagged blocked whose qname is
     equal to or below an allowed name is re-tagged `allowed` (rule `dnsjos-allowlist`)
     **before** any blocked-answer rule, so it resolves normally; answers whose A record is
     in the allowed IP set are never rewritten by the response-IP rule. No restart.
   * Every rule gets its own selector object (dnsdist counts hits on the selector, so a
     shared `TagRule` inflates every rule that uses it).
10. Abuse (abuse.lua): `MaxQPSIPRule(per_client_qps, 32, 64, burst)` → `DropAction()`
    excluding `trusted` (**MaxQPSIPRule matches clients OVER the rate — never wrap it in
    NotRule**), moved to top with `mvRuleToTop()`; `dynBlockRulesGroup()` with
    setQueryRate / setRCodeRate(NXDOMAIN) / setRCodeRate(SERVFAIL), warning at half rate,
    `excludeRange(trusted)`, applied in `maintenance()`.
11. CGK (cgk.lua): port of the production cgk.lua — response Lua that rewrites A records in
    the measured rewrite ranges to aliases, stable per qname, exclude SuffixMatchNode,
    metrics `cgk-rewrites`, `cgk-aliases`, `cgk-rewrite-ranges`, global `cgkReload()`.
12. `extra_lua` appended verbatim at the end, fenced by comments.
13. Custom metrics: `declareMetric` for dnsjos counters.
14. Rule names are unique (dnsdist exports `dnsdist_rule_hits{id=<name>}`; duplicates
    break the Prometheus exposition) and stable for dashboards: the legacy names
    `per-client-qps-cap` (abuse cap) and `cloudflare-cgk` (CGK rewrite) are kept; the
    analytics stream uses `dnsjos-analytics-response` / `-cachehit` / `-self`. Upstream
    `name=` is emitted only when set; it becomes the Prometheus `server` label (unnamed
    servers are labelled `ip:port`, as before adoption).

The renderer has golden-file tests (`testdata/*.golden`) for: defaults, DoH+DoT, abuse
off, cgk off, multiple upstreams with weights, extra_lua.

---

## 7. Blocklist builder (`internal/panel/blocklist`)

### 7.1 Sources

Defaults seeded by migration: TrustPositif domains
`https://trustpositif.komdigi.go.id/assets/db/domains_isp`, TrustPositif IPs
`https://trustpositif.komdigi.go.id/assets/db/ipaddress_isp`. Admins can add URL lists,
manual lists (textarea) and a whitelist.

Fetch with a browser User-Agent, `If-None-Match` / `If-Modified-Since`, 120 s timeout,
streaming (never hold the 220 MB body in memory as a string).

**Parallel download.** When the conditional request says a download is needed (or on a
forced build) and the 200 carries `Accept-Ranges: bytes`, `Content-Length` ≥ 8 MiB and a
strong `ETag`, the body is fetched as `blocklist_download_segments` (setting, 1..16, default
8; 1 = always one stream) parallel byte ranges written with `WriteAt` into a preallocated
temp file. Every range request carries `If-Range: <that ETag>`; a range answer that is not
a `206` for exactly the requested range with the same ETag aborts the ranges, and so does a
segment that still fails after 3 retries (each resuming from the segment's progress): the
source is then fetched again as one clean single-stream GET. The total must equal
`Content-Length`; the file is fsynced and renamed into place. Small files, servers without
ranges and `segments = 1` keep the single stream. The source's `last_status` reads
`ok: 217.3 MB in 2.9 s (74.9 MB/s, 8 streams)` (`1 stream` for a single stream) and the
same fields (`bytes`, `seconds`, `mb_per_s`, `streams`) are logged.

### 7.2 Build

* Schedule: every 3 h (setting), plus "Build now" button.
* If every URL source returns 304 and manual/whitelist unchanged → build `skipped`.
* A 304 on one source must **not** drop that source: keep the last successful raw
  download of every URL source on disk (`$DATA_DIR/blocklist/sources/<id>.txt`) and always
  build from all enabled sources.
* Normalize domains: lowercase, strip comments/whitespace/scheme/path/port, trailing dot,
  IDN → punycode, validate charset `[a-z0-9._-]`, labels ≤ 63, name ≤ 253.
* Whitelist entries are removed (exact name match; whitelist `example.com` also removes
  `*.example.com` entries). Active allowlist entries (§7.5) are removed the same way (IP
  entries by prefix) and counted in `whitelisted`; the allowlist version is part of the
  input fingerprint, so an allowlist change makes the next scheduled build rebuild.
* Sanity floor: refuse to publish if domains < 100 000 **when the TrustPositif domains
  source is enabled** (status `failed`, keep previous build).
* Write CDB to `<tmp>` in the same dir, fsync, rename to `<sha256>.cdb`. Keep the last 3.
* Memory: stream keys straight into the CDB writer; duplicates are allowed (dnsdist uses the
  first match), so no in-memory dedupe set. Report duplicates count only if cheap.

### 7.3 CDB key format (`internal/shared/cdb`)

Must match what dnsdist's `KeyValueLookupKeySuffix(0, true)` / `KeyValueLookupKeyQName(true)`
look up: **DNS wire format, lowercase**, e.g. `example.com` → `\x07example\x03com\x00`.
Value: empty. IPv4 entries: labels of the dotted quad in wire form, e.g. `1.2.3.4` →
`\x011\x012\x013\x014\x00` (this is the format used in production). IPv4 CIDR entries are
expanded only if ≤ /24 (≤ 256 keys), larger ones are skipped and counted.

### 7.4 Serving

`GET /agent/v1/blocklist` → 200 with the current CDB (`ETag: "<sha256>"`,
`X-Dnsjos-Sha256`, `Content-Length`), 304 on matching `If-None-Match`. Served with
`http.ServeContent` (supports Range, so agents can resume).

---

### 7.5 Allowlist (emergency unblock)

The regulator's list sometimes contains shared infrastructure (a CDN hostname or address)
whose blocking takes down unrelated sites. The allowlist overrides the blocklist within
seconds, fleet-wide, without a build or a dnsdist restart:

* Admins add `domain` entries (the name **and every name below it**) or `ip` entries (an
  address or CIDR; IPv4 ≥ /8, IPv6 ≥ /16) with a reason and an optional expiry. TLDs and
  IPs given as domains are rejected (422 `invalid_entry`).
* The active set has a version (`api.Allowlist.version`: 16 hex chars of sha256 over the
  sorted entries; never empty). The panel announces it in `AgentConfig.allowlist_version`
  and in every `HeartbeatAck.allowlist_version`; an agent seeing a new version fetches
  `GET /agent/v1/allowlist`, writes the two files of §6.4 atomically (0644) and calls
  `dnsjosAllowReload()`. With the default 10 s heartbeat the change is live on every node
  within ~15 s. An empty/missing `allowlist_version` means a panel without allowlist
  support: the agent does nothing. The config ETag does not include the allowlist.
* Builds leave allowlisted entries out of the CDB (§7.2), so a permanent entry also holds
  on a node that restarts before its first allowlist sync. Deleting (or expiring) an entry
  re-blocks immediately on the nodes only for names still in the node's current CDB; names
  dropped from the CDB by an earlier build come back with the next build (run **Build now**
  to re-block at once).
* The blocklist lookup reports `allowed` and the matching entry, so the UI can show
  "blocked by the list but allowed".

## 8. Agent protocol (`/agent/v1`, bearer = node token)

All agent requests carry `Authorization: Bearer <node_token>` and
`X-Dnsjos-Agent: <version>`. Node token = 32 random bytes, base64url; panel stores sha256.

| Method & path | Body → Response |
|---|---|
| `POST /agent/v1/enroll` (no bearer; enrollment token in body) | `api.EnrollRequest{token, hostname, os, arch, agent_version, dnsdist_version, public_ip, adopt, adopt_overrides}` → `api.EnrollResponse{node_id, name, node_token, poll_interval_s}`; 401 `invalid_token`; 422 `invalid_config` when `adopt_overrides` does not merge into a valid spec (the token is not consumed) |
| `GET /agent/v1/config` (`If-None-Match: "<version>"`) | 304 or `api.AgentConfig{version, spec (effective, merged), profile, blocklist{sha256,size,url}, poll_interval_s, heartbeat_interval_s, allowlist_version}`; 404 `no_config` (profile has nothing published); 409 `invalid_config` (overrides no longer valid); 409 `no_blocklist` (adopted node, see §17) |
| `GET /agent/v1/blocklist` | CDB stream (see §7.4) |
| `GET /agent/v1/allowlist` (`If-None-Match: "<version>"`) | 304 or `api.Allowlist{version, domains[], ips[]}` with `ETag: "<version>"` (§7.5; only unexpired entries) |
| `POST /agent/v1/heartbeat` | `api.Heartbeat` → `api.HeartbeatAck{config_version, blocklist_sha256, commands[], allowlist_version}` |
| `POST /agent/v1/blocked` | `api.BlockedBatch{items:[{day, qname, qtype, count}]}` → 204 (Idempotency-Key, below) |
| `POST /agent/v1/analytics` | `api.AnalyticsBatch` (§19; body ≤ `api.AnalyticsMaxBody` = 10 MiB, checked by `AnalyticsBatch.Validate` → 422 `invalid_batch`) → 204 (Idempotency-Key, below) |
| `POST /agent/v1/cgk` | `api.CGKReport{measured_at, aliases[], rewrite_ranges[], pools:[{net, colos[]}], ok bool, message}` → 204 |

**Idempotency.** Agents send `Idempotency-Key: <batch key>` (`api.IdempotencyHeader`, ≤ 255
bytes, else 400) on `/blocked` and `/analytics`; the key is the same on every retry and
spool replay of a batch. The panel inserts `(node_id, key)` into `ingested_batches` in the
same transaction as the batch's upserts (`ON CONFLICT DO NOTHING`); when the key already
exists the batch is skipped and still answered 204. Without the header the batch is stored
as before.

`api.Heartbeat`:
```jsonc
{
  "time": "RFC3339",
  "agent_version": "…", "dnsdist_version": "…", "os": "…", "uptime_s": 0,
  "dnsdist_running": true,
  "applied_config_version": 12, "apply_error": "",
  "blocklist_sha256": "…", "blocklist_error": "",
  "system": {"load1": 0.1, "mem_total_mb": 7940, "mem_avail_mb": 6000, "disk_free_mb": 1000},
  "counters": {"queries": 0, "responses": 0, "cache_hits": 0, "cache_misses": 0,
               "blocked": 0, "dyn_blocked": 0, "rule_drops": 0, "servfail": 0,
               "nxdomain": 0, "noerror": 0, "cgk_rewrites": 0},   // monotonically increasing, raw dnsdist values
  "latency_avg_ms": 0.0,
  "backends": [{"address": "", "name": "", "pool": "", "state": "up", "weight": 1, "order": 1,
                "qps": 0, "latency_ms": 0, "queries": 0, "drops": 0}],
  "dynblocks": [{"client": "1.2.3.4/32", "reason": "", "stage": "blocked", "seconds_left": 0, "blocks": 0}],
  "cgk": {"aliases": 8, "rewrite_ranges": 9, "last_refresh": "RFC3339", "last_error": ""},
  // upgrade inventory (§18): cached result of the last refresh, repeated every heartbeat
  "dnsdist_candidate": "", "dnsdist_available": [], "dnsdist_repo_series": "20",
  "inventory_at": null,                      // RFC3339, null until the first refresh
  "last_upgrade": null,                      // {kind: "dnsdist"|"agent", from, to, ok, error, at}
  "upgrade_in_progress": false
}
```

Panel ingest: store latest heartbeat in memory (map node_id→latest, for the live UI) and
in `nodes` columns; convert counter deltas (handle dnsdist restarts: a counter going down
means reset → delta = new value) into `metrics_minutely` upserts (add to the minute bucket);
upsert `backend_status`; open/refresh/close `offender_events`. A node is `offline` after
3 × heartbeat interval without heartbeat (job every 15 s), `degraded` when dnsdist is not
running, apply/blocklist error, or any backend down.

`commands[]` (optional): `api.Command{id, type, version?, series?}` — types (`api.CommandTypes`)
`cgk_refresh`, `restart_dnsdist`, `reapply`, and for §18 `check_updates`,
`upgrade_dnsdist` (+ `version`), `set_dnsdist_series` (+ `series`), `upgrade_agent` —
queued by the UI (params stored in `node_commands.params`), delivered once, acked by next
heartbeat (`acked_commands` field in Heartbeat). Upgrade commands are acked when started;
their outcome arrives later as `last_upgrade`. Panel ingest stores the inventory fields and
`last_upgrade` in the `nodes` columns of the same name.

---

## 9. Agent behaviour (`cmd/dnsjos-agent`)

* Config file `/etc/dnsjos/agent.json` (`{panel_url, node_id, node_token}`, mode 0600).
  `dnsjos-agent enroll --panel URL --token T` performs enrollment and writes it.
* Main loop (single process, goroutines):
  1. **Config**: poll `GET /config` every `poll_interval_s` (default 15 s) with ETag. On
     new version: `dnsconf.Render` → write to a staging dir → `dnsdist --check-config -C
     <staging>/dnsdist.conf` (staging dir contains the modules; paths inside the rendered
     conf are absolute to `/etc/dnsdist`, so check with a temporary copy placed under
     `/etc/dnsdist/.dnsjos-staging/` and `dofile` paths pointing there — simplest: render
     with a `base_dir` parameter) → back up current files to
     `/var/lib/dnsjos/backup/<timestamp>/` (keep 5) → swap → `systemctl restart dnsdist`
     (listeners/servers change) → wait until the console answers (`showVersion()`) within
     20 s → on failure restore backup + restart + report `apply_error`.
  2. **Blocklist**: every 60 s compare panel sha256 with local; download to
     `current.cdb.tmp`, verify sha256, rename atomically. No dnsdist restart needed
     (CDBKVStore refresh delay 60 s).
  2a. **Allowlist** (§7.5): when `allowlist_version` (config or heartbeat ack) differs from
     the applied one, `GET /allowlist` with ETag, write `<BaseDir>/dnsjos/allowlist-domains.txt`
     and `allowlist-ips.txt` (one entry per line, temp file + rename, 0644) and call
     `dnsjosAllowReload()` over the console; retry on failure. No restart.
  3. **Heartbeat** every 10 s: read `/jsonstat?command=stats` and
     `/api/v1/servers/localhost` from the local webserver (API key), dynblocks via
     `/jsonstat?command=dynblocklist`, system stats from `/proc`.
  4. **dnstap**: framestream TCP listener on `127.0.0.1:6000`; decode CLIENT_QUERY
     messages; aggregate `(day, qname, qtype) → count` in memory; flush every 60 s
     to `POST /blocked` (retry with backoff; keep unsent batches on disk
     `/var/lib/dnsjos/blocked-spool/` so a panel outage loses nothing).
  5. **CGK**: every `refresh_interval_h` (and on command): port of `cgk-refresh`
     (pools sampled with HTTPS to `www.cloudflare.com/cdn-cgi/trace` via the candidate IP,
     test sites compared by status code, fastest `aliases_wanted`), write the two txt files,
     call `cgkReload()` via console, POST report. Never rewrite dedicated/enterprise space:
     only `rewrite_pools` from the spec may appear in the output.
* Runs as root (needs to write /etc/dnsdist and restart dnsdist). Logs to journald (slog JSON).
* **Test mode** (used by CI and local end-to-end tests, works on macOS):
  `--root DIR` prefixes every filesystem path (`/etc/dnsdist` → `DIR/etc/dnsdist`, …),
  `--no-systemd` skips `systemctl` and skips `dnsdist --check-config` when the `dnsdist`
  binary is absent (logs a warning, treats the config as valid), and
  `--dnsdist-web URL` points the collector at a fake/local dnsdist webserver. When
  dnsdist is unreachable the heartbeat reports `dnsdist_running=false` with zero counters.
* Resource target: < 25 MB RSS idle; dnstap aggregation bounded (cap 200 000 distinct
  keys per flush window; overflow counted as `_other_`).

---

## 10. Panel HTTP API (`/api/v1`, session cookie `dnsjos_session`)

Auth: `POST /api/v1/auth/login` `api.LoginRequest{email,password}` → sets cookie (HttpOnly,
Secure when TLS, SameSite=Lax, 12 h sliding) and returns `api.Session{user, expires_at}`.
`POST /auth/logout` → 204. `GET /auth/me` → `api.Session`. `PATCH /auth/password`
`api.PasswordChange{current,new}` → 204 (any signed-in role; signs out the user's other sessions).
Passwords (change, user create, admin reset via `UserPatch.password`) must be 8..72 bytes,
else 422 `weak_password`.
Mutating requests must send header `X-Requested-With: dnsjos` (CSRF guard) — the SPA's
fetch wrapper always adds it. Login rate limit: 10/min per IP.
Roles: `viewer` = GET only; `admin` = everything.
Read-only API tokens: every `Viewer` route (GET-only by construction) also accepts
`Authorization: Bearer djt_…` (`djt_` + base64url of 32 random bytes). The token is valid
when sha256(token) is in `api_tokens`, not revoked, not expired and its creator is an
existing, enabled user (disabling or deleting the admin disables their tokens); the request runs as a
synthetic viewer principal with no user id (`GET /auth/me` returns it with an empty `id`).
Session, admin and agent routes and every non-GET method never accept an API token (no
cookie → 401). Invalid, expired or revoked token → 401 `unauthorized`. `last_used_at` is
written at most once per minute per token; tokens are never logged.

Response envelope: success → the resource JSON directly (no wrapper). Errors →
`api.ErrorBody` `{"error": {"code": "not_found", "message": "…"}}` with proper status.
Lists → `api.List[T]` `{"items": [...], "total": n}` (`items` is `[]`, never `null`).
Every body/response type below lives in `internal/shared/api` and is mirrored 1:1 in
`web/src/lib/api/types.ts`. Timeseries query params: `from`/`to` RFC 3339 (default: last 6 h),
`step` a Go duration ≥ `1m` (default chosen by the server, ≤ ~500 points).

| Route | Body → Response (`api.*`) |
|---|---|
| `GET /api/v1/overview` | `Overview` — nodes by status, total qps, cache hit ratio, blocked last 24 h, current build, active offenders |
| `GET /api/v1/overview/metrics?from&to&step` | `MetricSeries` — fleet timeseries: every `metrics_minutely` column summed over all nodes per step (`latency_avg_ms` = query-weighted mean) plus derived `qps` and `cache_hit_ratio` per point; empty buckets present with zeros |
| `GET /api/v1/nodes` · `GET /nodes/{id}` · `PATCH /nodes/{id}` · `DELETE /nodes/{id}` | `List[Node]` (incl. §18 inventory fields and `agent_outdated`) · `Node` · `NodePatch{name,labels,profile_id,overrides}` → `Node` · 204. `profile_id: ""` = follow `default`; `overrides: null` or `{}` clears them; other overrides are merged over the profile and validated → 422 `invalid_config` with the validation message |
| `GET /api/v1/nodes/{id}/live` | `NodeLive` — latest heartbeat (in-memory) |
| `GET /api/v1/nodes/{id}/metrics?from&to&step` | `MetricSeries` for one node (404 for an unknown node) |
| `POST /api/v1/nodes/{id}/commands` | admin: `CommandRequest{type,version,series}` → 202 `Command`; type ∈ `api.CommandTypes`; params validated by `CommandRequest.Validate(node.dnsdist_available, dnsconf.SupportedSeries)`: `version` required for (and only for) `upgrade_dnsdist` and must be one of the node's `dnsdist_available`, `series` required for (and only for) `set_dnsdist_series` and must be in `dnsconf.SupportedSeries` → 422 `invalid_command`; `upgrade_agent` → 422 unless the node's agent is outdated (or `?force=true`) and an agent is embedded; 409 `upgrade_running` for `upgrade_*`/`set_dnsdist_series` while an upgrade run is active or the node reports `upgrade_in_progress` |
| `GET /api/v1/nodes/{id}/versions` | `NodeVersions{installed,candidate,available,series,inventory_at,last_upgrade,upgrade_in_progress,agent_version,panel_agent_version,agent_outdated}` (404 unknown node) |
| `GET /api/v1/upgrades` · `GET /upgrades/{id}` | `List[UpgradeRun]` (newest first, each with ordered `steps`) · `UpgradeRun` (404) |
| `POST /api/v1/upgrades` | admin: `UpgradeRunCreate{kind,target_version,node_ids}` → 201 `UpgradeRun`; 422 `invalid_upgrade` (`UpgradeRunCreate.Validate`, unknown node, dnsdist `target_version` not in a node's `dnsdist_available`, agent `target_version` ≠ embedded agent version); 409 `upgrade_running` (a run is `running`/`paused`); 409 `nodes_not_ready` (any live node `offline`/`degraded`/`pending`, message lists them) |
| `POST /api/v1/upgrades/{id}/pause` · `/resume` · `/abort` | admin: → `UpgradeRun`; 409 `invalid_state` unless running→paused, paused→running (resume re-checks node health → 409 `nodes_not_ready`), running/paused→aborted |
| `GET /api/v1/meta` | `Meta{panel_version, agent_version, supported_series}` — `agent_version` = embedded agent binaries |
| `GET /api/v1/nodes/{id}/cgk` | `CGKReport` from the node's latest `POST /agent/v1/cgk`, or `null` |
| `GET /api/v1/nodes/{id}/config/rendered` | `RenderedConfig` — effective spec + rendered files (secrets masked) |
| `GET /api/v1/enrollment-tokens` · `POST` · `DELETE /{id}` | `List[EnrollmentToken]` · `EnrollmentTokenCreate{node_name,labels,profile_id,ttl_hours}` → 201 `EnrollmentTokenCreated{id,token,install_command,expires_at}` · 204 |
| `GET/POST /api/v1/profiles` · `GET/PATCH/DELETE /profiles/{id}` | `List[Profile]` · `ProfileRequest{name,description,copy_from}` → 201 `Profile` · `Profile` · 204 (409 while nodes use it; nodes without a profile count as users of `default`). Create also publishes version 1: `DefaultConfigSpec()`, or the newest published spec of profile `copy_from` (400 when it has none) |
| `GET /api/v1/profiles/{id}/versions` · `GET .../versions/{v}` | `List[ConfigVersion]` (newest first) · `ConfigVersion` |
| `POST /api/v1/profiles/{id}/versions` | `VersionCreate{spec,comment}` (validated, draft) → 201 `ConfigVersion` |
| `POST /api/v1/profiles/{id}/versions/{v}/publish` | → `ConfigVersion` |
| `GET /api/v1/profiles/{id}/versions/{a}/diff/{b}` | `ConfigVersionDiff{a,b,changes}` — both versions plus `SpecChange{path,op,old,new}` entries turning a into b |
| `POST /api/v1/profiles/{id}/preview` | `PreviewRequest{spec}` (validated, not saved) → `RenderedConfig` |
| `GET/POST /api/v1/blocklist/sources` · `PATCH/DELETE /blocklist/sources/{id}` | `List[BlocklistSource]` · `BlocklistSourceCreate` → 201 `BlocklistSource` · `BlocklistSourcePatch` → `BlocklistSource` · 204 |
| `GET /api/v1/blocklist/builds` · `POST /blocklist/builds` · `GET /blocklist/current` | `List[BlocklistBuild]` (newest first) · build now → 202 `BlocklistBuild` · current `BlocklistBuild` or `null` |
| `GET /api/v1/blocklist/lookup?name=` | `BlocklistLookup{name,blocked,match,allowed,allow_entry}` (checks current CDB incl. suffix walk; `allowed`/`allow_entry` = the most specific active allowlist entry covering the name or IP, else `false`/`null`) |
| `GET /api/v1/allowlist` · `POST` · `DELETE /allowlist/{id}` | `List[AllowEntry{id,kind,value,reason,created_by_email,created_at,expires_at}]` (active entries, newest first) · admin: `AllowEntryCreate{kind,value,reason,expires_at?}` → 201 `AllowEntry` (value normalized; 422 `invalid_entry` for a bad kind/value, a TLD, a too-broad prefix, reason > 1000 bytes or an expiry not in the future; 409 `conflict` when the entry is already active — an expired row is replaced) · admin: 204 (404 unknown). Audited as `allowlist.create` / `allowlist.delete` (§7.5) |
| `GET /api/v1/reports/blocked?from&to&node_id&limit` | `BlockedReport{total,by_node,by_month,top_domains}` (`from`/`to` are dates `YYYY-MM-DD`) |
| `GET /api/v1/reports/blocked.csv?...&kind=` | `text/csv` attachment; kind ∈ `api.CSVKinds` (summary / monthly / top) |
| `GET /api/v1/analytics?from&to&node_id&kind&limit` | `AnalyticsReport{from,to,total,by_qtype,by_rcode,by_day,top}` (§19). `from`/`to` dates `YYYY-MM-DD` (default: last 7 days), `kind` ∈ `api.AnalyticsKinds` (default `queried`), `limit` 1..1000 (default 100); 400 `bad_request` otherwise |
| `GET /api/v1/analytics.csv?...` | `text/csv` attachment `analytics-<kind>-<from>_<to>.csv`, columns `rank,name,count,share,approximate` |
| `GET /api/v1/offenders?active=true&node_id` | `List[Offender]` — abusive clients (open + history) |
| `GET /api/v1/users` · `POST` · `PATCH /users/{id}` · `DELETE /users/{id}` | admin only: `List[User]` · `UserCreate` → 201 `User` · `UserPatch` → `User` · 204 |
| `GET /api/v1/audit?limit&before` | admin only: `List[AuditEntry]`, newest first, `before` = audit id cursor |
| `GET /api/v1/api-tokens` · `POST` · `DELETE /api-tokens/{id}` | admin only: `List[APIToken{id,name,prefix,created_by_email,created_at,last_used_at,expires_at,revoked}]` (newest first, incl. revoked; never the secret) · `APITokenCreate{name,expires_in_days?}` (name 1..100 bytes, days 0..3650, 0/omitted = never; 400 otherwise) → 201 `APITokenCreated` (the entry plus `token`, returned only here) · revoke → 204 (404 unknown or already revoked). Audited as `api_token.create` / `api_token.revoke` |
| `GET/PUT /api/v1/settings` | `Settings` · PUT decodes over current values (partial body ok) → `Settings`; `blocklist_download_segments` 1..16 (§7.1), other ranges as in the UI; 400 otherwise |
| `GET /healthz` · `GET /readyz` (DB ping) | health |
| `GET /api/v1/branding` | public: `Branding{name, tagline, assets}` — `assets` has every `api.BrandingAssets` key (`login_logo`, `navbar_light`, `navbar_dark`, `login_bg`, `login_bg_mobile`, `cloud`, `favicon_ico`, `icon_192`, `icon_512`, `apple_touch`), each `/branding/<file>?v=<mtime>` or `null` when the file is absent (§15) |
| `GET /branding/{file}` | public: a file from `DNSJOS_BRAND_DIR`, only the names in `api.BrandingFiles` (correct `Content-Type`, `Cache-Control: public, max-age=86400`); anything else 404 |
| `GET /favicon.ico` · `GET /manifest.webmanifest` | public: the brand `favicon.ico`, else a neutral built-in icon · web manifest with the brand name and `icon-192/512.png` (else `/favicon.ico`) |

Every mutating admin action writes `audit_log`.

---

## 11. Frontend (web/)

Pages (sidebar layout, dark/light, responsive):

1. **Login**.
2. **Overview**: KPI cards (nodes online/total, fleet qps, cache hit, blocked 24 h,
   offenders now, blocklist build age), qps chart (all nodes stacked, 6 h), node table.
3. **Nodes** list: status badge, qps, cache hit, p50 latency, versions, config/blocklist
   in-sync badges, last seen. **Add node** dialog → creates enrollment token, shows the
   one-line install command with copy button.
4. **Node detail** tabs: *Overview* (charts: qps, cache hit, blocked, latency; backends
   table with state/weight/qps/latency), *Abuse* (current dynblocks + history),
   *CGK* (aliases, rewrite ranges, last refresh, "Refresh now"), *Config* (profile
   select, overrides JSON editor, rendered preview), *Actions* (restart dnsdist, reapply).
5. **Profiles**: list; profile editor = structured form per section (Listeners, ACL,
   Upstreams with weight sliders + share %, Cache, Blocking, Abuse, CGK, Tuning) +
   "Preview Lua" + version history with diff + Publish.
6. **Blocklist**: current build card (size, entries, sha, age), build history, sources
   CRUD, "Build now", domain lookup box.
7. **Reports**: date range + node filter; totals, per-node, monthly chart, top domains
   table; CSV export buttons (for the yearly Ministry report).
8. **Offenders**: active + recent, filter by node.
9. **Users**, **Audit log**, **Settings**.

UX rules: TanStack Query with 10 s refetch on live views; optimistic toasts (sonner);
skeleton loaders; all tables sortable; react-icons (Lucide set `react-icons/lu`).
The built SPA is embedded in the panel binary (`web/dist` via `//go:embed`).
Dev: Vite proxy `/api`, `/agent`, `/install.sh` → `http://127.0.0.1:8080`.

---

## 12. Built-in defaults (seed profile "default")

The repository never contains deployment data (real client prefixes, node or blockpage
addresses, hostnames). `api.DefaultConfigSpec()` is a safe generic starting point; each
deployment imports its own profile (client ACL, upstreams, blockpage) through the panel
from a file kept outside git.

* ACL: private, CGNAT, loopback, link-local and ULA space only
  (`10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
  192.168.0.0/16, ::1/128, fc00::/7, fe80::/10`).
* Upstreams (policy whashed): 1.1.1.1:53 w30, 1.0.0.1:53 w30, 8.8.8.8:53 w20,
  8.8.4.4:53 w20; sockets 4 each.
* Blockpage: documentation addresses 192.0.2.10 / 2001:db8::10 (RFC 5737 / RFC 3849) —
  every deployment must set its own.
* Abuse: 50 qps/250 burst cap; dyn 40 qps, 15 NXDOMAIN/s, 15 SERVFAIL/s over 10 s → truncate 300 s.
* CGK rewrite pools: 104.20.0.0/16, 104.21.0.0/16, 104.24.0.0/16, 104.25.0.0/16,
  104.26.0.0/16, 104.27.0.0/16, 172.66.0.0/16, 172.67.0.0/16, 188.114.96.0/20.
  Alias pools: 104.16.0.0/16, 104.17.0.0/16, 104.18.0.0/16, 104.19.0.0/16, 172.64.0.0/16.
  Exclude: argotunnel.com, cftunnel.com, api.cloudflare.com, cloudflareaccess.com,
  cloudflareresearch.com, acme-v02.api.letsencrypt.org, engage.cloudflareclient.com,
  time.cloudflare.com, imap.hostinger.com, smtp.hostinger.com, help.stockbit.com,
  chat.riotgames.com, gitlab.com.
* Blocking: `block_response_ips` off (opt-in, see §6.4).
* Tuning: UDP buffers 16 MB.

---

## 13. Installer (`GET /install.sh`)

POSIX sh, idempotent, Debian 12/13 and Ubuntu 22.04/24.04, amd64/arm64:
1. require root; detect OS/arch; `--token` required, `--panel` defaults to the URL it was
   served from (templated in).
2. add PowerDNS repo (`repo.powerdns.com`, dnsdist 2.0 series, pinned priority 600),
   install `dnsdist`; disable systemd-resolved stub listener if it holds :53.
3. download `/dl/agent/linux/<arch>` → `/usr/local/bin/dnsjos-agent` (verify sha256 from
   `/dl/agent/linux/<arch>.sha256`).
4. `dnsjos-agent enroll --panel P --token T`, install `dnsjos-agent.service`, enable+start.
5. print node name and panel URL.
Never touches an existing `/etc/dnsdist` without backing it up first.

---

## 14. Security

* Node tokens and session tokens stored as sha256; enrollment tokens single-use, TTL.
* Agent endpoints only accept bearer auth (node token); UI endpoints only session auth,
  except that GET-only viewer routes also accept a read-only API token (`djt_…`, §10).
  API tokens are stored as sha256 and looked up by that hash (no secret comparison),
  shown once at creation, never logged and never accepted on admin, session-mutating or
  agent routes. A leaked token exposes everything a viewer can read — give it an expiry
  and revoke it when unused.
* All SQL parameterized. JSON bodies limited to 1 MiB (heartbeat) / 10 MiB (blocked).
* Rendered config never contains panel secrets; node secrets stay on the node.
* The UI masks `web_password`, `web_api_key`, `console_key` in previews.
* First admin: `dnsjos admin create --email E --password P` (CLI subcommand), or
  env `DNSJOS_BOOTSTRAP_ADMIN_EMAIL`/`_PASSWORD` used only when `users` is empty.

---

## 15. Configuration (panel env)

| Var | Default |
|---|---|
| `DNSJOS_LISTEN` | `127.0.0.1:8080` |
| `DNSJOS_DATABASE_URL` | `postgres://dnsjos@127.0.0.1:5432/dnsjos?sslmode=disable` |
| `DNSJOS_DATA_DIR` | `/var/lib/dnsjos` |
| `DNSJOS_PUBLIC_URL` | `http://127.0.0.1:8080` (used in install commands) |
| `DNSJOS_SECURE_COOKIES` | `auto` (true when PUBLIC_URL is https) |
| `DNSJOS_LOG_LEVEL` | `info` |
| `DNSJOS_BRAND_NAME` | `DnsJos` (UI name; also the SPA `<title>`, set server-side) |
| `DNSJOS_BRAND_TAGLINE` | empty |
| `DNSJOS_BRAND_DIR` | `$DNSJOS_DATA_DIR/branding` — operator-provided images (§10 `/branding/{file}`); the repository ships none |

---

## 16. Build, run, test

* `make web` → `pnpm -C web install && pnpm -C web build` (outputs `web/dist`).
* `make agent` → `GOOS=linux GOARCH={amd64,arm64} CGO_ENABLED=0 go build -trimpath
  -ldflags "-s -w -X …version=…" -o internal/panel/install/bin/dnsjos-agent-linux-<arch>` (+ .sha256),
  and writes the same version to `internal/panel/install/bin/dnsjos-agent.version`; the panel
  reads it (`install.AgentVersion()`) as the embedded agent version for `agent_outdated`,
  agent upgrades and `GET /meta` (empty = no agent embedded).
* `make panel` → builds `bin/dnsjos` (embeds web/dist and agent binaries). A build without
  the embedded assets must still compile (placeholder files are committed).
* `make release` = `make web agent panel` (a panel binary with the SPA and both agents embedded).
* `make smoke` → `test/smoke/smoke.sh`: runs the real panel against a fresh local Postgres
  database and hits every §8/§10 route with valid and invalid input (any 5xx fails).
  `PANEL_BIN=bin/dnsjos EXPECT_AGENT=1` also checks the embedded agent downloads.
* `make test` → `go test ./...` (needs `DNSJOS_TEST_DATABASE_URL` for DB tests; they skip
  when unset) + `pnpm -C web typecheck && pnpm -C web lint`.
* `make dev` → run panel against local Postgres + `pnpm -C web dev`.
* Conventional Commits.

---

## 17. Adopting an existing dnsdist server (rolling, zero customer downtime)

Live servers already run dnsdist (dnsdist_ootb YAML wrapper + hand-made Lua). Adoption
must not change behaviour or break integrations, and must be done one node at a time.

* `dnsjos-agent enroll --adopt …` imports the existing secrets into
  `/var/lib/dnsjos/secrets.json` instead of generating new ones, so Prometheus/Grafana
  scrapes and `dnsdist-offenders` keep working: web password + API key from
  `admin.web.password/apikey` and console key from `admin.console.key` in
  `/etc/dnsdist/dnsdist.yml` (dnsdist_ootb format), falling back to generating new ones
  only when absent. It also keeps the existing webserver listen address/port
  (`admin.web.ip4:port`, e.g. `0.0.0.0:8083`) and web ACL by emitting them as node
  overrides in the enroll request (`EnrollRequest.adopt_overrides`, a JSON merge patch
  the panel stores in `nodes.overrides`).
* `dnsjos-agent plan` (works before and after enrollment): fetch/compute the effective
  config, render into `/etc/dnsdist/.dnsjos-staging/`, run `dnsdist --check-config`,
  print a summary (listeners, ACL size, upstreams+weights, blocking, abuse, cgk) and a
  unified diff against the files currently in `/etc/dnsdist/`. Never swaps, never restarts.
* First apply after adoption: back up the whole `/etc/dnsdist` (incl. dnsdist_ootb and
  the old CDB) to `/var/lib/dnsjos/pre-adopt-<ts>.tar.gz`, then the normal apply flow
  (check → swap → restart → verify → rollback on failure). Rollback restores the
  pre-adopt tree exactly.
* The agent must seed the local CDB before the first apply: download the panel's
  current blocklist first; if the panel has no build yet, copy the existing
  `/etc/dnsdist/db/blacklist.db` to the agent CDB path so blocking never lapses.
* The panel refuses to hand out a config to an adopted node until at least one
  `ok` blocklist build exists OR the agent reports a seeded local CDB: `GET /agent/v1/config`
  answers 409 `{"error":{"code":"no_blocklist"}}`. Enrolling with `adopt: true` sets
  `nodes.adopted` and stores `adopt_overrides` (validated like `PATCH /nodes/{id}`) as the node
  overrides; any heartbeat with a non-empty `blocklist_sha256` records
  `nodes.seeded_blocklist_sha256`, which counts as seeded. Re-enrolling clears the seed.
* Operator runbook (docs/OPERATIONS.md): order least-busy node first; before each node
  confirm the other nodes are `online`; after each node verify resolution, blockpage,
  HTTPS-type NODATA, DoH/DoT, dnstap → blocked report, Grafana scrape; only then continue.

---

## 18. dnsdist (and agent) upgrades from the panel

Goal: upgrade dnsdist on a node, or across the fleet, from the UI without customer
impact. Nodes are upgraded **one at a time**; the next node starts only after the previous
one is healthy again.

* **Inventory**: the agent reports in every heartbeat `dnsdist_version` (installed,
  `dpkg-query -W dnsdist`), and every 6 h (and on the `check_updates` command) the result
  of refreshing ONLY the PowerDNS list (`apt-get update -o
  Dir::Etc::sourcelist=sources.list.d/<dnsdist list> -o Dir::Etc::sourceparts=- -o
  APT::Get::List-Cleanup=0`) + `apt-cache policy dnsdist`: `dnsdist_candidate`,
  `dnsdist_available[]` (versions in the configured series), `dnsdist_repo_series`
  (e.g. `20` for `…-dnsdist-20`). The panel stores these on the node and shows
  "update available".
* **Upgrade command** `{"type": "upgrade_dnsdist", "version": "<exact version>"}`:
  agent runs `DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade
  -o Dpkg::Options::=--force-confold dnsdist=<version>` (never touches other packages,
  keeps the DnsJos-rendered config), then verifies: dnsdist active, console answers,
  `dnsdist --check-config` passes with the current rendered config, a local test query
  resolves, and a blocklisted name returns the blockpage. On any failure it downgrades to
  the previous version (`--allow-downgrades dnsdist=<previous>`, .deb kept in the apt
  cache). The result is reported in the next heartbeat
  (`last_upgrade: {kind, from, to, ok, error, at}`; `upgrade_in_progress` while running).
* **Series switch** (e.g. 2.0 → 2.1) is a separate, explicit admin action
  `{"type": "set_dnsdist_series", "series": "21"}` that rewrites the PowerDNS apt source
  + pin, followed by a normal upgrade. The renderer only supports series listed in
  `dnsconf.SupportedSeries` (initially `20`, `21`); the panel refuses others.
* **Fleet rolling upgrade** (panel orchestrator, `upgrade_runs` + `upgrade_run_steps`
  tables): admin picks target version + node order (default: least busy first), panel
  sends the command to node 1, waits until it reports the target version, dnsdist running,
  no apply/upgrade error, all backends up, and its qps recovers (health gate, timeout
  10 min) — then node 2, … Any failure pauses the run (admin can resume/abort). Never more
  than one node upgrading at a time; refuse to start when any node is offline/degraded.
* **Agent self-upgrade** `{"type": "upgrade_agent"}`: download `/dl/agent/linux/<arch>`,
  verify sha256, atomically replace `/usr/local/bin/dnsjos-agent`, exit so systemd restarts
  it; the panel shows agent version vs the panel's embedded agent version and offers a
  rolling agent upgrade the same way (agent restarts do not touch dnsdist).
* **Contract** (`internal/shared/api/upgrades.go`, migration `0003_upgrades`):
  `node_commands.params jsonb` carries `version`/`series`; `nodes` gains
  `dnsdist_candidate`, `dnsdist_available jsonb ('[]')`, `dnsdist_repo_series`,
  `inventory_at`, `last_upgrade jsonb` (`api.UpgradeResult`). `upgrade_runs(id, kind
  'dnsdist'|'agent', target_version, status 'running'|'paused'|'done'|'failed'|'aborted',
  created_by, created_at, finished_at, message)` with a unique partial index allowing at
  most one `running`/`paused` run; `upgrade_run_steps(run_id, position, node_id, status
  'pending'|'running'|'ok'|'failed'|'skipped', started_at, finished_at, message,
  from_version, to_version, pk(run_id, position))`. A failed step pauses the run (run
  `paused`, step `failed`); resume retries that step; abort marks remaining steps
  `skipped`; the run is `done` when every step is `ok`; `failed` is reserved for
  orchestrator errors that cannot be resumed. Agent runs target the panel's
  embedded agent version; their health gate is: reports that version and is `online`.
  Orchestrator (`internal/panel/upgrades`, job every 5 s): steps run in position order
  (default: least queries in the last hour first; `node_ids` order when given); a pending
  step whose node already runs the target (or was deleted) is `skipped`; before sending
  the command every live node must be `online`, else the run pauses. dnsdist health gate:
  reports the target version, `online` (dnsdist running, no apply/blocklist error, all
  backends up), heartbeat within 3 × interval, `last_upgrade` of this attempt (`at` ≥ step
  start) with `ok`, and — when the 5 minutes before the step averaged > 1 qps — qps over
  the whole minutes since the step started (≤ 2 min window, ≥ 30 s) back to ≥ 50 % of that
  average. A `last_upgrade` of this attempt with `ok: false` fails the step at once;
  otherwise the gate times out after 10 min.
  Routes: §10 (`/nodes/{id}/versions`, `/upgrades…`, `/meta`).
* Every upgrade action is audited; UI: node detail "Versions" card (installed, candidate,
  available list, Upgrade button, last result) and a Fleet → Upgrades page (start rolling
  run, live progress per node, pause/resume/abort, history).

---

## 19. Traffic analytics — top queried domains

Complements §7/§9 (which only see *blocked* queries) with fleet-wide query analytics.
No client addresses are collected or stored (top clients is a possible later option).
Types live in `internal/shared/api/analytics.go`.

* **Config** (`ConfigSpec.analytics`, `api.Analytics`): `enabled` (default true),
  `sample_rate` (default 1, 1..1000), `top_k` (default 5000, 100..50000), `stream_addr`
  (default `127.0.0.1:6001`). See §6 for defaults of older stored specs.
* **Stream**: when `analytics.enabled`, the renderer adds a second dnstap logger to
  `stream_addr` (separate from the blocked stream on :6000) with `DnstapLogResponseAction`
  on every response AND `addCacheHitResponseAction` (cache hits count too), guarded by
  `ProbaRule(1 / sample_rate)` when `sample_rate > 1` (default 1 = every query).
  Counts are multiplied back by `sample_rate` in the agent.
* **Agent aggregation** (bounded memory): per local day, Space-Saving top-K sketches
  (K = `top_k`) for the kinds (`api.AnalyticsKinds`):
  `queried` (raw qname), `queried_grouped` (registered domain via
  golang.org/x/net/publicsuffix EffectiveTLDPlusOne; names without one keep the raw name),
  `nxdomain` (raw qname of NXDOMAIN answers), `servfail` (raw qname of SERVFAIL answers);
  plus exact counters by qtype (`"A"`, `"AAAA"`, …, `TYPEn` when unknown) and rcode
  (`"NOERROR"`, `"NXDOMAIN"`, `"SERVFAIL"`, …), and total responses. Every 60 s the agent
  POSTs a batch to `POST /agent/v1/analytics` (with an Idempotency-Key, §8); unsent batches
  spool to disk like §9.4:
  ```jsonc
  {"day": "2026-01-02", "total": 0, "sample_rate": 1,
   "by_qtype": {"A": 0}, "by_rcode": {"NOERROR": 0},
   "epoch": "3f9c…", "tops_mode": "cumulative",
   "tops": {"queried": [{"name": "example.com", "count": 0, "error": 0}]},  // error = Space-Saving over-estimate bound
   "evicted": {"queried": ["gone.example"]}}
  ```
  Names are lower-case without the trailing dot. `total`, `by_qtype` and `by_rcode` are
  always deltas since the previous batch. **Tops protocol v2** (`tops_mode`):
  * `"delta"` (or absent, legacy agents): the window's own sketch; items are added.
  * `"cumulative"`: the agent keeps ONE sketch per day across flushes; `epoch` (required,
    ≤ 64 bytes) is random per sketch lifetime (new on agent start and day rollover). Each
    item carries the name's **cumulative** count/error within the epoch; only items whose
    (count, error) changed since last sent are sent, plus `evicted[kind]` = names sent
    earlier in this epoch that have since left the sketch. `evicted` is rejected in delta mode.
* **Panel storage** (`migrations/0004_analytics`, `0005`): `analytics_daily_totals(day, node_id,
* **Panel storage** (`migrations/0004_analytics`): `analytics_daily_totals(day, node_id,
  total, by_qtype jsonb, by_rcode jsonb, sampled, pk(day,node_id))` (upsert-add; jsonb maps
  summed per key; `sampled` ORed from `sample_rate > 1`) and `analytics_top_daily(day,
  node_id, kind, name, count, error, epoch, base, base_error, pk(day,node_id,kind,name))`,
  index `(day, kind, count desc)`. A name's value is `base + count` (error
  `base_error + error`) — reports, trim and CSV all use it. Delta batches add to
  count/error. Cumulative items: when the row's `epoch` differs from the batch's, fold
  (`base += count`, `base_error += error`) and take the batch epoch; then `count`/`error`
  := the item's. Evicted names: fold likewise, then `count = error = 0`; a row left with
  `base = 0` and `count = 0` is deleted. Evictions apply before the batch's items. Rows
  stay ~bounded by `top_k` per (day, node, kind, epoch). An epoch's batches must arrive in
  order (the spool replays in order); a stale batch of an older epoch arriving after a
  newer one would be folded twice. A daily job trims each (day, node, kind) to the
  node's top 1000 plus any name in the fleet's top 1000 for that (day, kind) once the
  day is over. Retention: setting `analytics_retention_days` (default
  400, in `api.Settings`).
* **API** (§10): `GET /api/v1/analytics` → `api.AnalyticsReport` — `by_day` has every day
  of the range (zeros included); `top[]` = `{rank (1-based), name, count, share,
  approximate}` summed over the selected nodes, where `share` = count / `total` for
  `queried*` and count / `by_rcode["NXDOMAIN"|"SERVFAIL"]` for `nxdomain`/`servfail`,
  and `approximate` is true when any contributing day was sampled or has `error > 0`.
  `.csv` export (kind + range in the filename). Viewer.
* **UI**: new page **Analytics** (`/analytics`, `useAnalytics`): date presets, node filter, kind tabs
  (Top domains [Raw | Grouped toggle], NXDOMAIN, SERVFAIL), top table with share bars,
  qtype/rcode breakdown charts, daily volume chart, CSV export. Node detail gets a
  compact "Top domains today" card. Counts from sampled nodes are marked approximate.
