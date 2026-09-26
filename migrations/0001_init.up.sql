-- DnsJos initial schema. Forward-only: never edit after it has been applied;
-- add 0002_*.up.sql instead.

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid()

-- ─── users & sessions ──────────────────────────────────────────────────────
CREATE TABLE users (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email          citext NOT NULL UNIQUE,
    name           text NOT NULL DEFAULT '',
    password_hash  text NOT NULL,
    role           text NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'viewer')),
    disabled       boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz
);

CREATE TABLE sessions (
    id_hash     bytea PRIMARY KEY,                 -- sha256(cookie token)
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    ip          text NOT NULL DEFAULT '',
    user_agent  text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

-- ─── config profiles & versions ────────────────────────────────────────────
CREATE TABLE config_profiles (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,
    description  text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE config_versions (
    id          bigserial PRIMARY KEY,
    profile_id  uuid NOT NULL REFERENCES config_profiles(id) ON DELETE CASCADE,
    version     integer NOT NULL,
    spec        jsonb NOT NULL,                     -- api.ConfigSpec
    comment     text NOT NULL DEFAULT '',
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    published   boolean NOT NULL DEFAULT false,
    published_at timestamptz,
    UNIQUE (profile_id, version)
);
CREATE INDEX config_versions_published_idx ON config_versions(profile_id, version DESC) WHERE published;

-- ─── nodes ─────────────────────────────────────────────────────────────────
CREATE TABLE nodes (
    id                        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                      text NOT NULL,
    hostname                  text NOT NULL DEFAULT '',
    public_ip                 text NOT NULL DEFAULT '',
    labels                    jsonb NOT NULL DEFAULT '{}'::jsonb,
    status                    text NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending', 'online', 'degraded', 'offline')),
    token_hash                bytea UNIQUE,         -- sha256(node token)
    profile_id                uuid REFERENCES config_profiles(id) ON DELETE SET NULL,
    overrides                 jsonb NOT NULL DEFAULT '{}'::jsonb,   -- RFC 7396 merge patch
    enrolled_at               timestamptz,
    last_seen_at              timestamptz,
    agent_version             text NOT NULL DEFAULT '',
    dnsdist_version           text NOT NULL DEFAULT '',
    os                        text NOT NULL DEFAULT '',
    arch                      text NOT NULL DEFAULT '',
    applied_config_version    integer,
    applied_blocklist_sha256  text NOT NULL DEFAULT '',
    last_error                text NOT NULL DEFAULT '',
    last_heartbeat            jsonb,                -- latest api.Heartbeat (for restarts of the panel)
    created_at                timestamptz NOT NULL DEFAULT now(),
    deleted_at                timestamptz
);
CREATE UNIQUE INDEX nodes_name_live_idx ON nodes(name) WHERE deleted_at IS NULL;

CREATE TABLE enrollment_tokens (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash    bytea NOT NULL UNIQUE,            -- sha256(token)
    node_name     text NOT NULL,
    labels        jsonb NOT NULL DEFAULT '{}'::jsonb,
    profile_id    uuid REFERENCES config_profiles(id) ON DELETE SET NULL,
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    used_by_node  uuid REFERENCES nodes(id) ON DELETE SET NULL
);

-- Commands queued from the UI, delivered once in a heartbeat ack.
CREATE TABLE node_commands (
    id            bigserial PRIMARY KEY,
    node_id       uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    type          text NOT NULL CHECK (type IN ('cgk_refresh', 'restart_dnsdist', 'reapply')),
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    delivered_at  timestamptz,
    acked_at      timestamptz
);
CREATE INDEX node_commands_pending_idx ON node_commands(node_id) WHERE acked_at IS NULL;

-- ─── blocklist ─────────────────────────────────────────────────────────────
CREATE TABLE blocklist_sources (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL,
    kind           text NOT NULL CHECK (kind IN ('trustpositif_domains', 'trustpositif_ips',
                                                  'url_domains', 'url_ips',
                                                  'manual_domains', 'manual_ips', 'whitelist')),
    url            text NOT NULL DEFAULT '',
    content        text NOT NULL DEFAULT '',        -- manual lists / whitelist
    enabled        boolean NOT NULL DEFAULT true,
    etag           text NOT NULL DEFAULT '',
    last_modified  text NOT NULL DEFAULT '',
    last_fetch_at  timestamptz,
    last_status    text NOT NULL DEFAULT '',
    entries        integer NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE blocklist_builds (
    id           bigserial PRIMARY KEY,
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    status       text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'ok', 'failed', 'skipped')),
    trigger      text NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual')),
    domains      integer NOT NULL DEFAULT 0,
    ips          integer NOT NULL DEFAULT 0,
    whitelisted  integer NOT NULL DEFAULT 0,
    skipped      integer NOT NULL DEFAULT 0,        -- invalid / oversize entries
    size_bytes   bigint NOT NULL DEFAULT 0,
    sha256       text NOT NULL DEFAULT '',
    error        text NOT NULL DEFAULT ''
);
CREATE INDEX blocklist_builds_ok_idx ON blocklist_builds(finished_at DESC) WHERE status = 'ok';

-- ─── monitoring & reporting ────────────────────────────────────────────────
CREATE TABLE metrics_minutely (
    node_id         uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    ts              timestamptz NOT NULL,           -- truncated to the minute
    queries         bigint NOT NULL DEFAULT 0,
    responses       bigint NOT NULL DEFAULT 0,
    cache_hits      bigint NOT NULL DEFAULT 0,
    cache_misses    bigint NOT NULL DEFAULT 0,
    blocked         bigint NOT NULL DEFAULT 0,
    dyn_blocked     bigint NOT NULL DEFAULT 0,
    rule_drops      bigint NOT NULL DEFAULT 0,
    servfail        bigint NOT NULL DEFAULT 0,
    nxdomain        bigint NOT NULL DEFAULT 0,
    noerror         bigint NOT NULL DEFAULT 0,
    cgk_rewrites    bigint NOT NULL DEFAULT 0,
    latency_sum_ms  double precision NOT NULL DEFAULT 0,   -- avg = latency_sum_ms / samples
    samples         integer NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, ts)
);
CREATE INDEX metrics_minutely_ts_idx ON metrics_minutely(ts);

CREATE TABLE backend_status (
    node_id     uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    address     text NOT NULL,
    name        text NOT NULL DEFAULT '',
    pool        text NOT NULL DEFAULT '',
    state       text NOT NULL DEFAULT '',
    weight      integer NOT NULL DEFAULT 1,
    "order"     integer NOT NULL DEFAULT 1,
    qps         double precision NOT NULL DEFAULT 0,
    latency_ms  double precision NOT NULL DEFAULT 0,
    queries     bigint NOT NULL DEFAULT 0,
    drops       bigint NOT NULL DEFAULT 0,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, address)
);

CREATE TABLE blocked_daily (
    day      date NOT NULL,
    node_id  uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    qname    text NOT NULL,
    qtype    text NOT NULL,
    count    bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (day, node_id, qname, qtype)
);
CREATE INDEX blocked_daily_qname_idx ON blocked_daily(qname);

CREATE TABLE offender_events (
    id          bigserial PRIMARY KEY,
    node_id     uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    client      text NOT NULL,
    stage       text NOT NULL CHECK (stage IN ('warning', 'blocked')),
    reason      text NOT NULL DEFAULT '',
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    blocks      bigint NOT NULL DEFAULT 0,
    closed      boolean NOT NULL DEFAULT false
);
CREATE INDEX offender_events_open_idx ON offender_events(node_id, client, reason) WHERE NOT closed;
CREATE INDEX offender_events_seen_idx ON offender_events(last_seen DESC);

CREATE TABLE cgk_reports (
    id              bigserial PRIMARY KEY,
    node_id         uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    measured_at     timestamptz NOT NULL,
    ok              boolean NOT NULL,
    message         text NOT NULL DEFAULT '',
    aliases         jsonb NOT NULL DEFAULT '[]'::jsonb,
    rewrite_ranges  jsonb NOT NULL DEFAULT '[]'::jsonb,
    pools           jsonb NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX cgk_reports_node_idx ON cgk_reports(node_id, measured_at DESC);

-- ─── audit & settings ──────────────────────────────────────────────────────
CREATE TABLE audit_log (
    id           bigserial PRIMARY KEY,
    at           timestamptz NOT NULL DEFAULT now(),
    user_id      uuid REFERENCES users(id) ON DELETE SET NULL,
    action       text NOT NULL,
    target_type  text NOT NULL DEFAULT '',
    target_id    text NOT NULL DEFAULT '',
    details      jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip           text NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_at_idx ON audit_log(at DESC);

CREATE TABLE settings (
    key    text PRIMARY KEY,
    value  jsonb NOT NULL
);

-- ─── seed data ─────────────────────────────────────────────────────────────
INSERT INTO blocklist_sources (name, kind, url) VALUES
    ('TrustPositif domains', 'trustpositif_domains', 'https://trustpositif.komdigi.go.id/assets/db/domains_isp'),
    ('TrustPositif IPs',     'trustpositif_ips',     'https://trustpositif.komdigi.go.id/assets/db/ipaddress_isp');

INSERT INTO settings (key, value) VALUES
    ('blocklist_build_interval_minutes', '180'),
    ('metrics_retention_days', '35'),
    ('blocked_retention_days', '800'),
    ('agent_poll_interval_s', '15'),
    ('agent_heartbeat_interval_s', '10');

-- The "default" profile row; its version 1 (api.DefaultConfigSpec) is inserted by the
-- panel at startup when the profile has no versions (the spec lives in Go, §6.1).
INSERT INTO config_profiles (name, description)
VALUES ('default', 'Default resolver profile');
