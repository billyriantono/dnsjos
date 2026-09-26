-- SPEC §7.5: emergency allowlist (names/IPs listed by mistake, e.g. shared CDN space) and
-- the parallel blocklist download setting (§7.1).

CREATE TABLE allowlist (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        text NOT NULL CHECK (kind IN ('domain', 'ip')),
    value       text NOT NULL,              -- domain: lowercase, no trailing dot; ip: address or masked CIDR
    reason      text NOT NULL DEFAULT '',
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz,                -- NULL = permanent; expired rows are ignored and purged
    UNIQUE (kind, value)
);

INSERT INTO settings (key, value) VALUES ('blocklist_download_segments', '8')
ON CONFLICT (key) DO NOTHING;
