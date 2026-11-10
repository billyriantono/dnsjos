-- SPEC §7.7: RPZ slave. The panel pulls the blocklist zone from an RPZ master over
-- AXFR/IXFR and writes the transferred domain list into a blocklist source of kind
-- 'rpz_domains'. No separate rpz-master relay host is required, and only the panel needs
-- the upstream's allow-IP/TSIG, not every node.
CREATE TABLE rpz_upstreams (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL UNIQUE,
    upstream      text NOT NULL,                    -- host:port of the RPZ master
    zone          text NOT NULL,                    -- FQDN (trailing dot added on use)
    tsig_key      text NOT NULL DEFAULT '',         -- FQDN; empty = no TSIG
    tsig_secret   text NOT NULL DEFAULT '',         -- base64; only used with tsig_key
    interval_s    integer NOT NULL DEFAULT 900 CHECK (interval_s BETWEEN 60 AND 86400),
    serial        bigint NOT NULL DEFAULT 0,
    total_domains integer NOT NULL DEFAULT 0,
    last_sync_at  timestamptz,
    last_error    text NOT NULL DEFAULT '',
    source_id     uuid NOT NULL REFERENCES blocklist_sources(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- The RPZ slave writes its transferred domains into a source of kind rpz_domains, so the
-- source kind check must allow it. Fresh installs get the kind from 0001.
ALTER TABLE blocklist_sources DROP CONSTRAINT IF EXISTS blocklist_sources_kind_check;
ALTER TABLE blocklist_sources ADD CONSTRAINT blocklist_sources_kind_check CHECK (kind IN (
    'trustpositif_domains', 'trustpositif_ips', 'url_domains', 'url_ips',
    'rpz_domains', 'manual_domains', 'manual_ips', 'whitelist'
));
