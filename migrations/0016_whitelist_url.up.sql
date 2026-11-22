-- Whitelist can now be bulk-imported from a URL (§7.1 sources). 'whitelist' stays the
-- manual paste; 'whitelist_url' is fetched on every build like the other URL sources.

ALTER TABLE blocklist_sources
    DROP CONSTRAINT blocklist_sources_kind_check;

ALTER TABLE blocklist_sources
    ADD CONSTRAINT blocklist_sources_kind_check
    CHECK (kind IN ('trustpositif_domains', 'trustpositif_ips',
                    'url_domains', 'url_ips',
                    'manual_domains', 'manual_ips',
                    'whitelist', 'whitelist_url'));
