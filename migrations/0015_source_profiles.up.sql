-- Share a blocklist source across several profiles (SPEC §7.1). A source used to carry a
-- single profile_id, so reusing one list in two profiles meant duplicating the row (and, for
-- an RPZ slave, transferring the zone twice). This join table makes the relation many-to-many:
-- a source with no row here stays global (shared by every profile), preserving the old
-- profile_id IS NULL meaning; one with rows is scoped to exactly those profiles.

CREATE TABLE blocklist_source_profiles (
    source_id  uuid NOT NULL REFERENCES blocklist_sources(id) ON DELETE CASCADE,
    profile_id uuid NOT NULL REFERENCES config_profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (source_id, profile_id)
);

CREATE INDEX blocklist_source_profiles_profile_idx ON blocklist_source_profiles (profile_id);

-- Backfill: every source that was scoped to one profile becomes a single join row. Sources
-- with profile_id IS NULL stay global and get no row.
INSERT INTO blocklist_source_profiles (source_id, profile_id)
SELECT id, profile_id FROM blocklist_sources WHERE profile_id IS NOT NULL;

-- profile_id is now derived from this table; keep the column for one release so a mixed-version
-- rollout (old binary reading the column) still scopes correctly, but stop reading it as the
-- source of truth. Drop its index: nothing queries it anymore.
DROP INDEX IF EXISTS blocklist_sources_profile_idx;
