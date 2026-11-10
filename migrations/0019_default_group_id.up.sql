-- Reconcile the blocklist "groups" schema for deployments that already carry it.
--
-- Some installs carry a blocklist_groups feature (from an earlier branch that was never
-- pushed) that adds a NOT NULL group_id to blocklist_sources and blocklist_builds with no
-- default.
-- Every INSERT that does not name a group then fails with SQLSTATE 23502, which broke the
-- scheduled blocklist build and the RPZ master create path (POST /api/v1/rpz/upstreams).
-- Pin the default group as the column default so those inserts keep working; profiles that
-- do not pick a group already resolve to it. Installs without the feature (fresh installs
-- from this tree) skip the migration entirely.

DO $$
DECLARE
    gid uuid;
    has_default boolean;
BEGIN
    IF to_regclass('public.blocklist_groups') IS NULL THEN
        RETURN; -- no groups feature in this install
    END IF;

    has_default := EXISTS (SELECT 1 FROM information_schema.columns
                           WHERE table_schema = 'public' AND table_name = 'blocklist_groups'
                             AND column_name = 'is_default');
    IF has_default THEN
        EXECUTE 'SELECT id FROM blocklist_groups WHERE is_default ORDER BY id LIMIT 1' INTO gid;
    END IF;
    IF gid IS NULL THEN
        EXECUTE 'SELECT id FROM blocklist_groups WHERE name = ''default'' ORDER BY id LIMIT 1' INTO gid;
    END IF;
    IF gid IS NULL THEN
        EXECUTE 'SELECT id FROM blocklist_groups ORDER BY id LIMIT 1' INTO gid;
    END IF;
    IF gid IS NULL THEN
        IF has_default THEN
            EXECUTE 'INSERT INTO blocklist_groups (name, is_default) VALUES (''default'', true) RETURNING id' INTO gid;
        ELSE
            EXECUTE 'INSERT INTO blocklist_groups (name) VALUES (''default'') RETURNING id' INTO gid;
        END IF;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'blocklist_sources'
                 AND column_name = 'group_id') THEN
        UPDATE blocklist_sources SET group_id = gid WHERE group_id IS NULL;
        EXECUTE format('ALTER TABLE blocklist_sources ALTER COLUMN group_id SET DEFAULT %L', gid);
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'blocklist_builds'
                 AND column_name = 'group_id') THEN
        UPDATE blocklist_builds SET group_id = gid WHERE group_id IS NULL;
        EXECUTE format('ALTER TABLE blocklist_builds ALTER COLUMN group_id SET DEFAULT %L', gid);
    END IF;
END $$;
