-- SPEC §17: adopted nodes get no config until a blocklist exists (panel build or seeded local CDB).
ALTER TABLE nodes
    ADD COLUMN adopted boolean NOT NULL DEFAULT false,
    ADD COLUMN seeded_blocklist_sha256 text NOT NULL DEFAULT '';
