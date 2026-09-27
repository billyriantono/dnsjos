-- SPEC §6.6: names each node found broken through a CGK alias (latest report per node).
ALTER TABLE nodes
    ADD COLUMN cgk_learned         jsonb NOT NULL DEFAULT '[]'::jsonb,  -- []api.CGKLearned, excluded only
    ADD COLUMN cgk_learned_checked integer NOT NULL DEFAULT 0,
    ADD COLUMN cgk_learned_at      timestamptz;
