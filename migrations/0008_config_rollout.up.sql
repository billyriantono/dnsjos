-- SPEC §6.5: staged profile publish — one node at a time through the upgrade orchestrator.

-- While a staged rollout has not reached a node, the node is served the newest published
-- version <= config_pin of its profile instead of the newest one. NULL = no pin.
ALTER TABLE nodes ADD COLUMN config_pin integer;

ALTER TABLE upgrade_runs
    DROP CONSTRAINT upgrade_runs_kind_check,
    ADD CONSTRAINT upgrade_runs_kind_check CHECK (kind IN ('dnsdist', 'agent', 'config')),
    ADD COLUMN profile_id uuid REFERENCES config_profiles(id) ON DELETE SET NULL;  -- kind 'config' only
