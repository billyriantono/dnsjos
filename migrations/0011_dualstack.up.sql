-- SPEC §6.8: each node's dual-stack selection (latest report per node).
ALTER TABLE nodes
    ADD COLUMN dualstack         jsonb NOT NULL DEFAULT '[]'::jsonb,  -- []api.DualStackName, listed names only
    ADD COLUMN dualstack_checked integer NOT NULL DEFAULT 0,
    ADD COLUMN dualstack_ipv6    boolean NOT NULL DEFAULT false,
    ADD COLUMN dualstack_at      timestamptz;
