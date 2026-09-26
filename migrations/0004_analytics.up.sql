-- SPEC §19: traffic analytics — per-day totals and top lists per node (upsert-add from the agent).

CREATE TABLE analytics_daily_totals (
    day       date NOT NULL,
    node_id   uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    total     bigint NOT NULL DEFAULT 0,
    by_qtype  jsonb NOT NULL DEFAULT '{}'::jsonb,   -- {"A": n, …}
    by_rcode  jsonb NOT NULL DEFAULT '{}'::jsonb,   -- {"NOERROR": n, …}
    sampled   boolean NOT NULL DEFAULT false,       -- any batch of the day had sample_rate > 1
    PRIMARY KEY (day, node_id)
);

CREATE TABLE analytics_top_daily (
    day      date NOT NULL,
    node_id  uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind     text NOT NULL CHECK (kind IN ('queried', 'queried_grouped', 'nxdomain', 'servfail')),
    name     text NOT NULL,
    count    bigint NOT NULL DEFAULT 0,
    error    bigint NOT NULL DEFAULT 0,             -- summed Space-Saving over-estimate bounds
    PRIMARY KEY (day, node_id, kind, name)
);
CREATE INDEX analytics_top_daily_rank_idx ON analytics_top_daily (day, kind, count DESC);

INSERT INTO settings (key, value) VALUES ('analytics_retention_days', '400')
ON CONFLICT (key) DO NOTHING;
