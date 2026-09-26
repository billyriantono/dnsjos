-- SPEC §8/§19: idempotent agent batches and the cumulative analytics tops protocol (v2).

-- One row per committed agent batch (Idempotency-Key); pruned after 7 days.
CREATE TABLE ingested_batches (
    node_id   uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    batch_key text NOT NULL,
    at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, batch_key)
);
CREATE INDEX ingested_batches_at_idx ON ingested_batches (at);

-- tops_mode "cumulative": count/error hold the value of the current epoch, base/base_error
-- everything folded in from earlier epochs (and legacy delta rows). Reports use base + count.
ALTER TABLE analytics_top_daily
    ADD COLUMN epoch      text   NOT NULL DEFAULT '',
    ADD COLUMN base       bigint NOT NULL DEFAULT 0,
    ADD COLUMN base_error bigint NOT NULL DEFAULT 0;
