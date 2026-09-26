-- SPEC §18: dnsdist/agent upgrades — command params, node inventory, rolling upgrade runs.

ALTER TABLE node_commands
    ADD COLUMN params jsonb NOT NULL DEFAULT '{}'::jsonb,   -- {"version": …} / {"series": …}
    DROP CONSTRAINT node_commands_type_check,
    ADD CONSTRAINT node_commands_type_check CHECK (type IN (
        'cgk_refresh', 'restart_dnsdist', 'reapply',
        'check_updates', 'upgrade_dnsdist', 'set_dnsdist_series', 'upgrade_agent'));

ALTER TABLE nodes
    ADD COLUMN dnsdist_candidate   text NOT NULL DEFAULT '',
    ADD COLUMN dnsdist_available   jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN dnsdist_repo_series text NOT NULL DEFAULT '',
    ADD COLUMN inventory_at        timestamptz,
    ADD COLUMN last_upgrade        jsonb;                    -- api.UpgradeResult, NULL until the first upgrade

CREATE TABLE upgrade_runs (
    id              bigserial PRIMARY KEY,
    kind            text NOT NULL CHECK (kind IN ('dnsdist', 'agent')),
    target_version  text NOT NULL DEFAULT '',
    status          text NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running', 'paused', 'done', 'failed', 'aborted')),
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    message         text NOT NULL DEFAULT ''
);
-- At most one active (running or paused) run: a paused run still owns the fleet until resumed or aborted.
CREATE UNIQUE INDEX upgrade_runs_one_active_idx ON upgrade_runs ((true)) WHERE status IN ('running', 'paused');

CREATE TABLE upgrade_run_steps (
    run_id        bigint NOT NULL REFERENCES upgrade_runs(id) ON DELETE CASCADE,
    position      integer NOT NULL,
    node_id       uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    status        text NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'running', 'ok', 'failed', 'skipped')),
    started_at    timestamptz,
    finished_at   timestamptz,
    message       text NOT NULL DEFAULT '',
    from_version  text NOT NULL DEFAULT '',
    to_version    text NOT NULL DEFAULT '',
    PRIMARY KEY (run_id, position),
    UNIQUE (run_id, node_id)
);
CREATE INDEX upgrade_run_steps_node_idx ON upgrade_run_steps(node_id);
