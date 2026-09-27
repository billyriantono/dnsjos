-- SPEC §10: read-only API tokens (Authorization: Bearer djt_…) for tools such as Grafana.
-- Only sha256(token) is stored; prefix is the first 8 characters, for display.

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL,
    token_hash   bytea UNIQUE NOT NULL,
    prefix       text NOT NULL,
    created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at   timestamptz,               -- NULL = never
    revoked_at   timestamptz
);
