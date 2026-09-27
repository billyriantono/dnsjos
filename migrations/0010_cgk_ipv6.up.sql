-- SPEC §6.7: IPv6 half of each CGK measurement.
ALTER TABLE cgk_reports
    ADD COLUMN aliases6 jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN ipv6     text  NOT NULL DEFAULT '';  -- api.CGKIPv6*; '' = agent without IPv6 support
