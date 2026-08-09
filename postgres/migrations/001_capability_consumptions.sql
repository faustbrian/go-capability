CREATE TABLE capability_consumptions (
    capability_id text PRIMARY KEY,
    uses bigint NOT NULL CHECK (uses > 0),
    max_uses bigint NOT NULL CHECK (max_uses > 0 AND uses <= max_uses),
    expires_at timestamptz NOT NULL
);

CREATE INDEX capability_consumptions_expires_at_idx
    ON capability_consumptions (expires_at);
