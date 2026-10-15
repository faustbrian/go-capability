-- +migrations Up
CREATE TABLE public.capability_identity_one_use (
 tenant_id text COLLATE "C" NOT NULL CHECK (octet_length(tenant_id) BETWEEN 1 AND 128),
 purpose text COLLATE "C" NOT NULL CHECK (octet_length(purpose) BETWEEN 1 AND 128),
 replay_key_version bigint NOT NULL CHECK (replay_key_version BETWEEN 1 AND 4294967295),
 replay_digest bytea NOT NULL CHECK (octet_length(replay_digest)=32),
 capability_id text COLLATE "C" NOT NULL CHECK (octet_length(capability_id) BETWEEN 1 AND 128),
 proof_fingerprint bytea NOT NULL CHECK (octet_length(proof_fingerprint)=32),
 expires_at timestamptz NOT NULL CHECK (expires_at>=timestamptz '0001-01-01 00:00:00+00' AND expires_at<timestamptz '10000-01-01 00:00:00+00'),
 max_uses integer NOT NULL CHECK (max_uses=1),
 uses integer NOT NULL DEFAULT 0 CHECK (uses BETWEEN 0 AND max_uses),
 state text COLLATE "C" NOT NULL DEFAULT 'issued' CHECK (state IN ('issued','reserved','finalized','released','expired','revoked')),
 command_id text COLLATE "C",
 command_fingerprint bytea,
 generation numeric,
 PRIMARY KEY (tenant_id,purpose,replay_key_version,replay_digest),
 UNIQUE (tenant_id,purpose,capability_id),
 CHECK (command_id IS NULL OR (octet_length(command_id)=22 AND command_id ~ '^[A-Za-z0-9_-]{22}$')),
 CHECK (command_fingerprint IS NULL OR octet_length(command_fingerprint)=32),
 CHECK (generation IS NULL OR (generation BETWEEN 1 AND 18446744073709551615 AND scale(generation)=0)),
 CHECK ((command_id IS NULL AND command_fingerprint IS NULL AND generation IS NULL) OR (command_id IS NOT NULL AND command_fingerprint IS NOT NULL AND generation IS NOT NULL)),
 CHECK ((state IN ('reserved','finalized','released') AND command_id IS NOT NULL) OR (state IN ('issued','expired','revoked'))),
 CHECK (state<>'issued' OR (uses=0 AND command_id IS NULL)),
 CHECK (state<>'finalized' OR uses=1),
 CHECK (state NOT IN ('released','expired','revoked') OR uses=0)
);

-- +migrations Down
-- Unsupported: retained replay evidence must never be dropped by downgrade.
