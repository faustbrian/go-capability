-- +migrations Up
-- Origin is independent of the subsequent consuming command. Nullable as one
-- group so existing records keep their historical interpretation unchanged.
ALTER TABLE public.capability_identity_one_use
 ADD COLUMN origin_command_id text COLLATE "C",
 ADD COLUMN origin_fingerprint bytea,
 ADD COLUMN origin_generation numeric,
 ADD COLUMN subject_id text COLLATE "C",
 ADD COLUMN signed_issued_at timestamptz,
 ADD COLUMN signed_not_before timestamptz,
 ADD COLUMN signing_key_id text COLLATE "C",
 ADD COLUMN payload_digest bytea,
 ADD COLUMN created_at timestamptz,
 ADD CONSTRAINT capability_original_issuance_group CHECK (
  (origin_command_id IS NULL AND origin_fingerprint IS NULL AND origin_generation IS NULL
   AND subject_id IS NULL AND signed_issued_at IS NULL AND signed_not_before IS NULL
   AND signing_key_id IS NULL AND payload_digest IS NULL AND created_at IS NULL)
  OR
  (origin_command_id IS NOT NULL AND origin_fingerprint IS NOT NULL AND origin_generation IS NOT NULL
   AND subject_id IS NOT NULL AND signed_issued_at IS NOT NULL AND signed_not_before IS NOT NULL
   AND signing_key_id IS NOT NULL AND payload_digest IS NOT NULL AND created_at IS NOT NULL)
 ),
 ADD CONSTRAINT capability_original_issuance_shape CHECK (
  origin_command_id IS NULL OR (
   octet_length(origin_command_id)=22 AND origin_command_id ~ '^[A-Za-z0-9_-]{22}$'
   AND octet_length(origin_fingerprint)=32
   AND origin_generation BETWEEN 1 AND 18446744073709551615 AND scale(origin_generation)=0
   AND octet_length(subject_id) BETWEEN 1 AND 128
   AND octet_length(signing_key_id) BETWEEN 1 AND 256
   AND octet_length(payload_digest)=32
   AND signed_issued_at>=timestamptz '1970-01-01 00:00:00+00'
   AND signed_issued_at=date_trunc('second',signed_issued_at)
   AND signed_not_before=date_trunc('second',signed_not_before)
   AND signed_not_before>=timestamptz '1970-01-01 00:00:00+00'
   AND created_at>=signed_issued_at AND created_at>=signed_not_before AND created_at<expires_at
  )
 );

-- +migrations Down
-- Unsupported: deleting origin evidence makes ambiguous issuance unrecoverable.
