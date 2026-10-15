-- +migrations Up
-- Supersession is orthogonal to consumption custody: reserved command evidence
-- must survive so the coordinator can still recover and terminal-release it.
ALTER TABLE public.capability_identity_one_use
 ADD COLUMN supersession_scope bytea,
 ADD COLUMN superseded_by_command_id text COLLATE "C",
 ADD CONSTRAINT capability_magiclink_supersession_shape CHECK (
  (supersession_scope IS NULL AND superseded_by_command_id IS NULL)
  OR (supersession_scope IS NOT NULL AND octet_length(supersession_scope)=32
   AND purpose='identity.magic-link.consume' AND origin_command_id IS NOT NULL
   AND (superseded_by_command_id IS NULL OR (
    octet_length(superseded_by_command_id)=22
    AND superseded_by_command_id ~ '^[A-Za-z0-9_-]{22}$'
    AND superseded_by_command_id<>origin_command_id)))
 );
CREATE INDEX capability_magiclink_supersession_candidates
 ON public.capability_identity_one_use(tenant_id,supersession_scope)
 WHERE purpose='identity.magic-link.consume' AND uses=0
 AND superseded_by_command_id IS NULL AND state IN ('issued','reserved');

-- +migrations Down
-- Unsupported: removing invalidation evidence could reactivate older links.
