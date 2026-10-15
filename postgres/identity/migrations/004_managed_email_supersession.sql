-- +migrations Up
-- Reuse the existing family and recovery evidence. Selected management issuance
-- authenticates its signed family; unselected/signup rows remain nullable.
ALTER TABLE public.capability_identity_one_use
 DROP CONSTRAINT capability_magiclink_supersession_shape,
 ADD CONSTRAINT capability_magiclink_supersession_shape CHECK (
  (supersession_scope IS NULL AND superseded_by_command_id IS NULL)
  OR (supersession_scope IS NOT NULL AND octet_length(supersession_scope)=32
   AND purpose IN ('identity.magic-link.consume','identity.identifier.verify')
   AND origin_command_id IS NOT NULL
   AND (superseded_by_command_id IS NULL OR (
    octet_length(superseded_by_command_id)=22
    AND superseded_by_command_id ~ '^[A-Za-z0-9_-]{22}$'
    AND superseded_by_command_id<>origin_command_id)))
 );
CREATE INDEX capability_managed_email_supersession_candidates
 ON public.capability_identity_one_use(tenant_id,supersession_scope)
 WHERE purpose='identity.identifier.verify' AND uses=0
 AND superseded_by_command_id IS NULL AND state IN ('issued','reserved');

-- +migrations Down
-- Unsupported: removing invalidation evidence could reactivate older links.
