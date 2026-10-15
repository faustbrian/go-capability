-- +migrations Up
-- Only authenticated original issuance can populate the signed identifier.
-- Existing grants stay unclassified: guessing from current account state would
-- permit selective retirement to miss an original credential or retire another.
ALTER TABLE public.capability_identity_one_use
 ADD COLUMN verification_identifier_id text COLLATE "C",
 ADD CONSTRAINT capability_verification_target_shape CHECK (
  verification_identifier_id IS NULL OR (
   purpose='identity.identifier.verify' AND origin_command_id IS NOT NULL
   AND octet_length(verification_identifier_id) BETWEEN 1 AND 128
   AND verification_identifier_id !~ '[[:cntrl:]]'));
CREATE INDEX capability_verification_target_candidates
 ON public.capability_identity_one_use(tenant_id,subject_id,verification_identifier_id)
 WHERE purpose='identity.identifier.verify' AND uses=0
 AND state IN ('issued','reserved');

-- +migrations Down
-- Unsupported: discarding original targets could omit usable links at removal.
