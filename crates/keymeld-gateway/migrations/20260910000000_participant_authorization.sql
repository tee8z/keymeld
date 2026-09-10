-- Legacy sessions do not contain the mandatory authorization manifest and cannot
-- be resumed by this protocol version. Create new sessions after upgrading.
ALTER TABLE keygen_participants ADD COLUMN registration_authorization TEXT NOT NULL DEFAULT '';

ALTER TABLE signing_approvals ADD COLUMN approval_proof TEXT NOT NULL DEFAULT '';
