-- Existing reservations have no proof of ownership and must not be imported.
DELETE FROM reserved_key_slots;
ALTER TABLE reserved_key_slots ADD COLUMN auth_pubkey BLOB NOT NULL DEFAULT X'';
-- Old queue entries were not authorized by the participant.
DELETE FROM pending_key_stores;
ALTER TABLE pending_key_stores ADD COLUMN authorization TEXT NOT NULL DEFAULT '';
