-- Track keygen sessions that permanently fail restoration (e.g., key rotation
-- means the encrypted session secret can never be decrypted by the current
-- enclave keys).  These sessions are excluded from future restore attempts.
ALTER TABLE keygen_sessions ADD COLUMN restoration_failed_at INTEGER;
ALTER TABLE keygen_sessions ADD COLUMN restoration_attempts INTEGER NOT NULL DEFAULT 0;
