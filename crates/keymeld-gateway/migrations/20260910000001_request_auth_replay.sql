-- Authentication proofs remain consumed across gateway restarts and replicas
-- using the same database. Entries expire only after the signed proof does.
CREATE TABLE request_auth_nonces (
    nonce_key TEXT PRIMARY KEY NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX request_auth_nonces_expires_at ON request_auth_nonces(expires_at);
