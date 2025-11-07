ALTER TABLE keygen_participants ADD COLUMN require_signing_approval BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE signing_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signing_session_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    approved_at INTEGER NOT NULL,
    user_hmac_validated BOOLEAN NOT NULL DEFAULT TRUE,
    session_hmac_validated BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (signing_session_id) REFERENCES signing_sessions (signing_session_id) ON DELETE CASCADE,
    UNIQUE(signing_session_id, user_id)
);


CREATE INDEX idx_signing_approvals_session ON signing_approvals(signing_session_id);
CREATE INDEX idx_signing_approvals_session_user ON signing_approvals(signing_session_id, user_id);
