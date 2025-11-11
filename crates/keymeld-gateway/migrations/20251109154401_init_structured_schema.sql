-- KeyMeld Database Schema - Structured Encrypted Data
-- Uses BLOB storage for v7 UUIDs (16 bytes vs 36 bytes TEXT)
-- Uses structured encrypted data columns for clean separation of session vs enclave encrypted data
-- Compatible with sqlean UUID extension for native uuid7() support
-- See: https://github.com/nalgeon/sqlean

CREATE TABLE keygen_sessions (
    keygen_session_id BLOB PRIMARY KEY,
    status_name TEXT NOT NULL,
    coordinator_enclave_id INTEGER,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    collecting_participants_at INTEGER,
    completed_at INTEGER,
    failed_at INTEGER,
    processing_started_at INTEGER,
    last_processing_attempt INTEGER,
    retry_count INTEGER DEFAULT 0,
    max_signing_sessions INTEGER,
    expected_participants TEXT NOT NULL,
    aggregate_pubkey_hash BLOB,
    status TEXT NOT NULL,
    error_message TEXT,
    session_encrypted_data TEXT NOT NULL DEFAULT '{}',
    enclave_encrypted_data TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE keygen_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keygen_session_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    assigned_enclave_id INTEGER,
    enclave_key_epoch INTEGER,
    registered_at INTEGER NOT NULL,
    require_signing_approval BOOLEAN NOT NULL DEFAULT FALSE,
    session_encrypted_data TEXT NOT NULL DEFAULT '{}',
    enclave_encrypted_data TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (keygen_session_id) REFERENCES keygen_sessions (keygen_session_id) ON DELETE CASCADE,
    UNIQUE(keygen_session_id, user_id)
);

CREATE TABLE signing_sessions (
    signing_session_id BLOB PRIMARY KEY,
    keygen_session_id BLOB NOT NULL,
    status_name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    collecting_participants_at INTEGER,
    generating_nonces_at INTEGER,
    collecting_nonces_at INTEGER,
    aggregating_nonces_at INTEGER,
    generating_signatures_at INTEGER,
    collecting_signatures_at INTEGER,
    finalizing_signature_at INTEGER,
    completed_at INTEGER,
    failed_at INTEGER,
    processing_started_at INTEGER,
    last_processing_attempt INTEGER,
    retry_count INTEGER DEFAULT 0,
    correlation_id BLOB,
    message_hash BLOB NOT NULL,
    expected_participants TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    session_encrypted_data TEXT NOT NULL DEFAULT '{}',
    enclave_encrypted_data TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (keygen_session_id) REFERENCES keygen_sessions (keygen_session_id)
);

CREATE TABLE signing_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signing_session_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    assigned_enclave_id INTEGER NOT NULL,
    enclave_key_epoch INTEGER NOT NULL,
    registered_at INTEGER NOT NULL,
    public_nonces BLOB,
    partial_signature BLOB,
    session_encrypted_data TEXT NOT NULL DEFAULT '{}',
    enclave_encrypted_data TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (signing_session_id) REFERENCES signing_sessions (signing_session_id) ON DELETE CASCADE,
    UNIQUE(signing_session_id, user_id)
);

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

CREATE TABLE enclave_public_keys (
    enclave_id INTEGER PRIMARY KEY,
    is_healthy BOOLEAN DEFAULT TRUE,
    key_epoch INTEGER DEFAULT 1,
    cached_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    key_generation_time INTEGER DEFAULT 0,
    startup_time INTEGER DEFAULT 0,
    active_sessions INTEGER DEFAULT 0,
    public_key TEXT NOT NULL,
    attestation_document TEXT DEFAULT '',
    UNIQUE(enclave_id)
);

-- Indexes
CREATE INDEX idx_keygen_sessions_status_expires ON keygen_sessions(status_name, expires_at, updated_at);
CREATE INDEX idx_keygen_participants_session ON keygen_participants(keygen_session_id);

CREATE INDEX idx_signing_sessions_keygen ON signing_sessions(keygen_session_id);
CREATE INDEX idx_signing_sessions_processing ON signing_sessions(status_name, expires_at, processing_started_at, last_processing_attempt, retry_count, updated_at);
CREATE INDEX idx_signing_sessions_keygen_count ON signing_sessions(keygen_session_id, status_name);
CREATE INDEX idx_signing_sessions_correlation_id ON signing_sessions(correlation_id) WHERE correlation_id IS NOT NULL;

CREATE INDEX idx_signing_participants_session ON signing_participants(signing_session_id);
CREATE INDEX idx_signing_participants_session_user ON signing_participants(signing_session_id, user_id);

CREATE INDEX idx_signing_approvals_session ON signing_approvals(signing_session_id);
CREATE INDEX idx_signing_approvals_session_user ON signing_approvals(signing_session_id, user_id);

CREATE INDEX idx_enclave_public_keys_expires_at ON enclave_public_keys(expires_at);
CREATE INDEX idx_enclave_public_keys_enclave_id ON enclave_public_keys(enclave_id);

-- Structured Encrypted Data Documentation:
-- All session_encrypted_data and enclave_encrypted_data columns contain JSON objects
-- serialized from Rust structs in crates/keymeld-core/src/encrypted_data.rs
--
-- keygen_sessions.session_encrypted_data: KeygenSessionData
-- keygen_sessions.enclave_encrypted_data: KeygenEnclaveData
-- keygen_participants.session_encrypted_data: KeygenParticipantSessionData
-- keygen_participants.enclave_encrypted_data: KeygenParticipantEnclaveData
-- signing_sessions.session_encrypted_data: SigningSessionData
-- signing_sessions.enclave_encrypted_data: SigningEnclaveData
-- signing_participants.session_encrypted_data: SigningParticipantSessionData
-- signing_participants.enclave_encrypted_data: SigningParticipantEnclaveData
