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
    session_encrypted_data TEXT,
    enclave_encrypted_data TEXT,
    session_public_key BLOB
);

CREATE TABLE keygen_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keygen_session_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    -- Reference to user_keys table for key material
    user_key_id INTEGER,
    registered_at INTEGER NOT NULL,
    require_signing_approval BOOLEAN NOT NULL DEFAULT FALSE,
    -- Session-encrypted participant data (nonces, commitments, etc.)
    session_encrypted_data TEXT,
    FOREIGN KEY (keygen_session_id) REFERENCES keygen_sessions (keygen_session_id) ON DELETE CASCADE,
    FOREIGN KEY (user_key_id) REFERENCES user_keys (id),
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
    session_encrypted_data TEXT,
    enclave_encrypted_data TEXT,
    FOREIGN KEY (keygen_session_id) REFERENCES keygen_sessions (keygen_session_id)
);

CREATE TABLE signing_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signing_session_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    -- Reference to user_keys table for key material
    user_key_id INTEGER NOT NULL,
    registered_at INTEGER NOT NULL,
    -- Session-encrypted participant data (nonces, partial signatures, etc.)
    session_encrypted_data TEXT,
    FOREIGN KEY (signing_session_id) REFERENCES signing_sessions (signing_session_id) ON DELETE CASCADE,
    FOREIGN KEY (user_key_id) REFERENCES user_keys (id),
    UNIQUE(signing_session_id, user_id)
);

CREATE TABLE signing_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signing_session_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    approved_at INTEGER NOT NULL,
    user_signature_validated BOOLEAN NOT NULL DEFAULT TRUE,
    session_signature_validated BOOLEAN NOT NULL DEFAULT TRUE,
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
CREATE INDEX idx_keygen_sessions_reserved ON keygen_sessions(status_name, created_at) WHERE status_name = 'reserved';
CREATE INDEX idx_keygen_sessions_public_key ON keygen_sessions(session_public_key) WHERE session_public_key IS NOT NULL;
CREATE INDEX idx_keygen_participants_session ON keygen_participants(keygen_session_id);
CREATE INDEX idx_keygen_participants_user_key ON keygen_participants(user_key_id);

CREATE INDEX idx_signing_sessions_keygen ON signing_sessions(keygen_session_id);
CREATE INDEX idx_signing_sessions_processing ON signing_sessions(status_name, expires_at, processing_started_at, last_processing_attempt, retry_count, updated_at);
CREATE INDEX idx_signing_sessions_keygen_count ON signing_sessions(keygen_session_id, status_name);
CREATE INDEX idx_signing_sessions_correlation_id ON signing_sessions(correlation_id) WHERE correlation_id IS NOT NULL;

CREATE INDEX idx_signing_participants_session ON signing_participants(signing_session_id);
CREATE INDEX idx_signing_participants_session_user ON signing_participants(signing_session_id, user_id);
CREATE INDEX idx_signing_participants_user_key ON signing_participants(user_key_id);

CREATE INDEX idx_signing_approvals_session ON signing_approvals(signing_session_id);
CREATE INDEX idx_signing_approvals_session_user ON signing_approvals(signing_session_id, user_id);

CREATE INDEX idx_enclave_public_keys_expires_at ON enclave_public_keys(expires_at);
CREATE INDEX idx_enclave_public_keys_enclave_id ON enclave_public_keys(enclave_id);

-- Enclave Persistent Keys
-- Stores each enclave's secp256k1 private key, encrypted with a KMS-derived DEK
-- Flow: KMS generates DEK → Enclave uses DEK to encrypt private_key → Store encrypted private_key
-- On restart: KMS decrypts DEK → Enclave uses DEK to decrypt private_key → Derive public_key
CREATE TABLE enclave_master_keys (
    enclave_id INTEGER PRIMARY KEY,
    kms_encrypted_dek BLOB NOT NULL,
    encrypted_private_key BLOB NOT NULL,
    kms_key_id TEXT NOT NULL,
    key_epoch INTEGER DEFAULT 1
);

CREATE INDEX idx_enclave_master_keys_kms_key
    ON enclave_master_keys(kms_key_id);

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

-- ============================================================================
-- User Keys: Storage for user-owned private keys in the enclave
-- ============================================================================
-- Private key is ECIES-encrypted to enclave's public key (gateway cannot decrypt)
-- Public key is NOT stored here (treated as secret, only in enclave memory)
--
-- Key sources:
--   - Imported: User encrypts their private key to enclave's public key and imports
--   - From keygen: User persists their key from a completed keygen session
--
-- Security model:
--   - auth_pubkey is derived from user's private key client-side (immutable once set)
--   - No rotation: if auth_pubkey is compromised, delete the key and import a new one
--   - This simplifies the design and removes attack surface from rotation endpoints

CREATE TABLE user_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BLOB NOT NULL,
    key_id BLOB NOT NULL,
    enclave_id INTEGER NOT NULL,
    enclave_key_epoch INTEGER NOT NULL,
    -- Private key ECIES encrypted to enclave's public key
    -- Gateway cannot decrypt this - only the enclave can
    encrypted_private_key BLOB NOT NULL,
    -- Auth public key for authenticating requests (immutable)
    -- Derived from user's private key, used to sign all API requests
    auth_pubkey BLOB NOT NULL,
    -- NULL if imported, set if from keygen session
    origin_keygen_session_id BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, key_id),
    FOREIGN KEY (enclave_id) REFERENCES enclave_public_keys(enclave_id)
);

CREATE INDEX idx_user_keys_user_id ON user_keys(user_id);
CREATE INDEX idx_user_keys_enclave ON user_keys(enclave_id);
CREATE INDEX idx_user_keys_key_id ON user_keys(key_id);

-- Single-signer signing sessions
-- For signing messages with stored user keys (without MuSig2)
CREATE TABLE single_signing_sessions (
    signing_session_id BLOB PRIMARY KEY,
    user_key_id INTEGER NOT NULL,
    status_name TEXT NOT NULL,
    -- Message encrypted to session secret (ECIES encrypted to enclave)
    encrypted_message BLOB,
    -- Session secret ECIES encrypted to enclave's public key
    encrypted_session_secret BLOB,
    -- Result signature encrypted to session secret
    encrypted_signature TEXT,
    -- Signature type: schnorr_bip340 or ecdsa
    signature_type TEXT NOT NULL,
    -- Approval signature: Sign(auth_privkey, SHA256(message_hash || key_id || approval_timestamp))
    -- Proves user authorized this specific signing operation
    approval_signature BLOB NOT NULL,
    -- Timestamp used in approval signature (enclave checks freshness)
    approval_timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    completed_at INTEGER,
    expires_at INTEGER NOT NULL,
    error_message TEXT,
    processing_started_at INTEGER,
    last_processing_attempt INTEGER,
    retry_count INTEGER DEFAULT 0,
    FOREIGN KEY (user_key_id) REFERENCES user_keys(id)
);

CREATE INDEX idx_single_signing_user_key ON single_signing_sessions(user_key_id);
CREATE INDEX idx_single_signing_status ON single_signing_sessions(status_name, expires_at);
CREATE INDEX idx_single_signing_processing ON single_signing_sessions(status_name, expires_at, processing_started_at, last_processing_attempt, retry_count, updated_at);

-- Reserved key slots for the two-phase import flow
-- Step 1: Client calls /keys/reserve to get an enclave assignment
-- Step 2: Client encrypts private key to that enclave and calls /keys/import
CREATE TABLE reserved_key_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id BLOB NOT NULL UNIQUE,
    user_id BLOB NOT NULL,
    enclave_id INTEGER NOT NULL,
    enclave_key_epoch INTEGER NOT NULL,
    reserved_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (enclave_id) REFERENCES enclave_public_keys(enclave_id)
);

CREATE INDEX idx_reserved_key_slots_key_id ON reserved_key_slots(key_id);
CREATE INDEX idx_reserved_key_slots_user ON reserved_key_slots(user_id);
CREATE INDEX idx_reserved_key_slots_expires ON reserved_key_slots(expires_at);

-- ============================================================================
-- Pending Key Imports: Async processing queue for key imports
-- ============================================================================
-- Follows the DB-first architecture: handler writes here, coordinator processes
-- On success: record moved to user_keys table
-- On failure: status updated to 'failed' with error message

CREATE TABLE pending_key_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id BLOB NOT NULL UNIQUE,
    user_id BLOB NOT NULL,
    enclave_id INTEGER NOT NULL,
    enclave_key_epoch INTEGER NOT NULL,
    -- Private key ECIES encrypted to enclave's public key
    encrypted_private_key BLOB NOT NULL,
    -- Auth public key for authenticating requests
    auth_pubkey BLOB NOT NULL,
    -- Processing status: pending, processing, completed, failed
    status_name TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    processing_started_at INTEGER,
    last_processing_attempt INTEGER,
    retry_count INTEGER DEFAULT 0,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (enclave_id) REFERENCES enclave_public_keys(enclave_id)
);

CREATE INDEX idx_pending_key_imports_status ON pending_key_imports(status_name, expires_at);
CREATE INDEX idx_pending_key_imports_user_key ON pending_key_imports(user_id, key_id);
CREATE INDEX idx_pending_key_imports_processing ON pending_key_imports(status_name, expires_at, processing_started_at, last_processing_attempt, retry_count);

-- ============================================================================
-- Pending Key Stores: Async processing queue for storing keys from keygen
-- ============================================================================
-- Follows the DB-first architecture: handler writes here, coordinator processes
-- On success: encrypted key stored in user_keys table
-- On failure: status updated to 'failed' with error message

CREATE TABLE pending_key_stores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id BLOB NOT NULL UNIQUE,
    user_id BLOB NOT NULL,
    keygen_session_id BLOB NOT NULL,
    -- Enclave where the user's key is stored (from keygen participant assignment)
    enclave_id INTEGER NOT NULL,
    -- Processing status: pending, processing, completed, failed
    status_name TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    processing_started_at INTEGER,
    last_processing_attempt INTEGER,
    retry_count INTEGER DEFAULT 0,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (enclave_id) REFERENCES enclave_public_keys(enclave_id),
    FOREIGN KEY (keygen_session_id) REFERENCES keygen_sessions(keygen_session_id)
);

CREATE INDEX idx_pending_key_stores_status ON pending_key_stores(status_name, expires_at);
CREATE INDEX idx_pending_key_stores_user_key ON pending_key_stores(user_id, key_id);
CREATE INDEX idx_pending_key_stores_processing ON pending_key_stores(status_name, expires_at, processing_started_at, last_processing_attempt, retry_count);
