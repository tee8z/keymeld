-- Add participant_public_key column to keygen_participants table
-- Migration: Add participant public key storage
-- Date: 2025-11-21

ALTER TABLE keygen_participants ADD COLUMN participant_public_key BLOB;

-- Create index for participant public key lookups
CREATE INDEX idx_keygen_participants_public_key ON keygen_participants(participant_public_key) WHERE participant_public_key IS NOT NULL;
