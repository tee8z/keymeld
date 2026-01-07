# KMS Integration

KeyMeld uses AWS KMS to persist enclave private keys across restarts without exposing them outside the enclave.

## How It Works

1. Enclave generates secp256k1 keypair
2. KMS generates a Data Encryption Key (DEK)
3. Enclave encrypts private key with DEK (AES-256-GCM)
4. Both encrypted DEK and encrypted private key stored in gateway database
5. On restart, enclave requests KMS to decrypt DEK, then decrypts private key

The private key never exists in plaintext outside the enclave.

## Configuration

### Development (LocalStack)

```yaml
# config/development.yaml
kms:
  enabled: true
  endpoint_url: "http://localhost:4566"
  key_id: "alias/keymeld-enclave-master-key"
  enable_attestation: false
```

### Production (AWS KMS)

```yaml
# config/production.yaml
kms:
  enabled: true
  endpoint_url: null
  key_id: "arn:aws:kms:us-west-2:ACCOUNT:key/KEY_ID"
  enable_attestation: true
```

## AWS Setup

### 1. Create KMS Key

```bash
aws kms create-key --description "KeyMeld Production Master Key"
aws kms create-alias --alias-name alias/keymeld-master --target-key-id YOUR_KEY_ID
```

### 2. Get Enclave PCR Values

```bash
nitro-cli describe-eif --eif-path artifacts/keymeld-enclave.eif | jq '.Measurements'
```

### 3. Configure Key Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowKeyMeldEnclaveWithAttestation",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT:role/KeyMeldGatewayRole"},
      "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": "YOUR_PCR0_VALUE",
          "kms:RecipientAttestation:PCR1": "YOUR_PCR1_VALUE",
          "kms:RecipientAttestation:PCR2": "YOUR_PCR2_VALUE"
        }
      }
    }
  ]
}
```

### 4. IAM Role for Gateway

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
    "Resource": "arn:aws:kms:us-west-2:ACCOUNT:key/YOUR_KEY_ID"
  }]
}
```

## Updating Enclave Builds

When deploying new enclave code with different PCR values, update the KMS key policy to allow both old and new builds:

```json
"kms:RecipientAttestation:PCR0": ["OLD_PCR0", "NEW_PCR0"]
```

Remove old PCR values after migration completes.

## Database Schema

```sql
CREATE TABLE enclave_master_keys (
    enclave_id INTEGER PRIMARY KEY,
    kms_encrypted_dek BLOB NOT NULL,
    encrypted_private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    kms_key_id TEXT NOT NULL,
    key_epoch INTEGER DEFAULT 1
);
```

## Testing

```bash
just start
just test-kms-e2e
```

The test validates:
- Initial key generation with KMS
- Signing with KMS-backed keys
- Key persistence across restarts
- Database integrity

## Troubleshooting

**Attestation validation failed**: PCR values in KMS policy don't match your EIF

**Access denied**: IAM role doesn't have KMS permissions

**Keys not persisting**: Check database for encrypted keys:
```bash
sqlite3 data/keymeld.db "SELECT enclave_id, length(encrypted_private_key) FROM enclave_master_keys;"
```

## Cost

- KMS Key: $1/month
- API Requests: $0.03 per 10,000 requests
- Typical usage: ~$1/month total
