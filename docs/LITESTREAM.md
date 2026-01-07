# Litestream Database Replication

Continuous SQLite replication to S3 for disaster recovery.

## Quick Start

```bash
# Start replication (development)
nix run .#litestream

# Restore from backup
nix run .#restore
```

## Configuration

### Development
Uses LocalStack S3 at `http://localhost:4566`. Config: `config/litestream.yml`

### Production
Uses real AWS S3. Config: `config/litestream.production.yml`

Required S3 setup:
```bash
aws s3 mb s3://keymeld-db-backups
aws s3api put-bucket-versioning --bucket keymeld-db-backups --versioning-configuration Status=Enabled
```

## Recovery

```bash
# Latest backup
nix run .#restore

# Point-in-time
LITESTREAM_TIMESTAMP="2025-12-30T10:00:00Z" nix run .#restore
```

Data loss: <10 seconds (sync interval). Cost: ~$0.43/month.
