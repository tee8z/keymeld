# KeyMeld AWS Deployment Guide

This guide covers deploying KeyMeld to AWS Nitro Enclaves using our automated Nix-based deployment system.

## Overview

KeyMeld uses a **CI/CD separation** approach for AWS deployment:

- **CI (Build)**: Build EIF and upload to S3 artifact store
- **CD (Deploy)**: Download EIF and deploy to EC2 with auto CID discovery

## Prerequisites

### AWS Setup
- **EC2 Instance** with Nitro Enclaves support (`m5.large` or better)
- **S3 Bucket** for storing EIF artifacts
- **IAM Roles** for CI/CD and EC2 deployment

### Local Tools
```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Install Nitro CLI (on EC2 instance)
wget https://github.com/aws/aws-nitro-enclaves-cli/releases/latest/download/nitro_cli-1.2.2-1_amd64.deb
sudo dpkg -i nitro_cli-1.2.2-1_amd64.deb
sudo apt-get install -f -y
```

## Deployment Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CI Pipeline   │    │   S3 Bucket     │    │   EC2 Instance  │
│   (GitHub)      │───▶│   (Artifacts)   │───▶│   (Runtime)     │
│                 │    │                 │    │                 │
│ • Build EIF     │    │ • Store EIF     │    │ • Download EIF  │
│ • Run Tests     │    │ • Versioning    │    │ • Deploy        │ 
│ • Upload S3     │    │ • Rollbacks     │    │ • Auto CID      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## CI/CD Setup

### 1. Configure GitHub Secrets

```bash
# Required secrets for GitHub Actions
AWS_BUILD_ROLE_ARN="arn:aws:iam::ACCOUNT:role/KeymeldBuildRole"
PRODUCTION_HOST="your-ec2-instance.amazonaws.com"
PRODUCTION_USER="ubuntu"
PRODUCTION_SSH_KEY="-----BEGIN OPENSSH PRIVATE KEY-----..."
```

### 2. Configure GitHub Variables

```bash
# Required variables
KEYMELD_ARTIFACTS_BUCKET="your-keymeld-artifacts-bucket"
AWS_REGION="us-west-2"
```

### 3. Setup S3 Bucket

```bash
# Create S3 bucket for artifacts
aws s3 mb s3://your-keymeld-artifacts-bucket

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket your-keymeld-artifacts-bucket \
  --versioning-configuration Status=Enabled
```

## Deployment Workflow

### CI: Build and Upload (Automatic)

**Triggers**: When you create a git tag (`v1.0.0`, etc.)

```bash
# Create and push a release tag
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions automatically:
# 1. Builds EIF using Nix
# 2. Runs tests and security scans
# 3. Uploads to S3: s3://bucket/keymeld/eifs/keymeld-enclave-v1.0.0.eif
```

### CD: Deploy to Production (Automatic)

**Happens on EC2**: GitHub Actions SSH to your EC2 instance and runs:

```bash
# What happens automatically on your EC2:
export S3_BUCKET=your-keymeld-artifacts-bucket
export VERSION=v1.0.0

# Stop old deployment
just stop-aws

# Download and deploy new version
just deploy-aws

# Start gateway with auto-discovered CIDs
just gateway-aws
```

## Manual Deployment

You can also deploy manually for testing:

### 1. Build EIF Locally

```bash
# Set your S3 bucket
export S3_BUCKET=your-keymeld-artifacts-bucket
export VERSION=v1.0.0

# Build and upload
just build-eif
```

### 2. Deploy to EC2

```bash
# SSH to your EC2 instance
ssh ubuntu@your-ec2-instance.amazonaws.com
cd /opt/keymeld

# Configure deployment
export S3_BUCKET=your-keymeld-artifacts-bucket
export VERSION=v1.0.0

# Deploy
just deploy-aws

# Start gateway  
just gateway-aws
```

## Environment Variables

### CI/CD Build Phase
| Variable | Purpose | Example |
|----------|---------|---------|
| `S3_BUCKET` | Artifact storage | `my-keymeld-artifacts` |
| `VERSION` | Build version | `v1.0.0` |
| `EIF_NAME` | Base EIF name | `keymeld-enclave` |

### Production Deploy Phase
| Variable | Purpose | Example |
|----------|---------|---------|
| `S3_BUCKET` | Download source | `my-keymeld-artifacts` |
| `VERSION` | Version to deploy | `v1.0.0` |
| `ENCLAVE_MEMORY` | Memory per enclave | `512` |
| `ENCLAVE_CPUS` | CPUs per enclave | `1` |
| `NUM_ENCLAVES` | Number of enclaves | `3` |

## Monitoring and Health

### Check Deployment Status

```bash
# Check services
just status

# Check individual components
curl https://your-domain.com/health

# View logs
just logs gateway
just logs enclave-0
```

### Monitor Enclaves

```bash
# List running enclaves
nitro-cli describe-enclaves

# Check enclave resources
nitro-cli describe-enclaves | jq '.[].State'
```

## Troubleshooting

### Build Issues

```bash
# Check CI build logs in GitHub Actions
# Common issues:
# - AWS credentials not configured
# - S3 bucket permissions
# - Nitro CLI installation
```

### Deployment Issues

```bash
# Check EIF download
aws s3 ls s3://your-bucket/keymeld/eifs/

# Check VSock connectivity
just vsock-proxy status
tail -f logs/gateway.log | grep -i "cid"

# Check enclave CID discovery
source keymeld-aws.env
echo "Enclave CIDs: $KEYMELD_ENCLAVE_0_CID $KEYMELD_ENCLAVE_1_CID $KEYMELD_ENCLAVE_2_CID"
```

### Rollback Procedure

```bash
# Stop current deployment
just stop-aws

# Deploy previous version
export VERSION=v1.0.0-previous
just deploy-aws
just gateway-aws

# Or use backup environment
if [ -f keymeld-aws.env.backup ]; then
  mv keymeld-aws.env.backup keymeld-aws.env
  just gateway-aws
fi
```

## Production Recommendations

### Security
- Use separate IAM roles for CI/CD vs runtime
- Enable S3 bucket encryption and access logging
- Regularly rotate SSH keys and AWS credentials
- Monitor enclave attestation status

### Reliability
- Use multiple availability zones
- Implement health check endpoints
- Set up CloudWatch monitoring
- Configure auto-scaling for load

### Operations
- Tag all AWS resources consistently
- Use infrastructure as code (Terraform/CDK)
- Implement blue-green deployments for zero downtime
- Keep deployment logs for audit trails

## Cost Optimization

### EC2 Instance Sizing
```bash
# Development: m5.large (2 vCPU, 8 GB RAM)
# Production: m5.xlarge+ depending on load
# Enclave overhead: ~512MB RAM + 1 CPU per enclave
```

### S3 Storage
```bash
# Use lifecycle policies to archive old EIFs
# Keep last 10 versions, archive older ones to Glacier
```

## Further Reading

- [AWS Nitro Enclaves User Guide](https://docs.aws.amazon.com/enclaves/)
- [KeyMeld VSock Architecture](VSOCK.md)
- [Development Setup Guide](SETUP.md)