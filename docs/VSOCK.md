# VSock Communication in KeyMeld

This document explains how KeyMeld uses VSock (Virtual Socket) communication for secure enclave-to-host communication, the differences between development and production setups, and how to troubleshoot common VSock issues.

## Overview

VSock is a communication protocol designed for virtual machine and container environments. In KeyMeld:

- **Production**: Uses real AWS Nitro Enclaves with native VSock support
- **Development**: Simulates VSock communication using local processes and proxy services

## VSock Addressing Fundamentals

### Context IDs (CIDs)

VSock uses Context IDs (CIDs) to identify communication endpoints. These have standardized meanings:

| CID | Purpose | Usage in KeyMeld |
|-----|---------|------------------|
| 0 | Reserved | Never used |
| 1 | Local loopback | Not used |
| 2 | Host | **Development**: All enclaves use this CID |
| 3+ | Guest VMs/Enclaves | **Production**: Each enclave gets unique CID |

### Ports

Within each CID, ports differentiate services:

- **Development**: Different ports (5000, 5001, 5002) distinguish enclaves
- **Production**: Same port (typically 8000) since CIDs provide isolation

## Production vs Development Architecture

### Production (AWS Nitro Enclaves)

```
┌─────────────────┐    VSock     ┌─────────────────┐
│   Gateway       │◄─────────────┤   Enclave 0     │
│   (Host)        │              │   CID: 16       │
│   CID: 2        │              │   Port: 8000    │
└─────────────────┘              └─────────────────┘
        │                        
        │          VSock          ┌─────────────────┐
        └─────────────────────────┤   Enclave 1     │
                                  │   CID: 17       │
                                  │   Port: 8000    │
                                  └─────────────────┘
```

**Characteristics:**
- Each enclave has a unique CID assigned by AWS
- All enclaves can use the same port (8000)
- True hardware isolation between enclaves
- Native VSock support in Nitro hypervisor

### Development (Local Simulation)

```
┌─────────────────┐              ┌─────────────────┐
│   Gateway       │              │   Enclave 0     │
│   (Host)        │              │   CID: 2        │
│   CID: 2        │              │   Port: 5000    │
└─────────────────┘              └─────────────────┘
        │                        
        │          VSock          ┌─────────────────┐
        └─────────────────────────┤   Enclave 1     │
                (All same CID)    │   CID: 2        │
                                  │   Port: 5001    │
                                  └─────────────────┘
```

**Characteristics:**
- All processes share the host CID (2)
- Different ports (5000, 5001, 5002) distinguish enclaves
- Process-level isolation only
- VSock simulation using kernel modules

## Development Setup Details

### Why CID 2 for All Enclaves?

In local development, we cannot use guest CIDs (3+) because:

1. **No Real VMs**: Guest CIDs require actual virtual machines or containers
2. **Kernel Limitation**: Linux VSock implementation doesn't allow arbitrary CID assignment without proper virtualization
3. **Simulation Approach**: All processes run in the same context (host), so they share the host CID

### VSock Proxy Architecture

Development uses proxy services to bridge networking layers:

```
TCP (9000-9002) ←→ VSock Proxy ←→ VSock (CID:2, Ports:5000-5002)
```

**Purpose:**
- Provides TCP endpoints for easier debugging
- Bridges external connections to VSock enclaves
- Allows tools like `curl` to interact with enclave services

### Configuration Requirements

#### Gateway Configuration (`config/development.yaml`)
```yaml
enclaves:
  enclaves:
    - id: 0
      cid: 2  # Host CID - required for development
      port: 5000
    - id: 1
      cid: 2  # Host CID - required for development
      port: 5001
    - id: 2
      cid: 2  # Host CID - required for development
      port: 5002
```

#### Enclave Startup (justfile)
```bash
# All enclaves use host CID
for i in {0..2}; do
    port=$((5000 + i))
    cid=2  # Host CID - required for local VSock simulation
    ENCLAVE_CID=${cid} VSOCK_PORT=${port} ./keymeld-enclave &
done
```

## Common Issues and Solutions

### Issue: "No such device (os error 19)"

**Symptom:**
```
ERROR keymeld_core::enclave::client: Command failed to CID 3:5000: 
Enclave communication error: Failed to connect: No such device (os error 19)
```

**Root Cause:** Trying to connect to guest CIDs (3, 4, 5) in local development.

**Solution:**
1. Check configuration uses CID 2:
   ```bash
   grep -A 10 "enclaves:" config/development.yaml
   ```
2. Verify all CIDs are set to 2
3. Restart services:
   ```bash
   just restart
   ```

### Issue: "Duplicate enclave CIDs detected"

**Symptom:**
```
Error: Failed to load default config
Caused by: Duplicate enclave CIDs detected
```

**Root Cause:** Configuration validation rejects duplicate CIDs.

**Solution:** This should be automatically handled in development mode. If you see this error:

1. Verify you're using development configuration:
   ```bash
   echo $KEYMELD_ENVIRONMENT  # Should be "development"
   ```
2. Check the gateway loads development config:
   ```bash
   tail -5 logs/gateway.log | grep "Environment: Development"
   ```

### Issue: Enclave public key "unavailable"

**Symptom:**
```
ERROR keymeld_demo: Enclave public key still unavailable after 10 retries
```

**Root Cause:** Gateway cannot connect to enclaves via VSock.

**Solution:**
1. Check VSock proxy status:
   ```bash
   just vsock-proxy status
   ```
2. Verify enclaves are listening:
   ```bash
   grep "VSock server listening" logs/enclave-*.log
   ```
3. Test VSock connectivity:
   ```bash
   nix develop -c socat - VSOCK-CONNECT:2:5000 < /dev/null
   ```

## Debugging VSock Connectivity

### Manual Connection Test
```bash
# Test connection to enclave 0
nix develop -c socat - VSOCK-CONNECT:2:5000 < /dev/null

# Should connect without error
# "No such device" indicates CID/port issues
```

### Check VSock Kernel Modules
```bash
lsmod | grep vsock
# Should show: vsock, vsock_loopback, vhost_vsock
```

### Verify VSock Device
```bash
ls -la /dev/vsock
# Should exist with proper permissions
```

### Monitor VSock Traffic
```bash
# Check proxy logs
tail -f /tmp/keymeld-vsock-proxies/proxy-0.log

# Check enclave logs
tail -f logs/enclave-0.log

# Check gateway logs for connection attempts
tail -f logs/gateway.log | grep -i vsock
```

## Production Deployment with AWS Nitro Enclaves

### Critical: Dynamic CID Assignment

**AWS assigns CIDs dynamically** when enclaves start. The gateway must discover these CIDs at runtime.

### Deployment Workflow

1. **Start AWS Nitro Enclaves**:
   ```bash
   # Start each enclave and capture CID
   CID_0=$(nitro-cli run-enclave --eif-path keymeld-enclave.eif | grep 'CID:' | cut -d: -f2)
   CID_1=$(nitro-cli run-enclave --eif-path keymeld-enclave.eif | grep 'CID:' | cut -d: -f2)
   CID_2=$(nitro-cli run-enclave --eif-path keymeld-enclave.eif | grep 'CID:' | cut -d: -f2)
   ```

2. **Set Environment Variables**:
   ```bash
   export KEYMELD_ENCLAVE_0_CID=$CID_0
   export KEYMELD_ENCLAVE_1_CID=$CID_1
   export KEYMELD_ENCLAVE_2_CID=$CID_2
   ```

3. **Start Gateway with Dynamic CIDs**:
   ```bash
   ./keymeld-gateway  # Reads CIDs from environment
   ```

### Environment Variables for CID Override

| Variable | Purpose | Example |
|----------|---------|---------|
| `KEYMELD_ENCLAVE_0_CID` | CID for enclave 0 | `16` |
| `KEYMELD_ENCLAVE_1_CID` | CID for enclave 1 | `17` |
| `KEYMELD_ENCLAVE_2_CID` | CID for enclave 2 | `18` |
| `KEYMELD_ENCLAVE_0_PORT` | Port override (optional) | `8000` |

### Production Configuration Template
```yaml
# config/production.yaml
enclaves:
  enclaves:
    - id: 0
      cid: 3 # TEMPLATE - Override with KEYMELD_ENCLAVE_0_CID
      port: 8000
    - id: 1
      cid: 4 # TEMPLATE - Override with KEYMELD_ENCLAVE_1_CID
      port: 8000
    - id: 2
      cid: 5 # TEMPLATE - Override with KEYMELD_ENCLAVE_2_CID
      port: 8000
```

### Complete Deployment Script
```bash
#!/bin/bash
set -e

# Build enclave image
nitro-cli build-enclave --docker-uri keymeld:latest --output-file keymeld.eif

# Start enclaves and capture CIDs
echo "Starting AWS Nitro Enclaves..."
CID_0=$(nitro-cli run-enclave --eif-path keymeld.eif --memory 512 --cpu-count 1 | \
        jq -r '.EnclaveId' | xargs nitro-cli describe-enclaves | jq -r '.[0].ContextId')

CID_1=$(nitro-cli run-enclave --eif-path keymeld.eif --memory 512 --cpu-count 1 | \
        jq -r '.EnclaveId' | xargs nitro-cli describe-enclaves | jq -r '.[0].ContextId')

CID_2=$(nitro-cli run-enclave --eif-path keymeld.eif --memory 512 --cpu-count 1 | \
        jq -r '.EnclaveId' | xargs nitro-cli describe-enclaves | jq -r '.[0].ContextId')

# Set environment variables
export KEYMELD_ENCLAVE_0_CID=$CID_0
export KEYMELD_ENCLAVE_1_CID=$CID_1
export KEYMELD_ENCLAVE_2_CID=$CID_2

echo "Enclave CIDs: $CID_0, $CID_1, $CID_2"

# Start gateway
echo "Starting KeyMeld Gateway..."
./keymeld-gateway --config config/production.yaml
```

## Best Practices

### Development
- Always use CID 2 for local development
- Use different ports for each enclave (5000, 5001, 5002)
- Start VSock proxies before other services
- Monitor logs for connection errors

### Production
- **Never hardcode CIDs** - always use environment variable overrides
- Implement health checks that verify enclave connectivity
- Log actual CIDs used for debugging
- Use deployment automation to capture and set CIDs
- Monitor enclave restarts and update CIDs accordingly
- Validate VSock connectivity in readiness probes

### CID Discovery Best Practices
1. **Capture CIDs immediately after enclave start**
2. **Store CIDs in deployment metadata** for restart scenarios
3. **Implement retry logic** for CID discovery failures
4. **Use structured logging** to track CID assignments
5. **Monitor for CID changes** during enclave lifecycle events

## Troubleshooting Production Deployment

### CID Discovery Failures
```bash
# Check enclave status
nitro-cli describe-enclaves

# Verify VSock connectivity
vsock-test -c <cid> -p 8000

# Check environment variables
echo "CID 0: $KEYMELD_ENCLAVE_0_CID"
echo "CID 1: $KEYMELD_ENCLAVE_1_CID"
echo "CID 2: $KEYMELD_ENCLAVE_2_CID"
```

### Gateway Startup Issues
```bash
# Verify configuration override
grep -A 20 "enclaves:" config/production.yaml

# Check gateway logs for CID usage
tail -f /var/log/keymeld/gateway.log | grep -i cid
```

## Further Reading

- [AWS Nitro Enclaves VSock Documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html)
- [AWS Nitro CLI Reference](https://docs.aws.amazon.com/enclaves/latest/user/nitro-cli-run.html)
- [Linux VSock Documentation](https://www.kernel.org/doc/Documentation/networking/af_vsock.rst)
- [VSock Protocol Specification](https://tools.ietf.org/html/rfc-ietf-vmm-vsock-01)
