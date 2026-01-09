# KeyMeld Development Setup Guide

This guide explains how to set up and develop KeyMeld, a distributed MuSig2 Bitcoin signing system using AWS Nitro Enclaves.

## 🚀 Quick Start

### Install Nix
```bash
curl -L https://nixos.org/nix/install | sh
```

### Configure as Trusted User (Recommended)
This enables binary caches for faster downloads:

```bash
# Add yourself to trusted users
echo "trusted-users = root $USER" | sudo tee -a /etc/nix/nix.conf

# Restart the Nix daemon
sudo systemctl restart nix-daemon.service

# Verify configuration
nix show-config | grep trusted-users
```

**Why this matters**: Binary caches dramatically speed up initial setup by downloading pre-built packages instead of compiling everything locally.

### Clone and Run
```bash
git clone <your-repo-url>
cd keymeld
just quickstart
```

That's it! Nix handles all dependencies and provides fast incremental builds.

## 🎯 Development Environment

KeyMeld uses a **Nix + Cargo hybrid approach** that gives you the best of both worlds:

**Nix provides:**
- Reproducible environment (Bitcoin Core, SQLite, OpenSSL, etc.)
- All development tools (Rust, cargo, just, bitcoin-cli)
- Binary caches for fast setup
- Guaranteed compatibility across machines

**Cargo provides:**
- True incremental compilation (only rebuilds changed code)
- Fast iteration cycles (10-30 second rebuilds)
- Standard Rust development workflow
- Persistent `target/` directory with build cache

### Speed Comparison
```
First-time setup:     2-5 minutes (Nix downloads/builds dependencies)
Code changes:         10-30 seconds (Cargo incremental compilation)
Dependency changes:   30-60 seconds (Nix rebuilds deps, Cargo updates)

Compare to alternatives:
- Pure Nix builds:    3-5 minutes per change (full rebuild)
- Docker containers:  3-5 minutes per change (layer invalidation)
```

## 📁 Project Structure

```
keymeld/
├── justfile           # All commands (Nix-based)
├── flake.nix          # Nix development environment
├── .envrc             # Direnv integration (optional)
├── crates/            # Rust workspace
│   ├── keymeld-core/      # Core MuSig2 library
│   ├── keymeld-gateway/   # REST API gateway
│   └── keymeld-enclave/   # Enclave runtime
├── examples/          # End-to-end demos
├── config/            # Configuration files
└── data/              # Runtime data (created automatically)
```

## 🔧 Common Commands

### Service Management
```bash
just quickstart     # Complete setup + demo (new users start here)
just start          # Start all services
just stop           # Stop all services
just restart        # Restart all services
just status         # Check service health
```

### Development
```bash
just build          # Build all services (incremental)
just build-prod     # Build production packages (pure Nix)
just test           # Run tests
just fmt            # Format code
just lint           # Lint code
just check          # Run all checks (fmt + lint + test)
```

### Demo & Testing
```bash
just demo           # Run MuSig2 demo
just demo-adaptors  # Run adaptor signatures demo
just mine 10        # Mine 10 regtest blocks
just setup-regtest  # Setup Bitcoin regtest environment
```

## 🏃‍♂️ Development Workflow

### Option 1: Let justfile handle everything (easiest)
```bash
just start            # Builds and starts services
# Make code changes...
just restart          # Fast incremental rebuild (10-30 sec)
just demo             # Test changes
```

### Option 2: Enter dev shell for manual control
```bash
just dev              # Enter Nix development shell
cargo build           # Standard Cargo workflow
cargo test
cargo run --bin keymeld-gateway
```

### Option 3: Production builds
```bash
just build-prod       # Pure Nix builds for deployment
```

**How it works internally:**
1. `cargo build` compiles incrementally in `target/debug/`
2. Binaries link against Nix-provided libraries (OpenSSL, SQLite)
3. `LD_LIBRARY_PATH` is set automatically so binaries find dependencies
4. The `target/` directory persists between sessions for fast rebuilds

### With direnv (Optional but Recommended)
Automatically loads the Nix environment when you enter the directory:

```bash
# Install direnv
curl -sfL https://direnv.net/install.sh | bash

# Enable for this project
direnv allow

# Environment auto-loads when you cd into the directory
cd keymeld  # Automatically loads Nix environment
```

## ⚡ Why Nix for KeyMeld?

### Perfect for Distributed Cryptography
- **Reproducible builds**: Critical for AWS Nitro Enclave attestation
- **Deterministic environments**: Same binary every time, everywhere
- **Security**: Precise dependency control, minimal attack surface
- **Audit-friendly**: Every dependency version locked and verifiable

### Developer Experience Benefits
- **Fast iteration**: 10-30 second rebuilds vs minutes with alternatives
- **No "works on my machine"**: Identical environment for all developers
- **Single command setup**: `just quickstart` and you're running
- **All tools included**: Bitcoin Core, SQLite, Rust, everything needed

### Production Deployment
- **AWS Enclave ready**: Deterministic builds ensure identical production artifacts
- **No dependency surprises**: What builds in dev works in production
- **Minimal containers**: Only essential runtime dependencies included

## 🔍 Troubleshooting

### Nix Issues

#### "Ignoring untrusted substituter" warnings
You need to be a trusted user to use binary caches:
```bash
echo "trusted-users = root $USER" | sudo tee -a /etc/nix/nix.conf
sudo systemctl restart nix-daemon.service
```

#### Slow builds or missing incremental compilation
Make sure you're using Cargo builds, not pure Nix:
```bash
just build            # ✅ Uses Cargo (fast, incremental)
nix build             # ❌ Pure Nix (slow, full rebuild)

# Verify target/ directory exists and persists
ls -la target/        # Should see Cargo build artifacts

# Clean and rebuild if needed
cargo clean
just build
```

#### Build errors after flake updates
```bash
# Clear Nix eval cache
just reset-cache

### VSock Issues

#### "No such device" errors when connecting to enclaves
This is usually caused by incorrect VSock CID configuration in development:

```bash
# ❌ This fails in local development:
# CID 3, 4, 5 don't exist without real VMs

# ✅ Check your config uses host CID (2):
grep -A 10 "enclaves:" config/development.yaml

# Should show:
#   - id: 0
#     cid: 2  # Host CID - required for local development
#     port: 5000
```

**Root cause**: In local development, we simulate AWS Nitro Enclave VSock communication, but VSock Context IDs (CIDs) have special meanings:

- **CID 0**: Reserved (cannot be used)
- **CID 1**: Well-known address for local communication  
- **CID 2**: Well-known address for host (what we use in development)
- **CID 3+**: Guest VM/Enclave CIDs (only available in real virtualization)

In local simulation, we cannot assign arbitrary guest CIDs (3, 4, 5, etc.) because there are no actual separate virtualized contexts. All processes run on the same host, so all enclaves must use the host CID (2) with different ports to differentiate.

**Solution**: Ensure all enclave configurations use `cid: 2` in development mode. The gateway validation allows duplicate CIDs in development but requires unique CIDs in production.

#### VSock proxy connection issues
```bash
# Check proxy status
just vsock-proxy status

# Restart proxies if needed
just stop-vsock-proxies
just start-vsock-proxies

# Test VSock connectivity manually
nix develop -c socat - VSOCK-CONNECT:2:5000 < /dev/null
# Should connect without "No such device" error
```

#### Enclave public key "unavailable" errors
Usually indicates VSock connectivity problems:

```bash
# Check gateway logs for VSock connection errors
tail -20 logs/gateway.log

# Look for "Enclave communication error: Failed to connect"
# If present, it's a VSock configuration issue (see above)

# Verify services are running
just status

# Should show all services healthy
```

# Update flake inputs
just nix-update

# Clean rebuild
cargo clean && just build
```

### Service Issues

#### Services won't start
```bash
# Check what's running
just status

# View service logs
just logs gateway
just logs enclave-0

# Clean restart
just stop && just clean && just start
```

#### Bitcoin regtest problems
```bash
# Reset Bitcoin environment
just clean
just setup-regtest
just mine 10
```

#### Database issues
```bash
# Reset database (nuclear option)
just clean  # This recreates the database from scratch
```

### General Debugging
```bash
just info             # Show system information
just status           # Check service health
nix develop -c env    # Show all environment variables
```

## 🎨 Configuration

### Environment Variables
Create a `.envrc` file (or set in your shell):
```bash
export KEYMELD_ENV=development
export RUST_LOG=debug
export KEYMELD_PORT=8080
```

### Configuration Files
- `config/development.yaml` - Development settings
- `config/production.yaml` - Production settings

Example configuration customization:
```yaml
# config/development.yaml
server:
  port: 8080
logging:
  level: "debug"
enclaves:
  max_users_per_enclave: 50
```

## 📋 Command Reference

### Quick Actions
```bash
just help              # Show all commands
just quickstart        # Complete setup + demo
just info              # System information
just status            # Service status
```

### Service Control
```bash
just start             # Start all services
just stop              # Stop all services
just restart           # Restart services
```

### Development
```bash
just dev               # Enter development shell
just build             # Build (incremental)
just build-prod        # Build (production)
just test              # Run tests
just fmt               # Format code
just lint              # Lint code
just check             # All checks
```

### Demo & Testing
```bash
just demo              # MuSig2 demo
just demo-adaptors     # Adaptor signatures demo
just setup-regtest     # Setup Bitcoin regtest
just mine <blocks>     # Mine regtest blocks
```

### Maintenance
```bash
just clean             # Clean all data
just reset-cache       # Reset Nix cache
just logs <service>    # Show service logs
```

### Nix Specific
```bash
just nix-info          # Show flake info
just nix-update        # Update flake inputs
nix develop            # Enter dev shell manually
nix build .#keymeld-gateway  # Build specific package
```

## 🎯 Best Practices

1. **Use `just quickstart`** for initial setup and demos
2. **Use `just dev`** to enter the development shell for extended work
3. **Use `just check`** before committing code
4. **Use `just build-prod`** for production deployments
5. **Set up direnv** for seamless environment loading
6. **Keep `target/` directory** - it contains your incremental build cache

## 🤝 Contributing

When contributing to KeyMeld:

1. **Install Nix** - it's required for development
2. **Run `just check`** before submitting PRs
3. **Use `just quickstart`** to verify your changes work end-to-end
4. **Update documentation** if you add new justfile commands

## 📞 Getting Help

- `just help` - Show all available commands
- `just info` - Check system status and versions
- `just status` - Check service health
- Check the main README for architecture details
- Review `flake.nix` for the complete development environment definition

## 🚀 Next Steps

After setup, try these to understand KeyMeld:

1. **Run the demo**: `just demo` - See complete 2-phase MuSig2 workflow
2. **Try adaptor signatures**: `just demo-adaptors` - Advanced cryptographic features
3. **Explore the API**: Visit http://localhost:8080/api/v1/docs after `just start`
4. **Read the examples**: Check `examples/README.md` for detailed explanations
5. **Study the architecture**: Main README has comprehensive Mermaid diagrams

KeyMeld is sophisticated distributed cryptography - take time to understand the 2-phase workflow and security model!