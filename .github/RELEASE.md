# Release Process

This document describes how to create a new release of KeyMeld.

## Overview

Releases are automated through GitHub Actions and are triggered by pushing a version tag to the repository.

## Steps to Create a Release

1. **Ensure CI is passing** on the `master` branch
   ```bash
   # Check the latest CI status
   git checkout master
   git pull origin master
   ```

2. **Create and push a version tag**
   ```bash
   # Create a tag for the new version (e.g., v0.1.0, v1.2.3)
   git tag v0.1.0
   
   # Push the tag to GitHub
   git push origin v0.1.0
   ```

3. **Automated workflow will:**
   - Extract the version from the tag (e.g., `v0.1.0` → `0.1.0`)
   - Update all `Cargo.toml` files with the new version
   - Commit and push the version updates back to `master`
   - Build release binaries for all supported platforms
   - Create a GitHub release with the binaries attached
   - Generate release notes automatically

4. **Review the release**
   - Go to the [Releases](../../releases) page
   - Verify the release notes and binaries
   - Edit the release description if needed

## Version Numbering

KeyMeld follows [Semantic Versioning](https://semver.org/):
- `MAJOR.MINOR.PATCH` (e.g., `1.2.3`)
- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

## Publishing to crates.io (Optional)

To publish crates to crates.io, uncomment the `publish-crates` job in `.github/workflows/release.yml` and add a `CARGO_REGISTRY_TOKEN` secret to the repository.

## Rollback

If you need to rollback a release:

1. Delete the tag locally and remotely:
   ```bash
   git tag -d v0.1.0
   git push origin :refs/tags/v0.1.0
   ```

2. Delete the GitHub release from the [Releases](../../releases) page

3. Revert the version commit on master if needed:
   ```bash
   git revert <commit-hash>
   git push origin master
   ```

## CI Behavior

- **Regular CI** (on pushes/PRs): Runs tests, linting, and debug builds only
- **Release CI** (on tags): Runs full release build with optimizations
- **Concurrency**: New commits automatically cancel outdated CI runs on the same branch/PR
