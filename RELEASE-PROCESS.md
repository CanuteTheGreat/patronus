# Patronus Firewall Release Process

This document describes how to create and publish a new release of Patronus Firewall.

## Prerequisites

- Commit access to both repositories (main and overlay)
- GitHub account with repository access
- Gentoo system for testing (recommended)

## Release Checklist

### 1. Pre-Release Testing

- [ ] Run all tests: `cargo test --workspace --all-features`
- [ ] Run security audit: `cargo audit`
- [ ] Run clippy: `cargo clippy --all-features -- -D warnings`
- [ ] Test minimal build: `cargo build --release --no-default-features --features "cli,nftables"`
- [ ] Test full build: `cargo build --release --all-features`
- [ ] Verify documentation builds: `cargo doc --all-features`

### 2. Update Version Numbers

Update version in the following files:

**Main Repository:**
- `Cargo.toml` - workspace version
- `README.md` - version references
- `CHANGELOG.md` - add new release section
- All crate `Cargo.toml` files (if using workspace = true, this is automatic)

**Overlay Repository:**
- `gentoo-overlay/net-firewall/patronus/patronus-X.Y.Z.ebuild` - create new ebuild
- `gentoo-overlay/README.md` - update version references

### 3. Generate Cargo.lock

```bash
cd /path/to/patronus
cargo generate-lockfile
```

### 4. Update CRATES in Ebuild

```bash
cd /path/to/patronus/gentoo-overlay
./generate-crates.sh
# Copy CRATES section to patronus-X.Y.Z.ebuild
```

Or use cargo-ebuild:

```bash
cd /path/to/patronus
cargo ebuild > /tmp/patronus-generated.ebuild
# Extract CRATES section
```

### 5. Commit Changes

**Main Repository:**
```bash
cd /path/to/patronus
git add .
git commit -m "Release v$VERSION

- Update version to $VERSION
- Update CHANGELOG
- Update dependencies"
```

**Overlay Repository:**
```bash
cd /path/to/patronus/gentoo-overlay
git add .
git commit -m "Add patronus-$VERSION ebuild

- Update to version $VERSION
- Update CRATES dependencies"
```

### 6. Create Release Artifacts

```bash
cd /path/to/patronus
./create-release.sh $VERSION
```

This creates:
- `releases/patronus-$VERSION.tar.gz`
- `releases/patronus-$VERSION.tar.gz.sha256`

### 7. Create Git Tags

**Main Repository:**
```bash
cd /path/to/patronus
git tag -a v$VERSION -m "Patronus Firewall v$VERSION

[Describe major changes]

🤖 Generated with Claude Code
Co-Authored-By: Claude <noreply@anthropic.com>"
```

**Overlay Repository:**
```bash
cd /path/to/patronus/gentoo-overlay
git tag -a v$VERSION -m "Patronus Gentoo Overlay v$VERSION

Compatible with Patronus Firewall v$VERSION"
```

### 8. Push to GitHub

**Main Repository:**
```bash
cd /path/to/patronus
git push origin main
git push origin v$VERSION
```

**Overlay Repository:**
```bash
cd /path/to/patronus/gentoo-overlay
git push origin main
git push origin v$VERSION
```

### 9. Create GitHub Release

#### Main Repository

1. Go to https://github.com/yourusername/patronus/releases/new
2. Select tag: `v$VERSION`
3. Release title: `Patronus Firewall v$VERSION`
4. Description:

```markdown
## Overview
[Brief description of major changes]

## Features
- Feature 1
- Feature 2

## Bug Fixes
- Fix 1
- Fix 2

## Performance
- Improvement 1

## Security
- Security update 1

## Installation

### Gentoo Linux
```bash
emerge -av net-firewall/patronus
```

### From Source
```bash
curl -L https://github.com/yourusername/patronus/archive/v$VERSION.tar.gz | tar xz
cd patronus-$VERSION
cargo build --release --all-features
```

## Documentation
- [README](https://github.com/yourusername/patronus/blob/v$VERSION/README.md)
- [Building Guide](https://github.com/yourusername/patronus/blob/v$VERSION/BUILDING.md)
- [Security Hardening](https://github.com/yourusername/patronus/blob/v$VERSION/SECURITY-HARDENING.md)

## Checksums
SHA256: [paste from .sha256 file]

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

5. Upload `patronus-$VERSION.tar.gz` as a release asset
6. Publish release

#### Overlay Repository

1. Go to https://github.com/yourusername/patronus-overlay/releases/new
2. Select tag: `v$VERSION`
3. Release title: `Patronus Overlay v$VERSION`
4. Description:

```markdown
Gentoo overlay for Patronus Firewall v$VERSION

## Changes
- Update to Patronus v$VERSION
- [List overlay-specific changes]

## Installation
```bash
eselect repository add patronus git https://github.com/yourusername/patronus-overlay
emaint sync -r patronus
emerge -av net-firewall/patronus
```

Compatible with Patronus Firewall v$VERSION
```

5. Publish release

### 10. Update Ebuild SRC_URI

After creating the GitHub release, the tarball will be available at:
```
https://github.com/yourusername/patronus/archive/v$VERSION.tar.gz
```

The ebuild already uses this format:
```bash
SRC_URI="https://github.com/yourusername/patronus/archive/v${PV}.tar.gz -> ${P}.tar.gz
	$(cargo_crate_uris ${CRATES})"
```

No manual update needed if the format is correct!

### 11. Generate Ebuild Manifest

On a Gentoo system:

```bash
cd /var/db/repos/patronus
ebuild net-firewall/patronus/patronus-$VERSION.ebuild manifest
```

This will:
1. Download the source tarball
2. Download all 660 Cargo crates
3. Verify checksums
4. Generate the `Manifest` file

### 12. Test the Ebuild

```bash
# Test pretend
emerge -pv net-firewall/patronus

# Test actual build
USE="cli nftables" emerge -av net-firewall/patronus

# Test with all features
USE="web cli api nftables gitops ai kubernetes arch-native" emerge -av net-firewall/patronus
```

### 13. Submit to Gentoo GURU (Optional)

If submitting to the official Gentoo GURU repository:

1. Fork https://github.com/gentoo/guru
2. Add the ebuild to the appropriate category
3. Run `pkgcheck scan --commits`
4. Fix any QA issues
5. Submit pull request
6. Wait for review

See: https://wiki.gentoo.org/wiki/Project:GURU/Information_for_Contributors

### 14. Announce Release

Post announcements on:
- GitHub Discussions
- Gentoo Forums
- Reddit (r/Gentoo, r/selfhosted)
- Twitter/Mastodon
- Project blog/website

## Hotfix Release Process

For urgent bug fixes:

1. Create hotfix branch from tag: `git checkout -b hotfix-$VERSION v$VERSION`
2. Apply fix
3. Update version to $VERSION-patch (e.g., 0.1.1)
4. Follow steps 3-13 above
5. Merge hotfix back to main

## Version Numbering

Patronus uses Semantic Versioning (SemVer):

- **MAJOR** (X.0.0): Breaking changes, incompatible API changes
- **MINOR** (0.X.0): New features, backwards compatible
- **PATCH** (0.0.X): Bug fixes, backwards compatible

Examples:
- `0.1.0` - Initial release
- `0.1.1` - Bug fix release
- `0.2.0` - New feature release
- `1.0.0` - First stable release

## Release Schedule

Suggested schedule:
- **Patch releases**: As needed for critical bugs
- **Minor releases**: Every 2-3 months
- **Major releases**: Annually or when significant breaking changes

## Troubleshooting

### Manifest Generation Fails

**Error:** "Crate not found"
- Check CRATES list is complete
- Regenerate with `cargo ebuild`
- Verify network connectivity

**Error:** "Checksum mismatch"
- Tarball was modified after upload
- Re-upload tarball to GitHub
- Clear distfiles: `rm /var/cache/distfiles/patronus-*`

### Build Failures

**Error:** "Feature not found"
- Verify feature flags match between ebuild and Cargo.toml
- Check all usex entries in src_configure

**Error:** "Cannot find crate"
- Missing workspace member in Cargo.toml
- Missing src/lib.rs or src/main.rs

## Post-Release Tasks

- [ ] Monitor GitHub issues for bug reports
- [ ] Update documentation based on feedback
- [ ] Plan next release features
- [ ] Update roadmap

---

**Last Updated:** 2025-10-08
**Current Version:** 0.1.0
