# Patronus SD-WAN CI/CD Pipeline

**Version**: 1.0.0
**Last Updated**: 2025-10-11

---

## Overview

This document describes the Continuous Integration and Continuous Deployment (CI/CD) pipeline for Patronus SD-WAN.

### Pipeline Goals

- **Quality**: Ensure all code changes pass tests and linting
- **Security**: Automated security audits and vulnerability scanning
- **Speed**: Fast feedback (<15 minutes for CI)
- **Reliability**: Consistent builds across environments
- **Automation**: Minimal manual intervention required

---

## CI Pipeline (GitHub Actions)

### Workflow: `.github/workflows/ci.yml`

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main`
- Manual workflow dispatch

**Jobs**:

1. **Test Suite** (~10 minutes)
   - Format checking (`cargo fmt`)
   - Linting (`cargo clippy`)
   - Unit tests (`cargo test`)
   - Documentation tests

2. **Security Audit** (~5 minutes)
   - Dependency audit (`cargo audit`)
   - License checking (`cargo deny`)

3. **Build Release** (~20 minutes, parallel)
   - Linux x86_64
   - macOS x86_64
   - Upload artifacts

4. **Code Coverage** (~15 minutes)
   - Generate coverage report
   - Upload to Codecov

5. **Docker Build** (~15 minutes)
   - Build Docker image
   - Test image

6. **Integration Tests** (~20 minutes)
   - Full integration test suite
   - With PostgreSQL service

7. **Documentation** (~10 minutes)
   - Build Rust docs
   - Check for broken links

###Usage

```bash
# CI runs automatically on push/PR

# Manual trigger
gh workflow run ci.yml

# View status
gh run list --workflow=ci.yml

# View logs
gh run view <run-id> --log
```

---

## Release Pipeline

### Workflow: `.github/workflows/release.yml`

**Triggers**:
- Push of version tag (e.g., `v1.0.0`)
- Manual workflow dispatch with version input

**Jobs**:

1. **Create Release** (~2 minutes)
   - Create GitHub release
   - Generate release notes

2. **Build Linux** (~20 minutes)
   - Build for x86_64-unknown-linux-gnu
   - Strip binaries
   - Package as .tar.gz
   - Upload to release

3. **Build macOS** (~20 minutes)
   - Build for x86_64-apple-darwin
   - Strip binaries
   - Package as .tar.gz
   - Upload to release

4. **Docker Release** (~25 minutes)
   - Multi-arch build (amd64, arm64)
   - Push to GitHub Container Registry
   - Tag as latest and version

5. **Publish Crates** (~10 minutes)
   - Publish to crates.io (optional)

### Creating a Release

```bash
# 1. Update version in Cargo.toml files
./scripts/update-version.sh 1.0.0

# 2. Update CHANGELOG.md

# 3. Commit changes
git add .
git commit -m "Release v1.0.0"

# 4. Create and push tag
git tag v1.0.0
git push origin main --tags

# 5. GitHub Actions will automatically:
#    - Run CI pipeline
#    - Build release artifacts
#    - Create GitHub release
#    - Publish Docker images

# 6. Verify release
gh release view v1.0.0
```

---

## Docker Images

### Available Images

```bash
# Latest stable
docker pull ghcr.io/patronus/patronus-sdwan:latest

# Specific version
docker pull ghcr.io/patronus/patronus-sdwan:v1.0.0

# Major version
docker pull ghcr.io/patronus/patronus-sdwan:1

# Development
docker pull ghcr.io/patronus/patronus-sdwan:develop
```

### Image Tags

| Tag | Description | Update Frequency |
|-----|-------------|------------------|
| `latest` | Latest stable release | On release |
| `v1.0.0` | Specific version | Never (immutable) |
| `1` | Latest 1.x | On 1.x release |
| `1.0` | Latest 1.0.x | On 1.0.x release |
| `develop` | Development branch | On push to develop |

---

## Local Development Workflow

### Setup

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install tools
cargo install cargo-watch cargo-nextest cargo-audit

# Install pre-commit hooks
./scripts/install-hooks.sh
```

### Pre-commit Checks

```bash
# Format code
cargo fmt --all

# Run linter
cargo clippy --workspace --all-features -- -D warnings

# Run tests
cargo test --workspace --all-features

# Run security audit
cargo audit
```

### Watch Mode (Development)

```bash
# Auto-rebuild and run tests on file changes
cargo watch -x test -x clippy

# Auto-rebuild and run specific test
cargo watch -x "test health_monitor"
```

---

## Deployment

### Manual Deployment

```bash
# 1. Download release
wget https://github.com/patronus/patronus/releases/download/v1.0.0/patronus-linux-x86_64.tar.gz

# 2. Extract
tar xzf patronus-linux-x86_64.tar.gz

# 3. Install
sudo cp patronus-sdwan /usr/bin/
sudo cp patronus-dashboard /usr/bin/

# 4. Configure
sudo cp config.example.yaml /etc/patronus/config.yaml
sudo vim /etc/patronus/config.yaml

# 5. Start services
sudo systemctl enable --now patronus-sdwan
sudo systemctl enable --now patronus-dashboard
```

### Docker Deployment

```bash
# Using docker-compose
git clone https://github.com/patronus/patronus
cd patronus
cp config.example.yaml config/config.yaml
vim config/config.yaml

docker-compose up -d

# Verify
docker-compose ps
curl http://localhost:8080/
```

### Kubernetes Deployment

```bash
# Using Helm (future)
helm repo add patronus https://patronus.github.io/charts
helm install patronus patronus/patronus-sdwan \
  --set config.check_interval=10 \
  --set image.tag=v1.0.0
```

---

## Continuous Deployment (CD)

### Automated Deployment (Optional)

For automated deployments to staging/production:

**.github/workflows/deploy.yml**:

```yaml
name: Deploy

on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment to deploy to'
        required: true
        type: choice
        options:
          - staging
          - production

jobs:
  deploy:
    name: Deploy to \${{ github.event.inputs.environment || 'production' }}
    runs-on: ubuntu-latest
    environment: \${{ github.event.inputs.environment || 'production' }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Deploy to environment
        run: |
          # Add deployment logic here
          # e.g., kubectl apply, terraform apply, etc.
          echo "Deploying to \${{ github.event.inputs.environment }}"
```

---

## Monitoring CI/CD

### GitHub Actions Badges

Add to README.md:

```markdown
![CI](https://github.com/patronus/patronus/workflows/CI/badge.svg)
![Release](https://github.com/patronus/patronus/workflows/Release/badge.svg)
[![codecov](https://codecov.io/gh/patronus/patronus/branch/main/graph/badge.svg)](https://codecov.io/gh/patronus/patronus)
```

### Metrics

Track:
- **Build Success Rate**: >95%
- **Build Time**: <15 minutes for CI
- **Test Coverage**: >80%
- **Security Vulnerabilities**: 0 critical/high

### Notifications

Configure notifications in GitHub repository settings:
- Email on build failure
- Slack integration
- GitHub status checks on PRs

---

## Troubleshooting

### Build Failures

**Issue**: Clippy warnings fail build

```bash
# Fix locally first
cargo clippy --workspace --all-features --fix --allow-dirty

# Verify
cargo clippy --workspace --all-features -- -D warnings
```

**Issue**: Tests fail in CI but pass locally

```bash
# Use exact CI environment
docker run --rm -v $(pwd):/build -w /build rust:1.75-slim bash -c "
  apt-get update && apt-get install -y pkg-config libsqlite3-dev libssl-dev &&
  cargo test --workspace --all-features
"
```

**Issue**: Out of disk space

- GitHub Actions runners have ~14GB free space
- Clean up artifacts after builds
- Use `cargo clean` if needed

### Release Failures

**Issue**: Tag already exists

```bash
# Delete local tag
git tag -d v1.0.0

# Delete remote tag
git push origin :refs/tags/v1.0.0

# Recreate and push
git tag v1.0.0
git push origin v1.0.0
```

**Issue**: Docker build fails

```bash
# Test locally
docker build -t patronus-sdwan:test .

# Check logs
docker build --progress=plain -t patronus-sdwan:test .
```

---

## Best Practices

### Branch Strategy

```
main (protected)
  ├── develop
  │   ├── feature/new-feature
  │   ├── fix/bug-fix
  │   └── refactor/improvement
  └── hotfix/critical-fix
```

**Rules**:
- `main`: Stable, production-ready
- `develop`: Integration branch
- Feature branches: Merge to `develop` via PR
- Hotfixes: Branch from `main`, merge to both `main` and `develop`

### Pull Request Workflow

1. Create feature branch
2. Make changes
3. Run pre-commit checks
4. Push to GitHub
5. Create PR
6. CI runs automatically
7. Code review
8. Merge (squash and merge recommended)

### Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **Major** (1.0.0): Breaking changes
- **Minor** (1.1.0): New features, backward compatible
- **Patch** (1.0.1): Bug fixes

---

## Security

### Secrets Management

Required secrets in GitHub repository settings:

| Secret | Purpose |
|--------|---------|
| `GITHUB_TOKEN` | Automatic (provided by GitHub) |
| `CARGO_REGISTRY_TOKEN` | Publishing to crates.io |
| `DOCKER_USERNAME` | Docker Hub (if using) |
| `DOCKER_PASSWORD` | Docker Hub (if using) |
| `CODECOV_TOKEN` | Code coverage upload |

### Dependency Scanning

- **Dependabot**: Automatically opens PRs for dependency updates
- **cargo-audit**: Scans for known vulnerabilities (in CI)
- **cargo-deny**: Checks licenses and banned dependencies

**Configuration**: `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

---

## Future Enhancements

1. **Performance Benchmarks**: Track performance regressions
2. **E2E Tests**: Full end-to-end testing
3. **Canary Deployments**: Gradual rollout with monitoring
4. **Auto-rollback**: Automatic rollback on failure detection
5. **Multi-region Deployment**: Deploy to multiple regions
6. **Helm Charts**: Kubernetes packaging

---

**Document Version**: 1.0.0
**Last Updated**: 2025-10-11
**Maintainer**: DevOps Team
