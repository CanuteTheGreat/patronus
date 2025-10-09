# Contributing to Patronus Firewall

Thank you for your interest in contributing to Patronus! This document provides guidelines and instructions for contributing to the project.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Review Process](#review-process)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. Please be respectful and constructive in all interactions.

### Our Standards

**Positive behavior includes:**
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards others

**Unacceptable behavior includes:**
- Harassment, trolling, or discriminatory language
- Personal attacks or insults
- Publishing others' private information
- Other unprofessional conduct

---

## Getting Started

### Prerequisites

Before contributing, ensure you have:

1. **Gentoo Linux** (recommended) or another Linux distribution
2. **Rust 1.70+** installed
3. **System dependencies:**
   ```bash
   # On Gentoo
   emerge -av dev-lang/rust dev-db/sqlite dev-util/pkgconf \
              net-libs/libnftnl net-libs/libmnl

   # On Debian/Ubuntu
   apt install build-essential rustc cargo pkg-config \
               libsqlite3-dev libnftnl-dev libmnl-dev
   ```
4. **Git** for version control
5. **Familiarity with Rust** (see [The Rust Book](https://doc.rust-lang.org/book/))

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/patronus.git
   cd patronus
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/CanuteTheGreat/patronus.git
   ```
4. Create a branch:
   ```bash
   git checkout -b feature/my-awesome-feature
   ```

---

## Development Environment

### Build the Project

```bash
# Build all crates
cargo build --workspace --all-features

# Build specific crate
cargo build -p patronus-core
```

### Run Tests

```bash
# Run all tests
cargo test --workspace --all-features

# Run tests for specific crate
cargo test -p patronus-core

# Run with verbose output
cargo test -- --nocapture
```

### Check Code Quality

```bash
# Run clippy (linter)
cargo clippy --workspace --all-features -- -D warnings

# Format code
cargo fmt --all

# Check formatting without modifying
cargo fmt --all -- --check
```

### Development Server

```bash
# Run web interface in development mode
cargo run --bin patronus-web

# With hot-reload (requires cargo-watch)
cargo install cargo-watch
cargo watch -x 'run --bin patronus-web'
```

---

## How to Contribute

### Types of Contributions

We welcome:
- 🐛 **Bug fixes** - Fix issues listed in GitHub Issues
- ✨ **New features** - Implement features from the roadmap
- 📚 **Documentation** - Improve or translate documentation
- 🧪 **Tests** - Add test coverage
- 🎨 **UI/UX improvements** - Enhance the web interface
- ⚡ **Performance optimizations** - Improve speed or memory usage
- 🔒 **Security improvements** - Harden security

### Finding Issues

- Check [GitHub Issues](https://github.com/CanuteTheGreat/patronus/issues)
- Look for issues labeled `good first issue` or `help wanted`
- Ask in [Discussions](https://github.com/CanuteTheGreat/patronus/discussions) if you need clarification

### Reporting Bugs

**Before submitting a bug report:**
1. Check if it's already reported in Issues
2. Ensure you're using the latest version
3. Verify the bug is reproducible

**When submitting a bug report, include:**
- Clear, descriptive title
- Steps to reproduce
- Expected vs. actual behavior
- Environment details (OS, Rust version, kernel version)
- Relevant logs or error messages
- Screenshots if applicable

**Template:**
```markdown
## Bug Description
Brief description of the bug.

## Steps to Reproduce
1. Go to '...'
2. Click on '...'
3. See error

## Expected Behavior
What you expected to happen.

## Actual Behavior
What actually happened.

## Environment
- OS: Gentoo Linux
- Kernel: 6.6.21
- Rust: 1.77.0
- Patronus: 0.1.0

## Logs
```
Paste relevant logs here
```

## Screenshots
If applicable, add screenshots.
```

### Requesting Features

**When requesting a feature:**
1. Check if it's already requested in Issues or Discussions
2. Explain the use case and benefits
3. Provide examples or mockups if applicable
4. Be open to feedback and alternative approaches

**Template:**
```markdown
## Feature Description
Brief description of the feature.

## Use Case
Why is this feature needed? What problem does it solve?

## Proposed Solution
How should this be implemented?

## Alternatives Considered
What other approaches did you consider?

## Additional Context
Any other relevant information.
```

---

## Coding Standards

### Rust Style Guide

Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/):

- Use `cargo fmt` to format code
- Maximum line length: 100 characters
- Use descriptive variable names
- Prefer explicit types for public APIs
- Add documentation comments (`///`) for public items

### Project Structure

```
patronus/
├── crates/
│   ├── patronus-core/          # Core firewall logic
│   ├── patronus-ebpf/          # eBPF/XDP programs
│   ├── patronus-nftables/      # Nftables integration
│   ├── patronus-vpn/           # VPN implementations
│   ├── patronus-monitoring/    # Metrics and monitoring
│   ├── patronus-ai/            # AI threat detection
│   ├── patronus-web/           # Web interface
│   ├── patronus-cli/           # CLI tools
│   ├── patronus-gitops/        # GitOps backend
│   ├── patronus-k8s/           # Kubernetes CNI
│   └── patronus-secrets/       # Secrets management
├── docs/                       # Documentation
├── gentoo-overlay/            # Gentoo ebuild
├── ansible-collection-patronus/ # Ansible collection
└── terraform-provider-patronus/ # Terraform provider
```

### Naming Conventions

- **Crates:** `patronus-{component}` (e.g., `patronus-core`)
- **Modules:** `snake_case` (e.g., `packet_filter`)
- **Types:** `PascalCase` (e.g., `FirewallRule`)
- **Functions:** `snake_case` (e.g., `apply_rule`)
- **Constants:** `SCREAMING_SNAKE_CASE` (e.g., `MAX_RULES`)
- **Lifetimes:** Single lowercase letter (e.g., `'a`, `'b`)

### Error Handling

- Use `Result<T, E>` for recoverable errors
- Use `panic!` only for unrecoverable errors
- Provide context with error messages
- Use `anyhow` for application code, `thiserror` for library code

**Example:**
```rust
use anyhow::{Context, Result};

fn apply_firewall_rule(rule: &FirewallRule) -> Result<()> {
    nftables::add_rule(rule)
        .context("Failed to apply firewall rule to nftables")?;
    Ok(())
}
```

### Async/Await

- Use `async/await` for I/O-bound operations
- Prefer Tokio runtime
- Use `tokio::spawn` for concurrent tasks
- Handle cancellation gracefully

### Security

- **Never log sensitive data** (passwords, keys, tokens)
- **Validate all user input** before processing
- **Use constant-time comparison** for secrets
- **Follow principle of least privilege**
- **Document security implications** in code comments

**Example:**
```rust
use subtle::ConstantTimeEq;

fn verify_password(input: &str, hash: &str) -> bool {
    // SECURITY: Use constant-time comparison to prevent timing attacks
    argon2::verify_encoded(hash, input.as_bytes())
        .unwrap_or(false)
}
```

---

## Testing

### Test Coverage

Aim for:
- **Unit tests** for core logic (70%+ coverage)
- **Integration tests** for component interactions
- **End-to-end tests** for critical workflows
- **Performance benchmarks** for hot paths

### Writing Tests

**Unit tests:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_parsing() {
        let rule = FirewallRule::parse("allow tcp 80").unwrap();
        assert_eq!(rule.action, Action::Accept);
        assert_eq!(rule.protocol, Some(Protocol::Tcp));
        assert_eq!(rule.dport, Some(80));
    }

    #[tokio::test]
    async fn test_async_operation() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

**Integration tests:**
```rust
// tests/integration_test.rs
use patronus_core::Firewall;

#[test]
fn test_firewall_integration() {
    let mut firewall = Firewall::new();
    firewall.add_rule(/* ... */);
    firewall.apply().unwrap();
    // Verify rule was applied
}
```

### Running Specific Tests

```bash
# Run specific test
cargo test test_rule_parsing

# Run tests matching pattern
cargo test rule

# Run tests in specific crate
cargo test -p patronus-core

# Run ignored tests
cargo test -- --ignored

# Run benchmarks
cargo bench
```

---

## Documentation

### Code Documentation

- **All public items** must have doc comments (`///`)
- **Include examples** in doc comments
- **Document panics, errors, and safety** requirements
- **Use proper Markdown** formatting

**Example:**
```rust
/// Applies a firewall rule to the nftables backend.
///
/// # Arguments
///
/// * `rule` - The firewall rule to apply
///
/// # Returns
///
/// Returns `Ok(())` if the rule was applied successfully,
/// or an error if nftables rejected the rule.
///
/// # Errors
///
/// This function will return an error if:
/// - The rule syntax is invalid
/// - nftables is not running
/// - Permission denied (requires root)
///
/// # Examples
///
/// ```
/// use patronus_core::{FirewallRule, apply_rule};
///
/// let rule = FirewallRule::allow_tcp(80);
/// apply_rule(&rule)?;
/// ```
pub fn apply_rule(rule: &FirewallRule) -> Result<()> {
    // Implementation
}
```

### User Documentation

- Update relevant `.md` files in root or `docs/`
- Follow existing documentation style
- Include code examples and screenshots
- Keep documentation in sync with code

### Documentation Standards

- Use clear, concise language
- Avoid jargon unless necessary
- Provide real-world examples
- Include troubleshooting sections
- Update table of contents if adding new sections

---

## Submitting Changes

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring (no feature/bug change)
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks (dependencies, build, etc.)

**Example:**
```
feat(vpn): add WireGuard QR code generation

Implement QR code generation for WireGuard mobile clients.
This allows users to easily set up WireGuard on mobile devices
by scanning a QR code from the web interface.

Closes #123
```

### Pull Request Process

1. **Update your fork:**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Ensure tests pass:**
   ```bash
   cargo test --workspace --all-features
   cargo clippy --workspace --all-features -- -D warnings
   cargo fmt --all -- --check
   ```

3. **Update documentation** if needed

4. **Push to your fork:**
   ```bash
   git push origin feature/my-awesome-feature
   ```

5. **Create Pull Request** on GitHub

6. **Fill out the PR template:**
   ```markdown
   ## Description
   Brief description of changes.

   ## Type of Change
   - [ ] Bug fix (non-breaking change fixing an issue)
   - [ ] New feature (non-breaking change adding functionality)
   - [ ] Breaking change (fix or feature causing existing functionality to break)
   - [ ] Documentation update

   ## How Has This Been Tested?
   Describe the tests you ran.

   ## Checklist
   - [ ] My code follows the style guidelines
   - [ ] I have performed a self-review
   - [ ] I have commented my code where necessary
   - [ ] I have updated the documentation
   - [ ] My changes generate no new warnings
   - [ ] I have added tests that prove my fix/feature works
   - [ ] New and existing unit tests pass locally
   - [ ] Any dependent changes have been merged

   ## Related Issues
   Closes #123
   ```

---

## Review Process

### What to Expect

1. **Automated checks** will run (CI/CD)
2. **Maintainers will review** your code
3. **Feedback may be provided** - address it by pushing new commits
4. **Once approved**, a maintainer will merge your PR

### Review Criteria

Reviewers will check for:
- ✅ Code quality and style
- ✅ Test coverage
- ✅ Documentation completeness
- ✅ Security implications
- ✅ Performance impact
- ✅ Breaking changes (if any)
- ✅ Commit message quality

### Addressing Feedback

- Be responsive to reviewer comments
- Ask questions if feedback is unclear
- Push additional commits (don't force-push during review)
- Mark conversations as resolved when addressed

---

## Project-Specific Guidelines

### eBPF Development

When working on eBPF code:
- Test on Linux kernel 5.10+
- Use `bpf_printk` for debugging
- Keep eBPF programs small (stack limit: 512 bytes)
- Verify with `bpftool prog show`
- Follow eBPF verifier requirements

### Web UI Development

When working on the web interface:
- Follow progressive disclosure pattern
- Maintain responsive design (mobile/tablet/desktop)
- Support dark/light mode
- Use semantic HTML
- Avoid JavaScript frameworks (vanilla JS only)
- Test in multiple browsers

### Security-Sensitive Code

For security-critical changes:
- Request security review explicitly
- Include threat model in PR description
- Add security tests
- Document security assumptions
- Consider fuzzing if applicable

---

## Community

### Getting Help

- **Documentation:** Check [docs/](docs/) first
- **GitHub Discussions:** Ask questions and discuss ideas
- **GitHub Issues:** Report bugs or request features
- **Code Review:** Learn by reviewing others' PRs

### Recognition

Contributors will be:
- Listed in `CONTRIBUTORS.md`
- Credited in release notes
- Co-authored in commits (if applicable)

---

## License

By contributing to Patronus, you agree that your contributions will be licensed under the **GPL-3.0-or-later** license.

All contributions must be original work or properly attributed if derived from other sources.

---

## Questions?

If you have questions not covered here:
1. Check [GitHub Discussions](https://github.com/CanuteTheGreat/patronus/discussions)
2. Ask in a GitHub Issue
3. Reach out to maintainers

**Thank you for contributing to Patronus Firewall!** 🚀

---

**Co-Authored-By:** Claude <noreply@anthropic.com>
**Date:** 2025-10-08
**License:** GPL-3.0-or-later
