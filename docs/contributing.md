# Contributing to Aldur

Thank you for your interest in contributing! This guide covers how to get started, submit changes, and add new security rules.

## Code of Conduct

This project follows the [OpenSSF Code of Conduct](https://openssf.org/community/code-of-conduct/). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- **Rust 1.70 or later** - Install from [rustup.rs](https://rustup.rs/)
- **Git** - For version control

### Setting Up

```bash
# Clone the repository
git clone https://github.com/scovetta/Aldur
cd Aldur/src

# Build in debug mode
cargo build

# Run tests
cargo test

# Build release binary
cargo build --release
```

## Project Structure

Aldur is organized as a Rust workspace:

```
src/
├── aldur/          # CLI application
├── aldur-core/     # Core types, traits, and analysis context
├── aldur-parsers/  # Binary parsers (PE, ELF, Mach-O, PDB, DWARF)
├── aldur-rules/    # Security rule implementations
└── aldur-sarif/    # SARIF report generation
```

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| [goblin](https://github.com/m4b/goblin) | PE, ELF, and Mach-O parsing |
| [pdb](https://github.com/willglynn/pdb) | Cross-platform PDB parsing |
| [gimli](https://github.com/gimli-rs/gimli) | DWARF debug info parsing |
| [clap](https://github.com/clap-rs/clap) | Command-line argument parsing |

## How to Contribute

### Reporting Issues

1. Check [existing issues](https://github.com/scovetta/Aldur/issues) first
2. Include Aldur version (`aldur --version`)
3. Include OS and architecture
4. Provide reproduction steps

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test`
5. Run clippy: `cargo clippy`
6. Format code: `cargo fmt`
7. Open a pull request

## Adding New Rules

### Rule ID Conventions

| Series | Platform |
|--------|----------|
| AD2xxx | PE (Windows) |
| AD3xxx | ELF (Linux/Unix) |
| AD5xxx | Mach-O (macOS) |
| AD4xxx | Cross-platform reporting |
| AD6xxx | Performance/optimization |

### Creating a Rule

1. Create the rule file in `aldur-rules/src/{pe,elf,macho}/`
2. Implement the `Rule` trait
3. Register the rule in the module
4. Add documentation in `docs/`
5. Add tests

### Rule Template

```rust
use crate::{Rule, RuleResult, Severity};

pub struct MyNewRule;

impl Rule for MyNewRule {
    fn id(&self) -> &'static str {
        "AD2xxx"
    }

    fn name(&self) -> &'static str {
        "MyNewRule"
    }

    fn description(&self) -> &'static str {
        "Brief description of what this rule checks"
    }

    fn check(&self, context: &AnalysisContext) -> RuleResult {
        // Implementation
    }
}
```

### Documentation Requirements

Every rule needs a documentation file in `docs/` with:

- **Description**: What the rule checks and why
- **Resolution**: How to fix violations
- **Performance**: Runtime characteristics

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test rule_name

# Run with logging
RUST_LOG=debug cargo test
```

## Code Style

- Follow Rust conventions
- Use `cargo fmt` for formatting
- Address all `cargo clippy` warnings
- Document public APIs

## Related

- [Configuration Guide](guide/configuration.md)
- [Security Rules](rules/index.md)
- [GitHub Repository](https://github.com/scovetta/Aldur)
