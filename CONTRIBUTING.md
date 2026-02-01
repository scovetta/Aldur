# Contributing to Aldur

Thank you for your interest in contributing to Aldur! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project follows the [OpenSSF Code of Conduct](https://openssf.org/community/code-of-conduct/). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- **Rust 1.70 or later** - Install from [rustup.rs](https://rustup.rs/)
- **Git** - For version control

### Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/scovetta/aldur
cd aldur/src

# Build in debug mode
cargo build

# Run tests
cargo test

# Build release binary
cargo build --release
```

### Project Architecture

Aldur is organized as a Rust workspace with modular crates:

```
src/
├── aldur/          # CLI application
├── aldur-core/     # Core types, traits, and analysis context
├── aldur-parsers/  # Binary parsers (PE, ELF, Mach-O, PDB, DWARF)
├── aldur-rules/    # Security rule implementations
└── aldur-sarif/    # SARIF report generation
```

### Key Dependencies

- **[goblin](https://github.com/m4b/goblin)**: PE, ELF, and Mach-O parsing
- **[pdb](https://github.com/willglynn/pdb)**: Cross-platform PDB parsing
- **[gimli](https://github.com/gimli-rs/gimli)**: DWARF debug info parsing
- **[clap](https://github.com/clap-rs/clap)**: Command-line argument parsing

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/scovetta/aldur/issues) to avoid duplicates
2. Use the bug report template
3. Include:
   - Aldur version (`aldur --version`)
   - Operating system and architecture
   - Steps to reproduce
   - Expected vs actual behavior
   - Sample binary (if possible and not confidential)

### Suggesting Features

1. Check [existing issues](https://github.com/scovetta/aldur/issues) for similar requests
2. Use the feature request template
3. Describe the use case and expected behavior

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests (`cargo test`)
5. Run clippy (`cargo clippy`)
6. Format code (`cargo fmt`)
7. Commit with a descriptive message
8. Push to your fork
9. Open a pull request

## Adding New Rules

Security rules are the core of Aldur. Here's how to add a new rule:

### 1. Choose a Rule ID

- **AD2xxx**: PE (Windows) rules
- **AD3xxx**: ELF (Linux/Unix) rules
- **AD5xxx**: Mach-O (macOS) rules
- **AD4xxx**: Cross-platform reporting rules
- **AD6xxx**: Performance/optimization rules

### 2. Create the Rule File

Create a new file in `aldur-rules/src/{pe,elf,macho}/`:

```rust
//! AD3099: MyNewRule
//!
//! Description of what this rule checks.

use aldur_core::{
    AnalysisApplicability, AnalysisContext, BinaryFormat, FailureLevel,
    Rule, RuleCategory, RuleDescriptor,
};

use crate::rule_ids::AD3099;

pub struct MyNewRule {
    descriptor: RuleDescriptor,
}

impl MyNewRule {
    pub fn new() -> Self {
        let descriptor = RuleDescriptor::new(AD3099, "MyNewRule")
            .with_category(RuleCategory::Security)
            .with_short_description("Brief description of the rule.")
            .with_full_description(
                "Detailed explanation of what this rule checks and why it matters."
            )
            .with_default_level(FailureLevel::Warning)
            .with_message("Pass", "'{0}' passes this check.")
            .with_message("Fail", "'{0}' fails this check. Here's how to fix it.");

        Self { descriptor }
    }
}

impl Default for MyNewRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MyNewRule {
    fn descriptor(&self) -> &RuleDescriptor {
        &self.descriptor
    }

    fn can_analyze(&self, context: &AnalysisContext) -> (AnalysisApplicability, Option<String>) {
        // Check if the rule applies to this binary
        let Some(binary) = context.binary() else {
            return (
                AnalysisApplicability::NotApplicableDueToMissingTarget,
                Some("Binary not loaded".to_string()),
            );
        };

        if binary.format() != BinaryFormat::ELF {
            return (
                AnalysisApplicability::NotApplicableToSpecifiedTarget,
                Some("Not an ELF binary".to_string()),
            );
        }

        (AnalysisApplicability::ApplicableToSpecifiedTarget, None)
    }

    fn analyze(&self, context: &mut AnalysisContext) {
        let file_name = context.file_name();

        // Your analysis logic here
        let passes = true; // Replace with actual check

        if passes {
            self.log_pass(context, "Pass", &[&file_name]);
        } else {
            self.log_fail(context, FailureLevel::Warning, "Fail", &[&file_name]);
        }
    }
}
```

### 3. Register the Rule

Add the rule ID to `aldur-rules/src/rule_ids.rs`:

```rust
pub const AD3099: &str = "AD3099"; // MyNewRule
```

Add the module and export in `aldur-rules/src/{pe,elf,macho}/mod.rs`:

```rust
mod ad3099_my_new_rule;
pub use ad3099_my_new_rule::MyNewRule;

// In all_rules() function:
Box::new(MyNewRule::new()),
```

### 4. Add Documentation

Create `docs/rules/AD3099.MyNewRule.md` with:

- Summary table (ID, Name, Category, Severity, Applies to)
- Description of what the rule checks
- Why it matters for security
- How to fix failures
- When to suppress
- References

### 5. Write Tests

Add tests in `aldur-rules/tests/{pe,elf,macho}_rules_tests.rs`:

```rust
mod ad3099_my_new_rule_tests {
    use super::*;
    use aldur_rules::elf::MyNewRule;

    #[test]
    fn test_rule_descriptor() {
        let rule = MyNewRule::new();
        verify_rule_descriptor(&rule, "AD3099", "MyNewRule");
    }

    #[test]
    fn test_default_level() {
        let rule = MyNewRule::new();
        assert_eq!(rule.descriptor().default_level, FailureLevel::Warning);
    }
}
```

## Cross-Compilation

To build for other platforms from Linux:

```bash
# Install targets
rustup target add x86_64-unknown-linux-musl x86_64-pc-windows-gnu aarch64-unknown-linux-gnu

# Install cross-compilation toolchains
sudo apt-get install gcc-mingw-w64-x86-64 gcc-aarch64-linux-gnu musl-tools

# Build for Windows
cargo build --release --target x86_64-pc-windows-gnu

# Build static Linux binary (musl)
cargo build --release --target x86_64-unknown-linux-musl

# Build for Linux ARM64
cargo build --release --target aarch64-unknown-linux-gnu
```

## Style Guidelines

### Rust Code

- Follow standard Rust conventions
- Run `cargo fmt` before committing
- Run `cargo clippy` and address warnings
- Write documentation comments for public APIs
- Keep functions focused and testable

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Reference issues when applicable (`Fixes #123`)

### Documentation

- Use clear, concise language
- Include code examples where helpful
- Keep the README focused on users, not developers
- Document rule behavior in the `docs/` folder

## Testing

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test --package aldur-rules

# Run a specific test
cargo test --package aldur-rules ad3001

# Run with verbose output
cargo test -- --nocapture
```

## Release Process

Releases are managed by maintainers. The process:

1. Update version in `Cargo.toml` files
2. Update CHANGELOG.md
3. Create a git tag
4. GitHub Actions builds and publishes releases

## Questions?

- Open a [discussion](https://github.com/scovetta/aldur/discussions) for questions
- Check existing issues before opening new ones
- Tag issues appropriately

Thank you for contributing to Aldur!
