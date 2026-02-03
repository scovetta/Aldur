# Installation

Aldur is available as pre-built binaries for all major platforms, or you can build from source.

## Pre-built Binaries

Download the latest release for your platform:

=== "Linux"

    **x86_64 (glibc)**
    ```bash
    curl -LO https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-x86_64-unknown-linux-gnu.tar.gz
    tar -xzf aldur-0.1.1-x86_64-unknown-linux-gnu.tar.gz
    sudo mv aldur /usr/local/bin/
    ```

    **x86_64 (musl - static binary)**
    ```bash
    curl -LO https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-x86_64-unknown-linux-musl.tar.gz
    tar -xzf aldur-0.1.1-x86_64-unknown-linux-musl.tar.gz
    sudo mv aldur /usr/local/bin/
    ```

    **ARM64**
    ```bash
    curl -LO https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-aarch64-unknown-linux-gnu.tar.gz
    tar -xzf aldur-0.1.1-aarch64-unknown-linux-gnu.tar.gz
    sudo mv aldur /usr/local/bin/
    ```

=== "macOS"

    **Intel (x86_64)**
    ```bash
    curl -LO https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-x86_64-apple-darwin.tar.gz
    tar -xzf aldur-0.1.1-x86_64-apple-darwin.tar.gz
    sudo mv aldur /usr/local/bin/
    ```

    **Apple Silicon (ARM64)**
    ```bash
    curl -LO https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-aarch64-apple-darwin.tar.gz
    tar -xzf aldur-0.1.1-aarch64-apple-darwin.tar.gz
    sudo mv aldur /usr/local/bin/
    ```

=== "Windows"

    **x86_64**
    ```powershell
    Invoke-WebRequest -Uri "https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-x86_64-pc-windows-msvc.zip" -OutFile "aldur.zip"
    Expand-Archive aldur.zip -DestinationPath C:\Tools\aldur
    # Add to PATH
    $env:PATH += ";C:\Tools\aldur"
    ```

    **ARM64**
    ```powershell
    Invoke-WebRequest -Uri "https://github.com/scovetta/Aldur/releases/download/v0.1.1/aldur-0.1.1-aarch64-pc-windows-msvc.zip" -OutFile "aldur.zip"
    Expand-Archive aldur.zip -DestinationPath C:\Tools\aldur
    ```

## Build from Source

### Requirements

- Rust 1.70 or later
- Git

### Build Steps

```bash
# Clone the repository
git clone https://github.com/scovetta/aldur
cd aldur/src

# Build release binary
cargo build --release

# The binary is at target/release/aldur
./target/release/aldur --version
```

### Install with Cargo

```bash
cargo install --git https://github.com/scovetta/aldur aldur
```

## Verify Installation

After installation, verify aldur is working:

```bash
aldur --version
# aldur 0.1.0

# Analyze a test binary
aldur analyze /bin/ls
```

## Next Steps

- [Quick Start Guide](quickstart.md) - Learn the basics
- [Verify Release Integrity](../supply-chain/verification.md) - Verify checksums and signatures
