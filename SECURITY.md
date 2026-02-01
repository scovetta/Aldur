# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Aldur, please report it privately by creating a [private vulnerability report](https://github.com/scovetta/aldur/security/advisories/new).

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 96 hours
- **Resolution timeline**: Depends on severity, typically within 90 days

## Scope

### In Scope

Security issues in:

- Aldur CLI application
- Archive extraction (zip bombs, path traversal, etc.)
- Binary parsing (malformed inputs causing crashes or code execution)
- SARIF output generation
- PDB/DWARF parsing
- GitHub Action

If you use AI to identify security issues, you are responsible for ensuring it's
valid before reporting.

### Out of Scope

- Security issues in analyzed binaries (that's what Aldur is designed to find!)
- Issues in third-party dependencies (please report to upstream maintainers)
- Denial of service through very large files (use `--max-file-size-kb`)
- Issues requiring physical access to the machine

## Security Features

Aldur includes several security features:

### Archive Scanning Safeguards

When scanning archives (ZIP, TAR, etc.), Aldur implements:

- **Depth limiting**: Prevents zip-bomb attacks via nested archives (default: 3 levels)
- **Size limiting**: Caps total uncompressed size (default: 10GB)
- **Entry limiting**: Caps number of files extracted (default: 100,000)
- **Path sanitization**: Prevents path traversal attacks (e.g., `../../../etc/passwd`)
- **Automatic cleanup**: Temporary files are deleted after scanning

### Binary Parsing

- All binary parsing uses memory-safe Rust code
- Input validation before processing
- Graceful handling of malformed binaries

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.0   | :white_check_mark: |

We provide security updates for the latest release. Upgrade to receive security fixes.

## Security Best Practices for Users

### Running Aldur Safely

1. **Use official releases**: Download from [GitHub Releases](https://github.com/scovetta/aldur/releases), use the official GitHub Action, or build from source.
2. **Verify checksums**: Compare SHA256 hashes of downloaded binaries
3. **Limit archive extraction**: Use `--max-archive-size-mb` and `--max-archive-depth` when scanning untrusted archives
4. **Run with least privilege**: Aldur doesn't require elevated permissions

### CI/CD Integration

1. **Pin versions**: Use specific versions in GitHub Actions (`uses: scovetta/aldur@v1.2.3` or pin to a hash)
2. **Review SARIF output**: Before uploading to security dashboards
3. **Use baselines**: Track security posture over time with `--baseline`

## Acknowledgments

We appreciate security researchers who help improve to Aldur. With permission, we'll acknowledge reporters in release notes.

