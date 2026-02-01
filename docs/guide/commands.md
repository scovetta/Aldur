# Command Reference

Aldur provides several commands for analyzing binaries and managing configurations.

## Main Commands

```
aldur [OPTIONS] <COMMAND>

Commands:
  analyze        Analyze binary files for security issues
  export-rules   Export rules metadata as JSON
  export-config  Export configuration template
  dump           Dump binary information (headers, sections, etc.)
  list-profiles  List available security profiles
  help           Print help information

Options:
  -v, --verbose  Enable verbose output
  -h, --help     Print help
  -V, --version  Print version
```

## analyze

Analyze binary files for security vulnerabilities and missing hardening features.

```bash
aldur analyze [OPTIONS] <TARGETS>...
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<TARGETS>...` | Files, directories, or glob patterns to analyze |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <FILE>` | Output file path for SARIF results | stdout |
| `-f, --format <FORMAT>` | Output format: `sarif`, `text`, `text-color` | `text` |
| `-P, --profile <PROFILE>` | Security profile to use | `default` |
| `-r, --recurse` | Recurse into subdirectories | false |
| `-c, --config <FILE>` | Path to configuration file | - |
| `-q, --quiet` | Suppress console output | false |
| `-s, --statistics` | Generate timing statistics | false |
| `--sympath <PATH>` | Symbol path for PDB lookup | - |
| `--level <LEVEL>` | Minimum failure level (error, warning, note) | all |
| `--baseline <FILE>` | Baseline SARIF file for comparison | - |
| `--save-baseline <FILE>` | Save current results as baseline | - |
| `--summary` | Show multi-target summary report | false |
| `--max-file-size-kb <KB>` | Maximum file size (0 = unlimited) | 0 |
| `--threads <N>` | Number of threads (0 = auto) | 0 |
| `--scan-archives` | Scan contents of archives | true |
| `--scan-nested-archives` | Scan nested archives | true |
| `--max-archive-depth <N>` | Maximum archive extraction depth | 3 |
| `--max-archive-size-mb <MB>` | Maximum uncompressed size | 10240 |
| `--max-archive-entries <N>` | Maximum entries to extract | 100000 |
| `--include <RULES>` | Rule IDs to include (comma-separated) | - |
| `--exclude <RULES>` | Rule IDs to exclude (comma-separated) | - |
| `--custom-profiles <PATH>` | Path to custom profiles file | - |

### Examples

```bash
# Analyze a single binary
aldur analyze /path/to/binary

# Analyze directory recursively with SARIF output
aldur analyze -r -o results.sarif /path/to/binaries/

# Use strict profile
aldur analyze --profile strict /path/to/binary

# Analyze an APK file
aldur analyze app.apk

# Show only errors
aldur analyze --level error /path/to/binary
```

## export-rules

Export all security rules metadata as JSON.

```bash
aldur export-rules [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `-o, --output <FILE>` | Output file (default: stdout) |

### Example

```bash
aldur export-rules -o rules.json
```

## export-config

Export a configuration template.

```bash
aldur export-config [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `-o, --output <FILE>` | Output file (default: stdout) |

## dump

Dump binary information for debugging and analysis.

```bash
aldur dump [OPTIONS] <FILE>
```

### Options

| Option | Description |
|--------|-------------|
| `--headers` | Show file headers |
| `--sections` | Show section information |
| `--symbols` | Show symbol table |
| `--imports` | Show import table |
| `--exports` | Show export table |

## list-profiles

List all available security profiles.

```bash
aldur list-profiles
```
