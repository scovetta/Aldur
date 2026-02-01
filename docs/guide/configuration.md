# Configuration

Aldur can be configured using command-line options, configuration files, or environment variables.

## Configuration File

Create a configuration file to set default options:

```bash
# Export a template configuration
aldur export-config -o aldur.toml
```

### Configuration File Format

```toml
# aldur.toml

[analyze]
# Default output format
format = "sarif"

# Default security profile
profile = "default"

# Recurse into directories
recurse = true

# Minimum failure level to report
level = "warning"

# Number of threads (0 = auto)
threads = 0

[archives]
# Scan contents of archives
scan = true

# Scan nested archives
nested = true

# Maximum extraction depth
max_depth = 3

# Maximum uncompressed size in MB
max_size_mb = 10240

# Maximum entries to extract
max_entries = 100000

[symbols]
# Symbol path for PDB lookup
# Supports symbol servers: srv*C:\symbols*https://msdl.microsoft.com/download/symbols
sympath = ""

[rules]
# Rules to always include (overrides profile)
include = []

# Rules to always exclude (overrides profile)
exclude = []

# Path to custom profiles file
custom_profiles = ""
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ALDUR_SYMPATH` | Symbol path for PDB lookup |
| `ALDUR_PROFILE` | Default security profile |
| `ALDUR_THREADS` | Number of threads |

## Configuration Precedence

Configuration is applied in this order (later overrides earlier):

1. Built-in defaults
2. Configuration file (`aldur.toml`)
3. Environment variables
4. Command-line options

## Symbol Path Configuration

For Windows PDB analysis, configure the symbol path:

```bash
# Local symbols directory
aldur analyze --sympath "C:\symbols" binary.exe

# Microsoft symbol server
aldur analyze --sympath "srv*C:\symbols*https://msdl.microsoft.com/download/symbols" binary.exe

# Environment variable
export ALDUR_SYMPATH="srv*~/symbols*https://msdl.microsoft.com/download/symbols"
aldur analyze binary.exe
```

## Per-Project Configuration

Place an `aldur.toml` file in your project root:

```
myproject/
├── aldur.toml      # Project configuration
├── src/
├── build/
└── ...
```

Aldur automatically loads `aldur.toml` from the current directory.
