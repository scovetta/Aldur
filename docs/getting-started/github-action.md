# GitHub Action

Aldur is available as a GitHub Action for easy integration into CI/CD pipelines.

## Basic Usage

```yaml
- name: Run aldur security scan
  uses: scovetta/aldur@v1
  with:
    targets: 'path/to/binaries'
```

## Full Example

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 # v6.0.1
        with:
          persist-credentials: false

      - name: Build project
        run: cargo build --release

      - name: Run aldur
        uses: scovetta/aldur@v1
        with:
          targets: 'target/release'
          format: sarif
          output: results.sarif
          recurse: true
          upload-sarif: true
          fail-on-error: true
```

## Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `targets` | Files, directories, or glob patterns to analyze (required) | - |
| `output` | Output file path for results | `aldur-results.sarif` |
| `format` | Output format: `sarif`, `text`, `text-color` | `sarif` |
| `recurse` | Recurse into subdirectories | `true` |
| `show-passed` | Include passing rules in output | `false` |
| `level` | Minimum failure level (`error`, `warning`, `note`) | - |
| `profile` | Security profile to use | `default` |
| `scan-archives` | Scan binaries inside archives | `true` |
| `version` | aldur version to use | `latest` |
| `upload-sarif` | Upload SARIF results to GitHub Code Scanning | `true` |
| `fail-on-error` | Fail the workflow if errors are found | `true` |

## Action Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `errors` | Number of errors found |
| `warnings` | Number of warnings found |
| `files-analyzed` | Number of files analyzed |

## Examples

### Scan Android APK

```yaml
- name: Scan APK
  uses: scovetta/aldur@v1
  with:
    targets: 'app/build/outputs/apk/release/*.apk'
    profile: android
```

### Scan Multiple Directories

```yaml
- name: Scan binaries
  uses: scovetta/aldur@v1
  with:
    targets: |
      build/bin/
      build/lib/
      third_party/
```

### Strict Security Scan

```yaml
- name: Strict security scan
  uses: scovetta/aldur@v1
  with:
    targets: 'build/'
    profile: strict
    fail-on-error: true
```

### Use Baseline for PR Checks

```yaml
- name: Download baseline
  uses: actions/download-artifact@v4
  with:
    name: security-baseline
    path: .

- name: Scan with baseline
  uses: scovetta/aldur@v1
  with:
    targets: 'build/'
    baseline: baseline.sarif
```

## Viewing Results

When `upload-sarif: true` (default), results appear in the Security tab of your repository under "Code scanning alerts".

Results can also be viewed in pull request annotations when the workflow runs on PRs.
