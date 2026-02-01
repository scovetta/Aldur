# CI/CD Integration

Aldur integrates with popular CI/CD platforms to automate binary security scanning.

## GitHub Actions

### Using the Official Action

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
      - uses: actions/checkout@v4

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

### Using the Binary Directly

```yaml
- name: Install aldur
  run: |
    curl -LO https://github.com/scovetta/aldur/releases/latest/download/aldur-x86_64-unknown-linux-gnu.tar.gz
    tar -xzf aldur-x86_64-unknown-linux-gnu.tar.gz
    chmod +x aldur

- name: Run security scan
  run: ./aldur analyze -o results.sarif -r ./build/

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: CmdLine@2
    displayName: 'Install aldur'
    inputs:
      script: |
        curl -LO https://github.com/scovetta/aldur/releases/latest/download/aldur-x86_64-unknown-linux-gnu.tar.gz
        tar -xzf aldur-x86_64-unknown-linux-gnu.tar.gz

  - task: CmdLine@2
    displayName: 'Run Binary Security Analysis'
    inputs:
      script: |
        ./aldur analyze -o $(Build.ArtifactStagingDirectory)/results.sarif $(Build.BinariesDirectory)

  - task: PublishBuildArtifacts@1
    inputs:
      pathtoPublish: '$(Build.ArtifactStagingDirectory)/results.sarif'
      artifactName: 'SecurityResults'
```

## GitLab CI

```yaml
security-scan:
  stage: test
  image: ubuntu:latest
  script:
    - apt-get update && apt-get install -y curl
    - curl -LO https://github.com/scovetta/aldur/releases/latest/download/aldur-x86_64-unknown-linux-gnu.tar.gz
    - tar -xzf aldur-x86_64-unknown-linux-gnu.tar.gz
    - ./aldur analyze -o results.sarif -r ./build/
  artifacts:
    reports:
      sast: results.sarif
```

## Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    curl -LO https://github.com/scovetta/aldur/releases/latest/download/aldur-x86_64-unknown-linux-gnu.tar.gz
                    tar -xzf aldur-x86_64-unknown-linux-gnu.tar.gz
                    ./aldur analyze -o results.sarif -r ./build/
                '''
                recordIssues(tools: [sarif(pattern: 'results.sarif')])
            }
        }
    }
}
```

## CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install aldur
          command: |
            curl -LO https://github.com/scovetta/aldur/releases/latest/download/aldur-x86_64-unknown-linux-gnu.tar.gz
            tar -xzf aldur-x86_64-unknown-linux-gnu.tar.gz
      - run:
          name: Run security scan
          command: ./aldur analyze -o results.sarif -r ./build/
      - store_artifacts:
          path: results.sarif
```

## Fail on Security Issues

Configure the pipeline to fail when security issues are found:

```bash
# Fail on any error-level findings
aldur analyze --level error --fail-on-error ./build/

# Exit code:
# 0 = no issues found
# 1 = issues found or analysis error
```

## Baseline Comparison

Compare against a baseline to only report new issues:

```bash
# Save current results as baseline
aldur analyze --save-baseline baseline.sarif ./build/

# Compare future runs against baseline
aldur analyze --baseline baseline.sarif ./build/
```
