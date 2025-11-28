# Shai-Hulud V2 Attack Checker

A fast vulnerability scanner that detects npm packages compromised in the Shai-Hulud V2 supply chain attack.

## Overview

This tool analyzes `package-lock.json` files to identify potentially compromised packages through two detection methods:

1. **Known Vulnerabilities** - Checks against a curated list of confirmed compromised packages
2. **Temporal Analysis** - Identifies packages published or updated during the attack window (Nov 24, 2025 onwards) using `npm view` metadata

## About the Attack

The Shai-Hulud V2 attack used stolen npm and GitHub tokens to republish legitimate packages with malicious code injected into install scripts (preinstall, postinstall hooks). When these packages are installed, malicious scripts execute automatically, exfiltrating secrets, tokens, and sensitive information from local machines and CI/CD environments.

**Attack Window:** Nov 24, 2025 - Present

Special thanks to [Wiz Research](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/shai-hulud-2-packages.csv) for documenting this vulnerability.

## Installation

### Pre-built Binaries

Download pre-built binaries for your platform from [GitHub Releases](https://github.com/ficemu5/shai_hulud_v2_checker/releases):

- macOS ARM64
- Linux x64
- Windows x64

### Build from Source

**Prerequisites:** Rust toolchain and npm installed

```bash
cargo build --release
```

Binary location: `target/release/shai_hulud_v2_checker`

## Usage

```bash
# Scan package-lock.json in current directory
shai_hulud_v2_checker

# Scan a specific lock file
shai_hulud_v2_checker -f /path/to/package-lock.json

# Use custom number of threads (default: 5)
shai_hulud_v2_checker -t 10
```

### Options

- `-f, --json-lock-file <PATH>` - Path to package-lock.json file (defaults to current directory)
- `-t, --threads-num <NUM>` - Number of threads for npm view commands (default: 5)
- `-h, --help` - Print help information
- `-V, --version` - Print version information

## Response Steps

### If Vulnerabilities Are Detected

1. **Rotate All Credentials** - Immediately rotate tokens and secrets that were accessible on affected systems:
   - GitHub personal access tokens
   - npm tokens
   - Cloud provider credentials (AWS, GCP, Azure)
   - CI/CD pipeline secrets and service accounts

2. **Clean and Reinstall**

   ```bash
   npm cache clean --force
   rm -rf node_modules
   npm install
   ```

3. **Monitor for Suspicious Activity** - Check logs and audit trails for:
   - Unauthorized access to repositories
   - Unexpected package publishes
   - Unusual API calls

4. **No Lock File?** - If you don't use `package-lock.json`:
   - You are at high risk if packages were installed during the attack window
   - Generate a lock file immediately: `npm install --package-lock-only`
   - Pin all package versions to dates before Nov 24, 2025
   - Run this tool to verify your dependency tree

### Prevention

- **Use Lock Files** - Always commit `package-lock.json` to version control
- **Audit Dependencies** - Regularly review and remove unused packages
- **Disable Install Scripts in CI/CD**

  ```bash
  npm config set ignore-scripts true
  ```
