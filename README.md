<div align="center">

<img src="images/icon.png" alt="GlassWorm Scanner Logo" width="200" />

# GlassWorm Scanner

**A high-precision security suite and automated remediation toolkit for the GlassWorm developer supply-chain malware campaign.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-Bash%20%7C%20Python%20%7C%20Perl-4EAA25.svg)]()
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-lightgrey.svg)]()
[![Threat Intel](https://img.shields.io/badge/Threat%20Intel-Extensions%20%2B%20Packages%20%2B%20Secrets-red.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/westackai/glassworm-scanner/pulls)

[Overview](#overview) • [Installation](#installation--prerequisites) • [Tools & Usage](#tools--usage) • [Threat Intel & IoCs](#threat-intelligence--iocs) • [Incident Response](#incident-response) • [CI/CD](#cicd-pipeline-integration) • [Contributing](#contributing) • [References](#threat-intelligence-references--acknowledgments) • [License](#license)

---

</div>

## Overview

**GlassWorm** is a sophisticated developer supply-chain malware campaign that propagates primarily through compromised Visual Studio Code and OpenVSX extensions. It infects repositories and developer workstations using:
- **Invisible Unicode variation selectors** (`U+FE00`–`U+FE0F`, `U+E0100`–`U+E01EF`) and **200+ space off-screen padding** in JS/TS configs.
- **Masqueraded font files** (e.g. `public/fonts/fa-solid-400.woff2` containing obfuscated Node.js scripts).
- **Automated IDE execution** via `.vscode/tasks.json` (`folderOpen`) and `.vscode/settings.json` prompt bypasses.
- **Blockchain dead-drop C2 resolvers** (Ethereum / Solana transaction metadata) and Git commit author spoofing.
- **Secondary malware loaders** distributed through poisoned npm and PyPI packages.

This toolkit provides **five focused, zero-trust tools** to detect, audit, and clean infections across your workstations, repositories, and GitHub organizations:

| Tool | Purpose | Primary Scope |
| :--- | :--- | :--- |
| **[`check-extensions.sh`](#1-check-extensionssh--ide-extension-audit)** | Audits installed IDE extensions against 418+ malicious IDs + deep invisible Unicode heuristics. | VS Code, Cursor, Windsurf, VSCodium |
| **[`scan-local.sh`](#2-scan-localsh--local-git--filesystem-scanner)** | 100% offline scanner for local clones, branch tips, commit history, and package dependencies. | Local Git repos & directories |
| **[`scan-github.sh`](#3-scan-githubsh--remote-github-scanner--remediator)** | Zero-clone GitHub API scanner with automated clean history restoration & helper deletion. | GitHub organizations & repositories |
| **[`scan-credentials.sh`](#4-scan-credentialssh--secret--token-scanner)** | Redacted secret scanner for Git history diffs, disk, and GitHub organization secret-scanning alerts. | Git history diffs, disk, GitHub alerts |
| **[`audit-github-access.sh`](#5-audit-github-accesssh--github-access--posture-audit)** | Read-only audit of GitHub authentication, SSH/GPG keys, local credential file permissions, and extension capabilities. | GitHub account, orgs & local workstation |

---

## Installation & Prerequisites

### Prerequisites
- **Operating System:** macOS or Linux (Ubuntu, Debian, Fedora, RHEL, Arch, Alpine, etc.)
- **Shell & Utilities:** `bash` (3.2+ or 4.0+), `python3` (3.8+), `perl` (5.10+), `git` (2.20+), `file`, `base64`, `awk`, `sed`, `grep`, `shasum`
- **For GitHub API Tools (`scan-github.sh`, `audit-github-access.sh`, `scan-credentials.sh --org`):**
  - [GitHub CLI (`gh`)](https://cli.github.com/) installed and authenticated (`gh auth login`).

### Quick Start

```bash
# Clone the repository
git clone https://github.com/westackai/glassworm-scanner.git
cd glassworm-scanner

# Make all audit scripts executable
chmod +x *.sh
```

---

## Tools & Usage

### 1. `check-extensions.sh` — IDE Extension Audit

Audits all extensions installed in your development environment against the canonical blocklist ([`data/compromised-extensions.tsv`](data/compromised-extensions.tsv)) across VS Code, Cursor, Windsurf, VSCodium, and OpenVSX.

```bash
# Standard mode: Match installed extension IDs against known-compromised database
./check-extensions.sh

# Deep mode: Also scan extension JavaScript bundles for invisible Unicode runs, markers, and decoders
./check-extensions.sh --deep
```

* **Target Directories:** `~/.vscode/extensions`, `~/.vscode-insiders/extensions`, `~/.vscode-oss/extensions`, `~/.cursor/extensions`, `~/.windsurf/extensions`, `~/.vscodium/extensions`, `~/.openvsx/extensions`.
* **Output:** Prints exact `code --uninstall-extension <id>` commands for flagged extensions. Exits `0` if clean, `1` on match.

---

### 2. `scan-local.sh` — Local Git & Filesystem Scanner

Scans local Git repositories, branch tips, commit history, and loose folders. **100% offline** (never touches the network, never locks indices).

```bash
# Scan default search directories (~/Projects and ~/github)
./scan-local.sh

# Scan specific directories or repositories
./scan-local.sh ~/workspace /var/www

# Deep mode: Also scan package manifests & .venv against 462+ malicious packages
./scan-local.sh --deep ~/Projects

# Include cached remote-tracking branches (refs/remotes/*)
./scan-local.sh --include-remote-refs ~/Projects

# Export findings to a tab-separated TSV report
./scan-local.sh --tsv /tmp/glassworm_findings.tsv ~/Projects
```

* **Detections:** Fake ASCII fonts (`fa-solid-400.woff2`), `folderOpen` task execution in `.vscode/tasks.json`, `.vscode/settings.json` prompt bypasses, poisoned `.gitignore`, invisible Unicode payloads (`VS_RUN_MIN=8`), off-screen whitespace padding (`PAD_MIN=200`), PolinRider markers (`rmcej%otb%`), and `config.bat` author-spoofing scripts.

---

### 3. `scan-github.sh` — Remote GitHub Scanner & Remediator

Zero-clone GitHub scanner using `gh api`. Scans all branches, finds the newest clean historical version for each infected file, and can automatically remediate the repository directly on GitHub.

```bash
# Scan all repositories under an organization
./scan-github.sh my-org

# Scan a single repository
./scan-github.sh my-org/frontend-app

# Deep mode: Audit remote lockfiles for malicious npm/PyPI packages
./scan-github.sh my-org --deep

# Scan targets from a text file (one repo/org per line)
./scan-github.sh --repos-from targets.txt

# Preview automated remediation plan without making any changes
./scan-github.sh my-org/frontend-app --dry-run-github

# Execute safe automated remediation directly via GitHub API
./scan-github.sh my-org/frontend-app --clean-github
```

* **Safe Remediation Rules:**
  - Configs (`next.config.js`, `postcss.config.mjs`, `tasks.json`): Restores only from verified clean historical commits.
  - Known malware helpers (`temp_auto_push.bat`, `branch_structure.json`): Deletes directly via API commit.
  - Fake text fonts: Restores verified clean binary font from history, or deletes text payload font.
  - Poisoned `.gitignore`: Strips malware helper patterns while preserving user rules.

---

### 4. `scan-credentials.sh` — Secret & Token Scanner

Dedicated, privacy-preserving scanner for exposed tokens in local Git history, uncommitted files, and open GitHub organization alerts.

> [!IMPORTANT]
> **Privacy Guarantee:** Secrets are **never printed in plaintext** or written to disk unredacted. Matches are masked (`ghp_123456…7890`) and fingerprinted with SHA-256 (`sha256:abcd1234ef56`). Repetitive padding strings are filtered via Shannon entropy checks.

```bash
# Scan committed files across branch tips in default paths (~/Projects ~/github)
./scan-credentials.sh

# Deep historical scan: inspect all reachable commit diffs (catches committed & deleted secrets)
./scan-credentials.sh --history ~/Projects

# Also scan untracked / gitignored local files (.env, .npmrc)
./scan-credentials.sh --local ~/Projects

# Query open GitHub organization Secret Protection alerts (secrets hidden by GitHub)
./scan-credentials.sh --org my-org --org partner-org

# Export a secure, mode-0600 redacted TSV report
./scan-credentials.sh --history --tsv /tmp/credentials_report.tsv ~/Projects
```

* **Patterns Covered:** GitHub Tokens (Classic PAT, Fine-grained PAT, OAuth, User/Refresh, Installation), npm Tokens, AWS Access & Secret Keys, Slack Tokens, Stripe Live Keys, Anthropic API Keys, OpenAI Keys, Private Key PEM blocks, and Git Remote URL credentials.

---

### 5. `audit-github-access.sh` — GitHub Access & Posture Audit

Read-only audit of your GitHub cloud authentication posture, repository access, and local workstation credential storage security.

```bash
# Standard audit: GitHub account metadata + local credential storage posture
./audit-github-access.sh

# Deep audit: Include organization SSO authorizations, GitHub Apps, and audit logs
./audit-github-access.sh --org my-org --audit-log

# Repository audit: Inspect deploy keys, webhooks, and secret metadata
./audit-github-access.sh --repo my-org/web-app --repo my-org/api-server

# Audit all repositories where you have administrator permissions
./audit-github-access.sh --all-repos

# Pure offline mode (audits local credential files, Git config, and extension capabilities only)
./audit-github-access.sh --offline
```

* **What it Audits:** `gh` auth status and token scopes, SSH/GPG keys, SSO credential authorizations, GitHub App installations, local credential file permissions (`~/.config/gh/hosts.yml`, `~/.npmrc`, `~/.aws/credentials`, `~/.docker/config.json`, etc.), Git `credential.helper` posture, and extension GitHub-auth capabilities.

---

## Threat Intelligence & IoCs

Threat intelligence feeds in [`data/`](data/) and [`iocs.txt`](iocs.txt) are continuously updated:

- **[`data/compromised-extensions.tsv`](data/compromised-extensions.tsv)**: 418+ malicious VS Code / OpenVSX extension IDs across all GlassWorm waves, sleeper campaigns, and evil-twin packages.
- **[`data/malicious-packages.tsv`](data/malicious-packages.tsv)**: 462+ malicious npm & PyPI packages (Shai-Hulud, PolinRider, TeamPCP, etc.) with exact and range version matching.
- **[`data/credential-patterns.tsv`](data/credential-patterns.tsv)**: 16+ high-precision token regexes with false-positive suppression rules.
- **[`data/credential-ignore.txt`](data/credential-ignore.txt)**: Filter for known benign documentation/placeholder keys.
- **[`iocs.txt`](iocs.txt)**: Technical indicators including MD5 hashes, C2 IP addresses, Ethereum dead-drop endpoints (`eth.blockscout.com`), attacker wallet fragments (`0xa322E5f3D311D3080e9aDC2490Ef6f0121063e…`), and obfuscator fingerprints (`rmcej%otb%`, `Cot%3t=shtP`, `lzcdrtfxyqiplpd`).

---

## Incident Response

If GlassWorm or exposed credentials are detected:

1. **Isolate Workstation:** Disconnect from corporate Wi-Fi/Ethernet and VPN.
2. **Purge Extensions:** Run `code --uninstall-extension <id>` for all flagged extensions.
3. **Disable Auto-Tasks:** In IDE settings, set `"task.allowAutomaticTasks": "off"` and `"extensions.autoUpdate": false`.
4. **Audit Access & Keys:** Run `./audit-github-access.sh` to review active keys, tokens, and authorizations.
5. **Scan Credentials:** Run `./scan-credentials.sh --history --local` to locate exposed tokens.
6. **Remediate Repositories:** Run `./scan-github.sh <org> --clean-github` to clean infected branches on GitHub.
7. **Revoke & Rotate:** Immediately revoke and rotate all GitHub PATs, SSH keys, npm tokens, cloud API keys, and crypto wallet secrets. *(Deleting a commit does not revoke an exposed token).*

---

## CI/CD Pipeline Integration

Integrate automated scanning into your GitHub Actions workflow:

```yaml
name: Security & Malware Audit

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master, develop ]

jobs:
  security-audit:
    name: GlassWorm & Secret Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Clone Scanner
        run: git clone https://github.com/westackai/glassworm-scanner.git /tmp/glassworm-scanner

      - name: Audit Repository for Malware
        run: |
          chmod +x /tmp/glassworm-scanner/*.sh
          /tmp/glassworm-scanner/scan-local.sh --deep --include-remote-refs .

      - name: Audit Repository for Committed Secrets
        run: |
          /tmp/glassworm-scanner/scan-credentials.sh --history .
```

---

## Contributing

We welcome contributions from the cybersecurity, DevOps, and open-source communities!

### 🌟 Ways to Contribute

* **🛡️ Threat Intelligence & Signatures:**
  * Submitting newly discovered GlassWorm waves, sleeper extensions, and malicious publishers to [`data/compromised-extensions.tsv`](data/compromised-extensions.tsv).
  * Adding newly observed malicious npm/PyPI packages to [`data/malicious-packages.tsv`](data/malicious-packages.tsv).
  * Refining token detection patterns in [`data/credential-patterns.tsv`](data/credential-patterns.tsv).
* **🚀 New Tooling & Features:**
  * Support for additional Git hosting providers (e.g. **GitLab API**, **Bitbucket Cloud / Server**, **Gitea / Forgejo**).
  * New output formats (**SARIF** for GitHub Code Scanning, structured **JSON**, **HTML audit reports**).
  * Pre-commit git hooks and standalone Docker container packaging.
* **💻 Additional IDE & Editor Support:**
  * Adding extension path discovery for emerging IDEs (e.g. **Zed**, **Trae**, **Positron**, **Eclipse Theia**).
* **⚡ Detection Engine & Performance:**
  * Optimizing scanning throughput across massive monorepos.
  * Enhancing heuristic filters to maintain zero false positives.

### 🔄 PR Workflow

1. **Fork & Branch:**
   ```bash
   git clone https://github.com/<your-username>/glassworm-scanner.git
   cd glassworm-scanner
   git checkout -b threat-intel/wave-7-extensions
   ```

2. **Validate & Test Locally:**
   ```bash
   # 1. Run shellcheck to catch syntax and portability issues
   shellcheck *.sh

   # 2. Test offline scanners
   ./scan-local.sh --deep .
   ./check-extensions.sh --deep
   ./scan-credentials.sh .
   ```

3. **Submit a Pull Request:** Open a PR against `main` on [westackai/glassworm-scanner](https://github.com/westackai/glassworm-scanner/pulls) with clear references to any security research or advisories.

### 🛡️ Development & Safety Standards

| Invariant | Requirement |
| :--- | :--- |
| **Zero Network Activity (`scan-local.sh`)** | Must never make network calls, trigger credential prompts, or take repository index locks. |
| **Safe Remediation (`scan-github.sh`)** | Never delete user configurations without verifying historical clean commits. |
| **Privacy & Redaction (`scan-credentials.sh`)** | Never output plaintext secrets; enforce SHA-256 fingerprinting and mode-0600 report permissions. |
| **Portability** | Must run on Bash 3.2+ / 4.0+ across both macOS and Linux. |
| **ShellCheck Compliance** | Must pass `shellcheck` with zero severe warnings. |

---

## Threat Intelligence References & Acknowledgments

This toolkit synthesizes research, indicators, and telemetry from across the cybersecurity industry:

- **[Koi Security](https://www.koisecurity.com/)** — [GlassWorm initial discovery](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace), native binary analysis, macOS campaign tracking, and MCP attack wave research.
- **[Socket.dev](https://socket.dev/)** — [GlassWorm v2 threat feed](https://socket.dev/supply-chain-attacks/glassworm-v2), [73 OpenVSX sleeper extensions research](https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm), and transitive campaign analysis.
- **[Checkmarx Zero](https://checkmarx.com/)** — Supply chain threat intelligence and malicious package disclosures.
- **[Yeeth Security](https://yeethsecurity.com/)** — [Bane forensics](https://yeethsecurity.com/blog/2026-04-28-GlassWormBaneForensics), [Solana dead-drop research](https://yeethsecurity.com/blog/2026-05-25-Glassworm-Solana), and [WASM delivery wave analysis](https://yeethsecurity.com/blog/2026-06-16-Glassworm-WASM).
- **[Manifold Security](https://manifold.security/)** — [OpenVSX evil-twin extensions analysis](https://www.manifold.security/blog/open-vsx-evil-twin-extensions).
- **[StepSecurity](https://www.stepsecurity.io/)** & **[BleepingComputer](https://www.bleepingcomputer.com/)** — Malicious npm release tracking and CI/CD security advisories.
- **[Aikido Security](https://www.aikido.dev/)** & **[JFrog Security](https://jfrog.com/)** — Unicode variation selector attacks and fake font binary evasion analysis.
- **[Wiz Research](https://www.wiz.io/)** & **[Sonatype](https://www.sonatype.com/)** — Shai-Hulud malware campaign indicators and dependency-confusion intelligence.

---

## License

This project is licensed under the [MIT License](LICENSE) — see the [LICENSE](LICENSE) file for details.
