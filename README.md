# SecurityClaw

[![Quick Install](https://img.shields.io/badge/Quick%20Install-npx%20github%3Amallen--lbx%2FSecurityClaw%20install-2ea44f?style=for-the-badge)](https://github.com/mallen-lbx/SecurityClaw)

SecurityClaw is a security-focused OpenClaw skill scanner. It inspects skills for risky patterns, scores findings, recommends actions (`allow`, `review`, `quarantine`), and supports continuous monitoring.

## Quick Install

Copy-paste one-shot install:

```bash
npx github:mallen-lbx/SecurityClaw install
```

Copy-paste global install:

```bash
npm i -g github:mallen-lbx/SecurityClaw
securityclaw install
```

## What SecurityClaw Does

- Scans OpenClaw skills for command execution, network egress, prompt injection markers, sensitive path usage, and install-hook risk indicators.
- Produces evidence-based reports with file/line proof.
- Creates an ELI5 removal summary when quarantine candidates exist.
- Supports owner-driven decisions: `Delete`, `Report`, `Allow`, `Scan all`.
- Sends notifications (Telegram, webhook, or stdout fallback).
- Watches for new/changed skills and scans automatically.
- Maintains monthly scan logs.

## Install (Public GitHub via npm)

This repo is public and installable directly from GitHub.

### Option 1: One-shot install with npx

```bash
npx github:mallen-lbx/SecurityClaw install
```

### Option 2: Global install then run

```bash
npm i -g github:mallen-lbx/SecurityClaw
securityclaw install
```

### What `securityclaw install` does

- Copies the skill to `~/.openclaw/skills/securityclaw-skill`.
- Installs persistent auto-scan scheduler:
  - macOS: `launchd` label `com.openclaw.securityclaw.watch`
  - Linux: `systemd --user` service `securityclaw-watch.service`
- If Linux scheduler dependency is missing, installer:
  - warns during installation,
  - shows an install command,
  - offers to install it automatically.

## Manual Scanner Usage

Run a one-time scan:

```bash
securityclaw scan --skills-dir ~/.openclaw/skills
```

Equivalent direct Python command:

```bash
python3 ~/.openclaw/skills/securityclaw-skill/scripts/securityclaw_scan.py --skills-dir ~/.openclaw/skills
```

## Auto-Scan Behavior

SecurityClaw watch mode scans new or changed skills automatically.

- Scheduler starts watch mode at login/user session.
- Watch mode writes report files only when findings require `review` or `quarantine`.
- Watch mode always notifies when a **new skill** is scanned.

Direct watch command:

```bash
securityclaw scan --skills-dir ~/.openclaw/skills --watch --watch-scan-on-start
```

## Reports, ELI5, and Logs

All outputs are under:

- `~/.openclaw/SecurityClaw_Scans`

### Report naming

- JSON: `Security_Scan-(MM)-(DD)-(YYYY)-(scan number).json`
- Markdown: `Security_Scan-(MM)-(DD)-(YYYY)-(scan number).md`
- ELI5 (only for quarantine candidates): `Security_Scan-(MM)-(DD)-(YYYY)-(scan number)-ELI5.md`

Example:

- `Security_Scan-02-06-2026-001.md`

### Quarantine evidence section

When quarantine candidates exist, Markdown report includes `Quarantine Evidence (4 findings each)` with proof entries (rule, file, line, context, confidence, excerpt).

### Monthly scan logs

- Directory: `~/.openclaw/SecurityClaw_Scans/Scan_Logs`
- File pattern: `<Month>.log` (example: `April.log`)
- Per-scan line format:

```text
scan completed 04-06-26 12:00:00
```

## Notifications

Notification config path:

- `~/.openclaw/securityclaw-notify.json`

Template:

- `skills/securityclaw-skill/references/notification.example.json`

Supported channels:

- `telegram`
- `webhook`
- `stdout`

If no working notification channel is configured, SecurityClaw prints a stdout fallback message so users are still notified.

## Configuration Files

- Allowlist template:
  - `skills/securityclaw-skill/references/allowlist.example.json`
- Notification template:
  - `skills/securityclaw-skill/references/notification.example.json`

Default runtime config paths:

- Allowlist: `~/.openclaw/securityclaw-allowlist.json`
- Notifications: `~/.openclaw/securityclaw-notify.json`

## How It Works (High-Level)

1. Enumerate skill directories.
2. Hash each skill for stable identity.
3. Run context-aware static checks.
4. Apply allowlist suppression (if configured).
5. Compute severity, confidence, risk score, and recommendation.
6. On `quarantine` recommendation, include 4 proof findings.
7. Save reports (based on report mode), create ELI5 summary when needed.
8. Send notifications.
9. Append monthly scan log entry.

## Scheduler Status and Operations

### macOS (`launchd`)

Check status:

```bash
launchctl print gui/$(id -u)/com.openclaw.securityclaw.watch
```

Restart:

```bash
launchctl kickstart -k gui/$(id -u)/com.openclaw.securityclaw.watch
```

### Linux (`systemd --user`)

Check status:

```bash
systemctl --user status securityclaw-watch.service
```

Restart:

```bash
systemctl --user restart securityclaw-watch.service
```

Enable at login/session:

```bash
systemctl --user enable --now securityclaw-watch.service
```

Optional (run after logout too):

```bash
loginctl enable-linger $USER
```

## Troubleshooting

### `securityclaw: command not found`

- Use one-shot install: `npx github:mallen-lbx/SecurityClaw install`
- If globally installed, ensure npm global bin is in `PATH`.

### Python not found

- Install Python 3 and rerun install.
- You can set a specific interpreter:

```bash
securityclaw install --python-bin /usr/bin/python3
```

### Linux scheduler not available

- Installer will notify and print an install command.
- Re-run installer after dependency install.
- Manual fallback:

```bash
securityclaw scan --skills-dir ~/.openclaw/skills --watch --watch-scan-on-start
```

### No report files in auto-scan mode

- This is expected when there are no `review`/`quarantine` findings.
- Check monthly scan logs for scan activity.

### No external notifications delivered

- Validate `~/.openclaw/securityclaw-notify.json`.
- Even with broken channels, stdout fallback notification is emitted.

### Too many false positives

- Add allowlist entries for approved skills/rules.
- Re-scan and review `suppressedFindings` in JSON report.

## Repository Layout

- `skills/securityclaw-skill/` - skill package and scanner scripts
- `skills/securityclaw-skill/scripts/securityclaw_scan.py` - core scanner
- `skills/securityclaw-skill/scripts/install_securityclaw.py` - scheduler installer (`launchd`/`systemd`)
- `bin/securityclaw.js` - npm CLI wrapper (`install`, `scan`)
- `handoff/` - product/spec/prompt handoff artifacts
- `docs/plans/` - execution plans

## Continuing Development

If you want to modify or extend SecurityClaw, start with the `handoff/` folder. It contains PRD/spec/prompt materials intended to help continue development with full context.

## License

MIT (see `LICENSE`).
