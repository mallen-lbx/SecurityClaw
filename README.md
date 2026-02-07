# SecurityClaw 🦞

SecurityClaw is a **security-first skill + toolkit** for OpenClaw that audits installed skills for:

- malicious behavior / exploit patterns
- prompt injection payloads embedded in docs
- secret exfiltration and unsafe tool usage
- risky install scripts / supply-chain issues

When a suspicious or infected skill is detected, SecurityClaw’s workflow is:

1) **Quarantine** the skill (move it out of the active skills directory)
2) Generate a **forensic report** (what matched, where, why it’s risky)
3) **Notify the owner** and await explicit instruction:
   - **Delete** (remove quarantined files)
   - **Report** (open an issue / publish IOCs)
   - **Allow** (add to allowlist and restore)
   - **Scan all** (deep scan all skills)

> Motto: **No silent side effects. No silent trust.**

---

## What’s in this repo

- `skills/securityclaw-skill/` — OpenClaw skill package (SKILL.md + scripts)
- `handoff/` — PRD/spec + handoff prompts for Claude/Codex/Gemini
- `docs/plans/` — implementation plans and execution checklists

## Quickstart (developer)

```bash
cd skills/securityclaw-skill/scripts
python3 securityclaw_scan.py --help
```

Install persistent auto-scan scheduler:

```bash
python3 install_securityclaw.py --skills-dir ~/.openclaw/skills --notify-config ~/.openclaw/securityclaw-notify.json
```

Install from GitHub via npm (public):

```bash
npx github:mallen-lbx/SecurityClaw install
```

Alternative:

```bash
npm i -g github:mallen-lbx/SecurityClaw
securityclaw install
```

Installer behavior:

- macOS: sets up `launchd` (`com.openclaw.securityclaw.watch`)
- Linux: sets up `systemd --user` (`securityclaw-watch.service`)
- Linux without `systemd`: installer warns, shows install command, and offers automatic install

Example scan:

```bash
python3 securityclaw_scan.py --skills-dir ~/.openclaw/skills
```

Reports are auto-saved to:

- `~/.openclaw/SecurityClaw_Scans`
- naming format: `Security_Scan-(MM)-(DD)-(YYYY)-(scan number)` (example: `Security_Scan-02-06-2026-001.json`)
- quarantine ELI5 summary: `Security_Scan-...-ELI5.md` (created when quarantine candidates exist)

Optional known-safe suppression:

```bash
python3 securityclaw_scan.py --skills-dir ~/.openclaw/skills --allowlist ~/.openclaw/securityclaw-allowlist.json
```

Notification summary (Telegram/webhook/stdout):

```bash
python3 securityclaw_scan.py --skills-dir ~/.openclaw/skills --notify-config ~/.openclaw/securityclaw-notify.json --notify-on quarantine
```

Auto-scan new/changed skills:

```bash
python3 securityclaw_scan.py --skills-dir ~/.openclaw/skills --watch --watch-scan-on-start
```

When quarantine candidates are detected, the Markdown report includes a quarantine-evidence section with 4 proof findings per skill.
In auto-scan mode, report docs are only written when findings require review/quarantine.
When a new skill is scanned in auto mode, notifications are always sent.

Monthly scan logs:

- location: `~/.openclaw/SecurityClaw_Scans/Scan_Logs/<Month>.log`
- line format: `scan completed 04-06-26 12:00:00`

## Design principles (security)

- **Assume untrusted input**: skills, markdown, and JSON are attacker-controlled.
- **Least privilege**: scans are read-only by default.
- **Quarantine > delete**: deletion requires explicit owner approval.
- **No surprises**: any install/bootstrap actions (Docker, Portainer, etc.) require **explicit owner approval**.
- **Defense in depth**: static checks + optional sandbox/dynamic checks.

## Recommended usage (best UX)

Run SecurityClaw **via chat** (owner ↔ bot) so the bot can:
- explain findings in plain English,
- ask follow-up questions,
- and present the owner action menu (**Delete / Report / Allow / Scan all**) with clear previews.

Avoid running destructive actions from scripts without a human in the loop.

---

## Lobster law 🦞

If it can pinch your tokens, it can pinch your secrets.
