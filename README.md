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
- `src/` — reusable library code (scanner rules, report generator)
- `handoff/` — PRD/spec + handoff prompts for Claude/Codex/Gemini
- `docs/` — additional design notes (kept out of the skill to avoid token bloat)

## Quickstart (developer)

```bash
cd skills/securityclaw-skill/scripts
python3 securityclaw_scan.py --help
```

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

