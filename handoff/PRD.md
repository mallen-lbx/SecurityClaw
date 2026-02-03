# SecurityClaw — PRD (Product Requirements Document)

## Problem
OpenClaw skills are code + instructions loaded into an agent context. A malicious skill can:
- execute arbitrary commands
- exfiltrate secrets via network tools
- poison memory / instructions (prompt injection)
- modify OpenClaw configuration and hooks
- introduce supply-chain risk via dependencies / install scripts

We need a **security-first skill auditing and quarantine system** that protects owners from installing or running unsafe skills.

## Goals
1) Detect risky or malicious skills before they run.
2) Quarantine suspicious skills (remove from active path) without data loss.
3) Generate a clear report (what + why + where).
4) Notify the owner and require explicit instruction before destructive actions.
5) Support optional sandbox/dynamic analysis in a controlled environment.

## Non-goals
- Perfect malware detection.
- Full VM-level containment on day 1.

## Users
- OpenClaw owners running local/remote gateways (Mac/Headless Linux).

## Core UX (Owner flow)
- Owner requests: “scan my skills”, or a new skill is added.
- SecurityClaw returns a report + recommendation.
- If infected/suspicious, SecurityClaw quarantines and prompts owner with options:
  - **Delete** (remove quarantined files)
  - **Report** (prepare sanitized report / open issue)
  - **Allow** (add allowlist rule; restore skill)
  - **Scan all** (deep scan everything)

## Requirements
### R1. Static analysis
- Scan SKILL.md + scripts + package.json + manifests.
- Detect:
  - command execution primitives
  - network egress primitives
  - references to sensitive files/paths
  - prompt injection markers
  - install scripts and supply-chain red flags
- Output: JSON report + human summary.

### R2. Quarantine
- Move suspicious skill directory to `~/.openclaw/skills-quarantine/<timestamp>-<name>`.
- Never delete automatically.

### R3. Owner notification + approval gate
- Notify owner via configured channel.
- Await explicit “Delete / Report / Allow / Scan all”.

### R4. Allowlist
- Allow exceptions per skill hash + rule override.
- Store allowlist in a safe location (outside skill directories).

### R5. Optional dynamic analysis (Phase 2)
- Run the skill in a sandboxed runner:
  - no network
  - no access to `~/.openclaw/openclaw.json`, secrets, or real tools
  - log tool calls and filesystem touches
- Produce behavioral indicators.

## Success metrics
- % of new skills scanned before use.
- Time-to-report under 30s for typical setups.
- Low false positive rate after tuning + allowlist.

## Phases
- **Phase 1**: static scan + quarantine + owner prompt.
- **Phase 2**: allowlist + regression tests for known-safe skills.
- **Phase 3**: sandbox/dynamic behavior harness.
