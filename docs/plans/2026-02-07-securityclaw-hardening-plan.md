# SecurityClaw Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Improve SecurityClaw scan accuracy/confidence, add deterministic report storage in `~/.openclaw/SecurityClaw_Scans`, and provide clear user-facing findings summaries.

**Architecture:** Keep the scanner dependency-light but split responsibilities into rule evaluation, contextual severity mapping, risk scoring, allowlist suppression, report generation, and quarantine auditing. Use deterministic file naming and append-only audit logs.

**Tech Stack:** Python 3 standard library (`argparse`, `json`, `pathlib`, `hashlib`, `datetime`, `re`, `shutil`, `unittest`).

---

## Execution Checklist

### Task 1: Baseline + safety guardrails

**Files:**
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/scripts/securityclaw_scan.py`

**Checklist:**
- [x] Keep scan read-only by default.
- [x] Preserve explicit `--quarantine` gate.
- [x] Preserve non-zero exit code when high-risk unsuppressed findings exist.
- [x] Preserve compatibility with existing `--skills-dir` and `--quarantine-dir` flags.

**Acceptance:** Existing basic scan invocation still works and writes a JSON report.

### Task 2: Context-aware rules + confidence scoring

**Files:**
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/scripts/securityclaw_scan.py`

**Checklist:**
- [x] Classify files into `code`, `config`, `docs`, `other`.
- [x] Downgrade doc/reference mentions for operational primitives (network/shell/sensitive paths/install hooks).
- [x] Keep prompt-injection checks active for docs.
- [x] Add per-finding `confidence`, `weight`, and `fileType` fields.
- [x] Add skill-level risk scoring and recommendation policy.

**Acceptance:** Doc-only mentions no longer automatically escalate to quarantine-level severity.

### Task 3: Allowlist with hash-aware suppression

**Files:**
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/scripts/securityclaw_scan.py`
- Add: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/references/allowlist.example.json`

**Checklist:**
- [x] Add `--allowlist` flag with default `~/.openclaw/securityclaw-allowlist.json`.
- [x] Compute stable skill hash from directory contents.
- [x] Support allowlist by skill name + hash + rule IDs (`*` wildcard allowed).
- [x] Keep suppressed findings in report under explicit suppression metadata.

**Acceptance:** Known-safe skills can be suppressed without removing evidence from the report.

### Task 4: Report folder + naming convention

**Files:**
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/scripts/securityclaw_scan.py`
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/SKILL.md`

**Checklist:**
- [x] Write reports by default to `~/.openclaw/SecurityClaw_Scans`.
- [x] Use filename format `Security_Scan-(MM)-(DD)(YYYY)(scan number)`.
- [x] Implement daily incrementing scan number (zero-padded to 3 digits).
- [x] Write both `.json` and `.md` reports per scan.
- [x] Optionally continue supporting explicit `--out` override.

**Acceptance:** Repeated runs on the same day produce `...001`, `...002`, etc.

### Task 5: User-facing findings summary

**Files:**
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/scripts/securityclaw_scan.py`
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/SKILL.md`

**Checklist:**
- [x] Print concise terminal summary after every run.
- [x] Include severity counts, top findings, confidence, recommended actions.
- [x] Include saved report paths in summary.
- [x] Show owner action menu for high-risk findings.

**Acceptance:** The scanner always reports a clear human-readable result to the user.

### Task 6: Quarantine audit index

**Files:**
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/scripts/securityclaw_scan.py`

**Checklist:**
- [x] Append quarantine events to `~/.openclaw/skills-quarantine/index.jsonl`.
- [x] Include timestamp, skill, source path, destination path, hash, reason.

**Acceptance:** Every quarantine action is traceable in append-only audit logs.

### Task 7: Regression tests

**Files:**
- Add: `/Users/mallen/ClawPojects/SecurityClaw/tests/securityclaw/test_scan.py`

**Checklist:**
- [x] Add tests for report filename sequencing.
- [x] Add tests ensuring docs mentions do not produce high-risk quarantine by themselves.
- [x] Add tests for allowlist suppression behavior.
- [x] Add tests for markdown + JSON report emission.

**Acceptance:** Local test run passes and protects against previously observed false positives.

### Task 8: Validation + documentation update

**Files:**
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/README.md`
- Modify: `/Users/mallen/ClawPojects/SecurityClaw/skills/securityclaw-skill/SKILL.md`

**Checklist:**
- [x] Update quickstart examples to new report defaults.
- [x] Document allowlist format and location.
- [x] Document report folder naming and scan number behavior.
- [x] Document interpretation of confidence and recommendations.

**Acceptance:** README and skill docs match implemented behavior with no stale references.

---

## Implementation order

1. Task 2 (context + scoring)
2. Task 4 (report path + naming)
3. Task 3 (allowlist)
4. Task 5 (user summary)
5. Task 6 (quarantine index)
6. Task 7 (tests)
7. Task 8 (docs)

## Rollback strategy

- Keep changes in small commits.
- If scoring creates regressions, fallback to recommendation-only use while retaining raw findings.
- Preserve full findings in JSON so downstream tooling remains debuggable.
