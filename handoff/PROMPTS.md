# Handoff prompts (Claude / Codex / Gemini)

Use these prompts to hand off implementation work to another coding agent.

## Prompt: implement SecurityClaw Phase 1

You are building **SecurityClaw**, a security-first OpenClaw skill to scan installed skills for exploits and prompt injections.

Repository layout is already created. Implement Phase 1:
- Expand the scanner rules to reduce false positives.
- Add allowlist support (by skill name + content hash).
- Add a quarantine index file (jsonl) under ~/.openclaw/skills-quarantine/index.jsonl.
- Add a human-readable Markdown report output option.

Constraints:
- Do not execute untrusted code.
- Do not auto-delete.
- Keep scripts dependency-light.

Acceptance tests:
- Running scan on a skills dir produces report.json.
- --quarantine moves only high+ skills.
- allowlist prevents known-safe skills from being quarantined.

## Prompt: implement Phase 2 sandbox runner (design + stub)

Design an optional sandbox runner for dynamic analysis:
- No network egress
- No access to ~/.openclaw/openclaw.json or secrets
- Runs a dummy agent environment and logs actions

Output:
- a design doc (docs/sandbox-runner.md)
- a runnable stub command that prints what would be executed.
