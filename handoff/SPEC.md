# SecurityClaw — Spec Sheet

## Deliverables
- OpenClaw skill: `skills/securityclaw-skill/`
- Scanner script: `scripts/securityclaw_scan.py`
- Rule catalog + sandbox strategy references
- Repo: `SecurityClaw` (public)

## Data model (report.json)
```json
{
  "ts": "2026-02-02T00:00:00Z",
  "skillsDir": "...",
  "quarantineDir": "...",
  "summary": {"total": 12, "bySeverity": {"info":0,"low":1,"medium":5,"high":6,"critical":0}},
  "results": [
    {
      "skill": "clawdlink",
      "path": ".../clawdlink",
      "severity": "high",
      "findingCount": 3,
      "findings": [
        {"rule_id":"network_egress","severity":"high","message":"...","file":"clawdlink/handler.js","line":12,"excerpt":"fetch(..."}
      ],
      "recommendation": "quarantine"
    }
  ],
  "actions": [
    {"action":"quarantine","skill":"clawdlink","movedTo":".../skills-quarantine/TS-clawdlink"}
  ]
}
```

## Rules engine
- Start with conservative regex rules.
- Reduce false positives with:
  - allowlist per known-safe skill
  - context-aware checks (e.g., in docs vs code)
  - per-language AST checks (Phase 2)

## Quarantine
- Move only (no delete).
- Keep an audit trail in report.json.

## Owner instruction options
- Delete
- Report
- Allow
- Scan all

## Security posture
- Treat all skill text/code as untrusted.
- Never execute untrusted code during Phase 1.
- Dynamic analysis (Phase 2/3) must run in a sandbox.
