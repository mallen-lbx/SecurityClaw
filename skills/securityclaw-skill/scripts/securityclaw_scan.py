#!/usr/bin/env python3
"""SecurityClaw: scan OpenClaw skills directories for high-risk patterns.

Goals
- Security-first, conservative scanner for skill folders.
- Produce JSON and Markdown reports with recommendations.
- Quarantine (move) suspicious skills out of the active skills dir.

Non-goals
- Perfect malware detection.
- Executing untrusted skill code.

This script is intentionally dependency-light.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

TEXT_EXTS = {
    ".md",
    ".txt",
    ".json",
    ".js",
    ".ts",
    ".py",
    ".sh",
    ".mjs",
    ".cjs",
    ".yaml",
    ".yml",
    ".toml",
    ".rst",
}
MAX_FILE_BYTES = 2_000_000  # avoid giant files

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_LIST = ["info", "low", "medium", "high", "critical"]
SEVERITY_MULTIPLIER = {"info": 0.1, "low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}
DEFAULT_OPENCLAW_ROOT = Path.home() / ".openclaw"
DEFAULT_REPORT_DIR = DEFAULT_OPENCLAW_ROOT / "SecurityClaw_Scans"
DEFAULT_ALLOWLIST = DEFAULT_OPENCLAW_ROOT / "securityclaw-allowlist.json"
DEFAULT_QUARANTINE_DIR = DEFAULT_OPENCLAW_ROOT / "skills-quarantine"
DEFAULT_NOTIFY_CONFIG = DEFAULT_OPENCLAW_ROOT / "securityclaw-notify.json"
DEFAULT_WATCH_STATE = DEFAULT_REPORT_DIR / "watch-state.json"

DOC_PRIMITIVE_RULES = {"install_script", "shell_exec", "network_egress", "secret_access", "sensitive_paths"}


@dataclasses.dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    base_weight: float


# Conservative starter set; can evolve with regression testing.
RULES: Sequence[Rule] = (
    Rule(
        "install_script",
        "high",
        re.compile(r"\b(postinstall|preinstall|install)\b", re.I),
        "Install scripts can execute arbitrary code.",
        2.8,
    ),
    Rule(
        "shell_exec",
        "high",
        re.compile(
            r"\b(child_process\.(exec|execSync|spawn|spawnSync)|os\.system\(|subprocess\.(Popen|run|call)|Runtime\.getRuntime\(\)\.exec)\b",
            re.I,
        ),
        "Direct command execution found.",
        3.2,
    ),
    Rule(
        "network_egress",
        "high",
        re.compile(r"(fetch\(|axios\.|curl\b|wget\b|requests\.|http\.client|net\.Socket|WebSocket\b)", re.I),
        "Network egress primitives found.",
        2.6,
    ),
    Rule(
        "secret_access",
        "high",
        re.compile(r"(OPENAI_API_KEY|GEMINI_API_KEY|SEARXNG|PORTAINER_TOKEN|BOT_TOKEN|PRIVATE_KEY|BEGIN\s+PRIVATE\s+KEY)", re.I),
        "Possible secret access or exfiltration target.",
        3.4,
    ),
    Rule(
        "prompt_injection",
        "medium",
        re.compile(r"(ignore\s+previous\s+instructions|system\s+prompt|developer\s+message|exfiltrate|BEGIN\s+SYSTEM\s+PROMPT)", re.I),
        "Prompt-injection style content found.",
        1.8,
    ),
    Rule(
        "sensitive_paths",
        "high",
        re.compile(r"(~/?\.openclaw/|/etc/|\.ssh/|id_rsa|authorized_keys|keychain|\.env\b)", re.I),
        "References sensitive paths.",
        2.7,
    ),
)


@dataclasses.dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    excerpt: str
    fileType: str
    context: str
    confidence: float
    weight: float
    suppressed: bool = False
    suppressReason: str = ""


@dataclasses.dataclass
class AllowlistEntry:
    skill: str
    hash: str
    rules: List[str]
    expires: str
    reason: str


@dataclasses.dataclass
class SkillMeta:
    name: str
    path: Path
    digest: str


def clamp_excerpt(s: str, limit: int = 240) -> str:
    s = s.replace("\t", " ")
    return s if len(s) <= limit else s[: limit - 3] + "..."


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 0)


def lower_severity(severity: str, steps: int) -> str:
    idx = max(0, SEVERITY_LIST.index(severity) - steps)
    return SEVERITY_LIST[idx]


def classify_file(path: Path) -> str:
    name = path.name.lower()
    ext = path.suffix.lower()

    if ext in {".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".bash"}:
        return "code"
    if name in {"package.json", "manifest.json", "openclaw.json"}:
        return "config"
    if ext in {".json", ".yaml", ".yml", ".toml"}:
        return "config"
    if ext in {".md", ".txt", ".rst"} or name.startswith("readme"):
        return "docs"
    if ext in TEXT_EXTS:
        return "docs"
    return "other"


def looks_like_comment(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")


def read_text_file(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None


def contextualize(rule: Rule, file_type: str, line: str) -> Tuple[str, float, float, str]:
    severity = rule.severity
    weight = rule.base_weight
    confidence = 0.88
    context = "executable_context"

    if file_type == "docs":
        if rule.rule_id in DOC_PRIMITIVE_RULES:
            severity = lower_severity(severity, 3)
            weight *= 0.10
            confidence = 0.22
            context = "documentation_mention"
        elif rule.rule_id == "prompt_injection":
            severity = "medium"
            weight *= 0.85
            confidence = 0.62
            context = "instruction_content"
        else:
            severity = lower_severity(severity, 1)
            weight *= 0.45
            confidence = 0.45
            context = "documentation_content"
    elif file_type == "config":
        confidence = 0.86
        context = "configuration_content"
    elif file_type == "code":
        stripped = line.strip()
        if "re.compile(" in stripped or stripped.startswith("Rule("):
            severity = lower_severity(severity, 2)
            weight *= 0.20
            confidence = 0.32
            context = "pattern_definition"
        elif "help=" in stripped or "description=" in stripped or "message=" in stripped:
            severity = lower_severity(severity, 2)
            weight *= 0.20
            confidence = 0.35
            context = "metadata_string"
        elif (stripped.startswith('"') or stripped.startswith("'")) and stripped.endswith(("\",", "',", "\"", "'")):
            severity = lower_severity(severity, 2)
            weight *= 0.20
            confidence = 0.30
            context = "string_literal"
        elif looks_like_comment(line):
            severity = lower_severity(severity, 1)
            weight *= 0.55
            confidence = 0.58
            context = "comment"
        else:
            confidence = 0.92
            context = "executable_context"
    else:
        severity = lower_severity(severity, 2)
        weight *= 0.30
        confidence = 0.40
        context = "unknown_content"

    return severity, round(weight, 3), round(confidence, 3), context


def scan_file(path: Path, rel: str) -> List[Finding]:
    text = read_text_file(path)
    if text is None:
        return []

    file_type = classify_file(path)
    findings: List[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule.pattern.search(line):
                sev, weight, confidence, context = contextualize(rule, file_type, line)
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        severity=sev,
                        message=rule.message,
                        file=rel,
                        line=i,
                        excerpt=clamp_excerpt(line.strip()),
                        fileType=file_type,
                        context=context,
                        confidence=confidence,
                        weight=weight,
                    )
                )
    return findings


def worst_severity(findings: Sequence[Finding]) -> str:
    if not findings:
        return "info"
    return max((f.severity for f in findings), key=severity_rank)


def findings_sorted(findings: Sequence[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (severity_rank(f.severity), f.confidence, f.weight),
        reverse=True,
    )


def quarantine_proof(findings: Sequence[Finding], limit: int = 4) -> List[Dict]:
    proof = []
    for f in findings_sorted(findings)[: max(1, limit)]:
        proof.append(
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "confidence": f.confidence,
                "file": f.file,
                "line": f.line,
                "context": f.context,
                "excerpt": f.excerpt,
                "message": f.message,
            }
        )
    return proof


def compute_skill_hash(skill_path: Path) -> str:
    digest = hashlib.sha256()
    for p in sorted(skill_path.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        try:
            rel = str(p.relative_to(skill_path)).replace("\\", "/")
            digest.update(rel.encode("utf-8"))
            digest.update(b"\0")
            digest.update(p.read_bytes())
            digest.update(b"\0")
        except Exception:
            continue
    return digest.hexdigest()


def skill_dirs(skills_dir: Path) -> List[Path]:
    if not skills_dir.exists():
        return []
    return [p for p in skills_dir.iterdir() if p.is_dir() and not p.name.startswith(".")]


def load_allowlist(path: Path) -> List[AllowlistEntry]:
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []

    entries_raw = data.get("entries", []) if isinstance(data, dict) else []
    out: List[AllowlistEntry] = []
    for item in entries_raw:
        if not isinstance(item, dict):
            continue
        skill = str(item.get("skill", "")).strip()
        if not skill:
            continue
        digest = str(item.get("hash", "")).strip().lower()
        rules = item.get("rules", ["*"])
        if not isinstance(rules, list):
            rules = ["*"]
        out.append(
            AllowlistEntry(
                skill=skill,
                hash=digest,
                rules=[str(r).strip() for r in rules if str(r).strip()],
                expires=str(item.get("expires", "")).strip(),
                reason=str(item.get("reason", "approved by owner")).strip() or "approved by owner",
            )
        )
    return out


def allowlist_reason(
    entries: Sequence[AllowlistEntry],
    skill_name: str,
    skill_hash: str,
    rule_id: str,
    now_local: dt.datetime,
) -> str:
    today = now_local.date()
    for entry in entries:
        if entry.skill != skill_name:
            continue
        if entry.hash and entry.hash != skill_hash:
            continue
        if entry.expires:
            try:
                expires_date = dt.date.fromisoformat(entry.expires)
                if today > expires_date:
                    continue
            except ValueError:
                continue
        if "*" in entry.rules or rule_id in entry.rules:
            return entry.reason
    return ""


def evaluate_skill(
    meta: SkillMeta,
    base_dir: Path,
    allow_entries: Sequence[AllowlistEntry],
    now_local: dt.datetime,
) -> Dict:
    findings: List[Finding] = []

    for p in meta.path.rglob("*"):
        if p.is_symlink() or not p.is_file():
            continue
        if p.suffix.lower() in TEXT_EXTS or p.name in {"SKILL.md", "package.json", "manifest.json"}:
            rel = str(p.relative_to(base_dir))
            findings.extend(scan_file(p, rel))

    active: List[Finding] = []
    suppressed: List[Finding] = []
    for finding in findings:
        reason = allowlist_reason(allow_entries, meta.name, meta.digest, finding.rule_id, now_local)
        if reason:
            finding.suppressed = True
            finding.suppressReason = reason
            suppressed.append(finding)
        else:
            active.append(finding)

    score = round(sum(f.weight * SEVERITY_MULTIPLIER.get(f.severity, 0.0) for f in active), 3)
    severity = worst_severity(active)

    if active:
        confidence = round(sum(f.confidence for f in active) / len(active), 3)
    else:
        confidence = 0.10

    executable_high = any(
        severity_rank(f.severity) >= SEVERITY_ORDER["high"] and f.fileType in {"code", "config"} and f.context != "comment"
        for f in active
    )

    if executable_high:
        recommendation = "quarantine"
    elif score >= 4.0 or severity_rank(severity) >= SEVERITY_ORDER["medium"]:
        recommendation = "review"
    else:
        recommendation = "allow"

    proof = quarantine_proof(active, limit=4) if recommendation == "quarantine" else []

    return {
        "skill": meta.name,
        "path": str(meta.path),
        "hash": meta.digest,
        "severity": severity,
        "confidence": confidence,
        "riskScore": score,
        "findingCount": len(active),
        "suppressedCount": len(suppressed),
        "findings": [dataclasses.asdict(f) for f in active],
        "suppressedFindings": [dataclasses.asdict(f) for f in suppressed],
        "quarantineProof": proof,
        "recommendation": recommendation,
    }


def quarantine_skill(skill_path: Path, quarantine_dir: Path) -> Path:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = quarantine_dir / f"{ts}-{skill_path.name}"
    shutil.move(str(skill_path), str(dest))
    return dest


def append_quarantine_index(quarantine_dir: Path, record: Dict) -> None:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    idx = quarantine_dir / "index.jsonl"
    with idx.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")


def allocate_report_paths(report_dir: Path, now_local: dt.datetime) -> Tuple[Path, Path, str]:
    report_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"Security_Scan-{now_local:%m}-{now_local:%d}-{now_local:%Y}-"

    max_num = 0
    pattern = re.compile(rf"^{re.escape(prefix)}(\d{{3}})\.json$")
    for p in report_dir.glob(f"{prefix}*.json"):
        m = pattern.match(p.name)
        if not m:
            continue
        max_num = max(max_num, int(m.group(1)))

    next_num = max_num + 1
    base = f"{prefix}{next_num:03d}"
    return report_dir / f"{base}.json", report_dir / f"{base}.md", base


def render_markdown_report(report: Dict) -> str:
    lines: List[str] = []
    lines.append("# SecurityClaw Scan Report")
    lines.append("")
    lines.append(f"- Timestamp: `{report['ts']}`")
    lines.append(f"- Skills directory: `{report['skillsDir']}`")
    lines.append(f"- Report JSON: `{report['reportFiles']['json']}`")
    lines.append(f"- Report Markdown: `{report['reportFiles']['markdown']}`")
    lines.append("")

    summary = report["summary"]
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total skills: **{summary['total']}**")
    lines.append(
        "- Severity counts: "
        + ", ".join(f"`{k}`={summary['bySeverity'].get(k, 0)}" for k in ["info", "low", "medium", "high", "critical"])
    )
    lines.append("")

    risky = [r for r in report["results"] if r["recommendation"] == "quarantine"]
    if risky:
        lines.append("## Quarantine Candidates")
        lines.append("")
        for r in risky:
            lines.append(
                f"- **{r['skill']}**: severity `{r['severity']}`, confidence `{r['confidence']}`, risk score `{r['riskScore']}`"
            )
        lines.append("")
        lines.append("## Quarantine Evidence (4 findings each)")
        lines.append("")
        for r in risky:
            lines.append(f"### {r['skill']}")
            proof = r.get("quarantineProof", [])[:4]
            if not proof:
                lines.append("- No proof entries were generated.")
            else:
                for idx, f in enumerate(proof, start=1):
                    lines.append(
                        f"{idx}. `{f['rule_id']}` `{f['severity']}` `{f['file']}:{f['line']}` "
                        f"(context `{f['context']}`, confidence `{f['confidence']}`) — {f['excerpt']}"
                    )
            if len(proof) < 4:
                lines.append(f"- Note: only {len(proof)} finding(s) available for this skill.")
            lines.append("")

    lines.append("## Skill Findings")
    lines.append("")
    for r in report["results"]:
        lines.append(
            f"### {r['skill']} ({r['severity']} | confidence {r['confidence']} | score {r['riskScore']} | recommendation {r['recommendation']})"
        )
        if not r["findings"]:
            lines.append("- No active findings.")
        else:
            for f in r["findings"][:12]:
                lines.append(
                    f"- `{f['rule_id']}` `{f['severity']}` `{f['file']}:{f['line']}` ({f['fileType']}, {f['context']}, conf {f['confidence']})"
                )
        if r.get("suppressedFindings"):
            lines.append(f"- Suppressed findings: {len(r['suppressedFindings'])}")
        lines.append("")

    if report["actions"]:
        lines.append("## Actions Taken")
        lines.append("")
        for a in report["actions"]:
            lines.append(f"- `{a['action']}` skill `{a['skill']}` -> `{a.get('movedTo', '')}`")
        lines.append("")

    if report.get("notifications"):
        lines.append("## Notifications")
        lines.append("")
        for n in report["notifications"]:
            lines.append(f"- `{n.get('type', 'unknown')}` ok=`{n.get('ok', False)}` status=`{n.get('status', '')}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def has_reportable_findings(report: Dict) -> bool:
    # "Found something" means behavior that requires human attention.
    return any(r.get("recommendation") in {"review", "quarantine"} for r in report.get("results", []))


def render_eli5_summary(report: Dict) -> str:
    risky = [r for r in report.get("results", []) if r.get("recommendation") == "quarantine"]
    lines: List[str] = []
    lines.append("# SecurityClaw ELI5 Risk Summary")
    lines.append("")
    lines.append("This is the simple explanation of why a skill may need to be removed or quarantined.")
    lines.append("")
    if not risky:
        lines.append("No quarantine candidates were found in this scan.")
        lines.append("")
        return "\n".join(lines)

    for r in risky:
        lines.append(f"## Skill: {r['skill']}")
        lines.append("")
        lines.append("### ELI5")
        lines.append(
            "This skill asks for powerful actions that could send data out, run commands, or change important files. "
            "If that power is abused, private data or your system can be harmed."
        )
        lines.append("")
        lines.append("### Why this is risky")
        lines.append(
            f"- Severity: `{r['severity']}`\n"
            f"- Confidence: `{r['confidence']}`\n"
            f"- Risk score: `{r['riskScore']}`\n"
            "- Recommended action: `quarantine`"
        )
        lines.append("")
        lines.append("### Four proof examples")
        proof = r.get("quarantineProof", [])[:4]
        if not proof:
            lines.append("- No proof entries were generated.")
        else:
            for idx, p in enumerate(proof, start=1):
                lines.append(
                    f"{idx}. `{p['rule_id']}` at `{p['file']}:{p['line']}` "
                    f"(confidence `{p['confidence']}`) -> `{p['excerpt']}`"
                )
        lines.append("")
        lines.append("### Real-world risk examples")
        lines.append("- A network call can quietly send internal notes or keys to a remote server.")
        lines.append("- A shell command can install or execute unsafe software.")
        lines.append("- Access to sensitive paths can expose credentials or machine secrets.")
        lines.append("")

    lines.append("Owner options: Delete / Report / Allow / Scan all")
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def top_findings(results: Sequence[Dict], limit: int) -> List[Dict]:
    all_findings: List[Dict] = []
    for r in results:
        for f in r.get("findings", []):
            all_findings.append({"skill": r["skill"], **f})

    all_findings.sort(
        key=lambda x: (
            severity_rank(x.get("severity", "info")),
            x.get("confidence", 0.0),
            x.get("weight", 0.0),
        ),
        reverse=True,
    )
    return all_findings[: max(0, limit)]


def print_user_summary(report: Dict, summary_limit: int) -> None:
    summary = report["summary"]
    print("SecurityClaw scan complete.")
    print(f"Scanned {summary['total']} skill(s) from {report['skillsDir']}")
    print(
        "Severity counts: "
        + ", ".join(f"{k}={summary['bySeverity'].get(k, 0)}" for k in ["info", "low", "medium", "high", "critical"])
    )
    json_report = report.get("reportFiles", {}).get("json", "")
    md_report = report.get("reportFiles", {}).get("markdown", "")
    eli5_report = report.get("reportFiles", {}).get("eli5", "")
    print(f"Report JSON: {json_report or 'not generated for this scan'}")
    print(f"Report Markdown: {md_report or 'not generated for this scan'}")
    if eli5_report:
        print(f"ELI5 Summary: {eli5_report}")
    if report.get("scanLog"):
        print(f"Scan Log: {report['scanLog']}")

    highlights = top_findings(report["results"], summary_limit)
    if highlights:
        print("Top findings:")
        for f in highlights:
            print(
                f"- {f['skill']}: {f['rule_id']} ({f['severity']}, conf={f['confidence']}) at {f['file']}:{f['line']}"
            )

    risky = [r for r in report["results"] if r["recommendation"] == "quarantine"]
    if risky:
        print("Recommended owner actions: Delete / Report / Allow / Scan all")
        print("Risk indicators are not proof of malicious intent; review evidence before action.")
        if eli5_report:
            print("ELI5 removal summary file created and ready for owner review.")


def load_notify_config(path: Path) -> Dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def build_notification_message(report: Dict) -> str:
    risky = [r for r in report["results"] if r["recommendation"] == "quarantine"]
    scan_context = report.get("scanContext", {}) or {}
    mode = scan_context.get("mode", "manual")
    reason = scan_context.get("reason", "manual")
    new_skills = scan_context.get("newSkills", []) or []

    if not risky:
        suffix = ""
        if new_skills:
            suffix = f", new_skills={','.join(new_skills)}"
        return (
            "SecurityClaw: scan completed with no quarantine candidates. "
            f"mode={mode}, reason={reason}, skills={report['summary']['total']}, "
            f"report={report.get('reportFiles', {}).get('markdown') or 'not-generated'}{suffix}"
        )

    lines = [
        "SecurityClaw quarantine alert",
        f"skills={report['summary']['total']} quarantine_candidates={len(risky)}",
    ]
    for r in risky:
        proof = r.get("quarantineProof", [])[:2]
        why = "; ".join(
            f"{p['rule_id']} {p['file']}:{p['line']} conf={p['confidence']}"
            for p in proof
        )
        lines.append(
            f"- {r['skill']} ({r['severity']}, score={r['riskScore']}, conf={r['confidence']}): {why or 'no proof entries'}"
        )
    lines.append(f"report={report['reportFiles']['markdown']}")
    if report.get("reportFiles", {}).get("eli5"):
        lines.append(f"eli5={report['reportFiles']['eli5']}")
    if new_skills:
        lines.append(f"new_skills={','.join(new_skills)}")
    lines.append("owner_actions=Delete|Report|Allow|Scan all")
    return "\n".join(lines)


def http_post_json(url: str, payload: Dict, headers: Optional[Dict[str, str]] = None, timeout: int = 10) -> Tuple[bool, str]:
    body = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url=url, data=body, headers=req_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", 200)
            return True, f"http_{code}"
    except urllib.error.HTTPError as e:
        return False, f"http_error_{e.code}"
    except Exception as e:
        return False, f"error_{type(e).__name__}"


def send_notifications(report: Dict, notify_config_path: Path, notify_on: str) -> List[Dict]:
    risky = [r for r in report["results"] if r["recommendation"] == "quarantine"]
    if notify_on == "never":
        return []
    if notify_on == "quarantine" and not risky:
        return []

    cfg = load_notify_config(notify_config_path)
    message = build_notification_message(report)
    if not cfg.get("enabled", False):
        print("SecurityClaw notification (stdout fallback):")
        print(message)
        return [{"type": "stdout-fallback", "ok": True, "status": "printed_no_config"}]

    results: List[Dict] = []
    channels = cfg.get("channels", [])
    if not isinstance(channels, list):
        channels = []

    for ch in channels:
        if not isinstance(ch, dict):
            continue
        ctype = str(ch.get("type", "")).strip().lower()
        if ctype == "telegram":
            bot = str(ch.get("botToken", "")).strip()
            chat = str(ch.get("chatId", "")).strip()
            if not bot or not chat:
                results.append({"type": "telegram", "ok": False, "status": "missing_bot_or_chat"})
                continue
            url = f"https://api.telegram.org/bot{bot}/sendMessage"
            ok, status = http_post_json(
                url,
                {
                    "chat_id": chat,
                    "text": message,
                    "disable_web_page_preview": True,
                },
            )
            results.append({"type": "telegram", "ok": ok, "status": status})
        elif ctype == "webhook":
            url = str(ch.get("url", "")).strip()
            if not url:
                results.append({"type": "webhook", "ok": False, "status": "missing_url"})
                continue
            headers = ch.get("headers", {})
            if not isinstance(headers, dict):
                headers = {}
            ok, status = http_post_json(
                url,
                {
                    "kind": "securityclaw_scan",
                    "summary": message,
                    "report": report,
                },
                headers={str(k): str(v) for k, v in headers.items()},
            )
            results.append({"type": "webhook", "ok": ok, "status": status})
        elif ctype == "stdout":
            print("SecurityClaw notification (stdout):")
            print(message)
            results.append({"type": "stdout", "ok": True, "status": "printed"})
        else:
            results.append({"type": ctype or "unknown", "ok": False, "status": "unsupported_channel"})

    delivered = any(bool(r.get("ok")) for r in results)
    if not delivered:
        print("SecurityClaw notification (stdout fallback):")
        print(message)
        results.append({"type": "stdout-fallback", "ok": True, "status": "printed_no_delivery"})

    return results


def build_skill_snapshot(skills_dir: Path) -> Dict[str, str]:
    snap: Dict[str, str] = {}
    for sp in skill_dirs(skills_dir):
        snap[sp.name] = compute_skill_hash(sp)
    return snap


def load_watch_state(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    raw = data.get("skills", {})
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}


def save_watch_state(path: Path, snapshot: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ts": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "skills": snapshot,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def snapshot_diff(prev: Dict[str, str], curr: Dict[str, str]) -> Tuple[List[str], List[str], List[str]]:
    added = sorted(k for k in curr if k not in prev)
    changed = sorted(k for k in curr if k in prev and curr[k] != prev[k])
    removed = sorted(k for k in prev if k not in curr)
    return added, changed, removed


def append_monthly_scan_log(report_dir: Path, now_local: dt.datetime) -> Path:
    logs_dir = report_dir / "Scan_Logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    month_name = now_local.strftime("%B")
    log_file = logs_dir / f"{month_name}.log"
    line = f"scan completed {now_local:%m-%d-%y %H:%M:%S}\n"
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(line)
    return log_file


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Scan OpenClaw skills for risky patterns")
    ap.add_argument("--skills-dir", required=True, help="Path to skills directory (e.g., ~/.openclaw/skills)")
    ap.add_argument("--out", help="Optional extra JSON output path (legacy compatibility)")
    ap.add_argument(
        "--report-dir",
        default=str(DEFAULT_REPORT_DIR),
        help="Directory for SecurityClaw scan reports (default: ~/.openclaw/SecurityClaw_Scans)",
    )
    ap.add_argument("--no-markdown", action="store_true", help="Disable markdown report output")
    ap.add_argument("--quarantine", action="store_true", help="Move quarantine candidates to quarantine dir")
    ap.add_argument("--quarantine-dir", default=str(DEFAULT_QUARANTINE_DIR))
    ap.add_argument(
        "--allowlist",
        default=str(DEFAULT_ALLOWLIST),
        help="Allowlist JSON path (default: ~/.openclaw/securityclaw-allowlist.json)",
    )
    ap.add_argument("--summary-limit", type=int, default=5, help="Top findings to print in user summary")
    ap.add_argument(
        "--write-reports",
        choices=["always", "on-findings", "never"],
        default="always",
        help="Report file write mode (default: always)",
    )
    ap.add_argument(
        "--notify-config",
        default=str(DEFAULT_NOTIFY_CONFIG),
        help="Notification config JSON path (default: ~/.openclaw/securityclaw-notify.json)",
    )
    ap.add_argument(
        "--notify-on",
        choices=["quarantine", "always", "never"],
        default="quarantine",
        help="When to send notifications (default: quarantine)",
    )
    ap.add_argument("--watch", action="store_true", help="Watch skills directory and auto-scan on new/changed skills")
    ap.add_argument("--watch-interval", type=int, default=30, help="Watch polling interval in seconds")
    ap.add_argument(
        "--watch-state",
        default=str(DEFAULT_WATCH_STATE),
        help="Watch state file path (default: ~/.openclaw/SecurityClaw_Scans/watch-state.json)",
    )
    ap.add_argument(
        "--watch-scan-on-start",
        action="store_true",
        help="In watch mode, also run an immediate initial scan before polling loop",
    )
    ap.add_argument(
        "--watch-max-cycles",
        type=int,
        default=0,
        help="For testing: stop watch mode after N cycles (0 = run forever)",
    )
    return ap.parse_args(argv)


def run_scan(args: argparse.Namespace, scan_context: Optional[Dict] = None) -> Dict:
    now_utc = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    now_local = dt.datetime.now().replace(microsecond=0)

    skills_dir = Path(os.path.expanduser(args.skills_dir)).resolve()
    quarantine_dir = Path(os.path.expanduser(args.quarantine_dir)).resolve()
    report_dir = Path(os.path.expanduser(args.report_dir)).resolve()
    allowlist_path = Path(os.path.expanduser(args.allowlist)).resolve()
    notify_config_path = Path(os.path.expanduser(args.notify_config)).resolve()
    out_arg = getattr(args, "out", None)
    no_markdown = bool(getattr(args, "no_markdown", False))
    write_mode = str(getattr(args, "write_reports", "always"))
    notify_on = str(getattr(args, "notify_on", "quarantine"))

    allow_entries = load_allowlist(allowlist_path)
    if scan_context is None:
        scan_context = {
            "mode": "manual",
            "reason": "manual",
            "newSkills": [],
            "changedSkills": [],
        }

    report = {
        "ts": now_utc.isoformat().replace("+00:00", "Z"),
        "skillsDir": str(skills_dir),
        "quarantineDir": str(quarantine_dir),
        "allowlist": str(allowlist_path),
        "notifyConfig": str(notify_config_path),
        "scanContext": scan_context,
        "reportFiles": {"json": "", "markdown": "", "eli5": ""},
        "results": [],
        "summary": {"total": 0, "bySeverity": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}},
        "actions": [],
        "notifications": [],
    }

    sdirs = skill_dirs(skills_dir)
    report["summary"]["total"] = len(sdirs)

    for sp in sdirs:
        meta = SkillMeta(name=sp.name, path=sp, digest=compute_skill_hash(sp))
        result = evaluate_skill(meta, skills_dir, allow_entries, now_local)
        report["results"].append(result)

        sev = result["severity"]
        report["summary"]["bySeverity"][sev] = report["summary"]["bySeverity"].get(sev, 0) + 1

        if args.quarantine and result["recommendation"] == "quarantine":
            moved_to = quarantine_skill(sp, quarantine_dir)
            action = {
                "action": "quarantine",
                "skill": result["skill"],
                "movedTo": str(moved_to),
                "hash": result["hash"],
                "reason": "high-confidence executable risk",
            }
            report["actions"].append(action)
            append_quarantine_index(
                quarantine_dir,
                {
                    "ts": now_utc.isoformat().replace("+00:00", "Z"),
                    "skill": result["skill"],
                    "hash": result["hash"],
                    "srcPath": result["path"],
                    "destPath": str(moved_to),
                    "action": "quarantine",
                    "reason": action["reason"],
                },
            )

    should_write_reports = (
        write_mode == "always" or (write_mode == "on-findings" and has_reportable_findings(report))
    ) and write_mode != "never"

    json_path: Optional[Path] = None
    md_path: Optional[Path] = None
    if should_write_reports:
        json_path, md_path, _ = allocate_report_paths(report_dir, now_local)
        report["reportFiles"]["json"] = str(json_path)
        report["reportFiles"]["markdown"] = str(md_path)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        if not no_markdown:
            md_path.write_text(render_markdown_report(report), encoding="utf-8")

        if any(r.get("recommendation") == "quarantine" for r in report["results"]):
            eli5_path = md_path.with_name(md_path.stem + "-ELI5.md")
            eli5_path.write_text(render_eli5_summary(report), encoding="utf-8")
            report["reportFiles"]["eli5"] = str(eli5_path)

    # Explicit output path is honored even when default report writing is skipped.
    if out_arg:
        out_path = Path(os.path.expanduser(out_arg)).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["reportFiles"]["extraJsonOut"] = str(out_path)

    # Maintain monthly scan log for both manual and auto scans.
    log_path = append_monthly_scan_log(report_dir=report_dir, now_local=now_local)
    report["scanLog"] = str(log_path)

    notification_results = send_notifications(report, notify_config_path=notify_config_path, notify_on=notify_on)
    if notification_results:
        report["notifications"] = notification_results
        # Persist notification status in saved reports when files exist.
        if json_path is not None:
            json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        if out_arg:
            out_path = Path(os.path.expanduser(out_arg)).resolve()
            out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        if md_path is not None and not no_markdown:
            md_path.write_text(render_markdown_report(report), encoding="utf-8")
        if report["reportFiles"].get("eli5"):
            eli5_path = Path(report["reportFiles"]["eli5"])
            eli5_path.write_text(render_eli5_summary(report), encoding="utf-8")

    # Persist scan log path into report file as final write.
    if json_path is not None:
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if out_arg:
        out_path = Path(os.path.expanduser(out_arg)).resolve()
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if md_path is not None and not no_markdown:
        md_path.write_text(render_markdown_report(report), encoding="utf-8")

    return report


def run_watch(args: argparse.Namespace) -> int:
    skills_dir = Path(os.path.expanduser(args.skills_dir)).resolve()
    state_path = Path(os.path.expanduser(args.watch_state)).resolve()
    interval = max(5, int(args.watch_interval))
    max_cycles = max(0, int(args.watch_max_cycles))

    prev = load_watch_state(state_path)
    if not prev:
        prev = build_skill_snapshot(skills_dir)
        save_watch_state(state_path, prev)

    watch_args = argparse.Namespace(**vars(args))
    watch_args.write_reports = "on-findings"

    if args.watch_scan_on_start:
        start_context = {
            "mode": "auto",
            "reason": "watch_start",
            "newSkills": [],
            "changedSkills": [],
        }
        report = run_scan(watch_args, scan_context=start_context)
        print_user_summary(report, summary_limit=max(1, args.summary_limit))

    print(f"SecurityClaw watch mode active. interval={interval}s skills_dir={skills_dir}")
    cycles = 0
    while True:
        time.sleep(interval)
        curr = build_skill_snapshot(skills_dir)
        added, changed, removed = snapshot_diff(prev, curr)
        if added or changed:
            changed_set = ", ".join(added + changed)
            print(f"Detected new/changed skills: {changed_set}")
            cycle_args = argparse.Namespace(**vars(watch_args))
            # Always notify when a new skill is scanned.
            if added:
                cycle_args.notify_on = "always"
            context = {
                "mode": "auto",
                "reason": "new_or_changed_skill",
                "newSkills": added,
                "changedSkills": changed,
            }
            report = run_scan(cycle_args, scan_context=context)
            print_user_summary(report, summary_limit=max(1, args.summary_limit))
        elif removed:
            print(f"Detected removed skills: {', '.join(removed)}")

        if curr != prev:
            save_watch_state(state_path, curr)
        prev = curr

        cycles += 1
        if max_cycles and cycles >= max_cycles:
            print(f"Stopping watch mode after {cycles} cycle(s).")
            return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.watch:
        return run_watch(args)

    manual_context = {
        "mode": "manual",
        "reason": "manual_cli",
        "newSkills": [],
        "changedSkills": [],
    }
    report = run_scan(args, scan_context=manual_context)
    print_user_summary(report, summary_limit=max(1, args.summary_limit))

    high_found = any(
        severity_rank(r["severity"]) >= SEVERITY_ORDER["high"] and r.get("recommendation") == "quarantine"
        for r in report["results"]
    )
    return 2 if high_found else 0


if __name__ == "__main__":
    raise SystemExit(main())
