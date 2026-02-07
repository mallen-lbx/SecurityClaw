import datetime as dt
import sys
import tempfile
import types
import unittest
from importlib import util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "skills" / "securityclaw-skill" / "scripts" / "securityclaw_scan.py"

spec = util.spec_from_file_location("securityclaw_scan", SCRIPT_PATH)
scanner = util.module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = scanner
spec.loader.exec_module(scanner)


class SecurityClawScanTests(unittest.TestCase):
    def make_skill(self, skills_root: Path, name: str, files: dict[str, str]) -> Path:
        skill_dir = skills_root / name
        skill_dir.mkdir(parents=True, exist_ok=True)
        for rel, content in files.items():
            target = skill_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return skill_dir

    def test_report_filename_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report_dir = Path(td)
            existing = report_dir / "Security_Scan-02-07-2026-001.json"
            existing.write_text("{}", encoding="utf-8")

            json_path, md_path, base = scanner.allocate_report_paths(
                report_dir,
                dt.datetime(2026, 2, 7, 9, 0, 0),
            )
            self.assertEqual(base, "Security_Scan-02-07-2026-002")
            self.assertEqual(json_path.name, "Security_Scan-02-07-2026-002.json")
            self.assertEqual(md_path.name, "Security_Scan-02-07-2026-002.md")

    def test_doc_mentions_do_not_trigger_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            skills_root = Path(td) / "skills"
            skills_root.mkdir(parents=True, exist_ok=True)
            skill_dir = self.make_skill(
                skills_root,
                "docs-only",
                {
                    "SKILL.md": "Use fetch and curl for docs. Path: ~/.openclaw/skills and /etc/hosts",
                },
            )

            meta = scanner.SkillMeta(
                name="docs-only",
                path=skill_dir,
                digest=scanner.compute_skill_hash(skill_dir),
            )
            result = scanner.evaluate_skill(meta, skills_root, [], dt.datetime(2026, 2, 7, 12, 0, 0))

            self.assertNotEqual(result["recommendation"], "quarantine")
            self.assertTrue(
                all(scanner.severity_rank(f["severity"]) < scanner.SEVERITY_ORDER["high"] for f in result["findings"])
            )

    def test_allowlist_suppresses_rule(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            skills_root = Path(td) / "skills"
            skills_root.mkdir(parents=True, exist_ok=True)
            skill_dir = self.make_skill(
                skills_root,
                "netskill",
                {
                    "script.js": "const x = fetch('https://example.com/data.json');",
                },
            )

            digest = scanner.compute_skill_hash(skill_dir)
            meta = scanner.SkillMeta(name="netskill", path=skill_dir, digest=digest)
            allow_entries = [
                scanner.AllowlistEntry(
                    skill="netskill",
                    hash=digest,
                    rules=["network_egress"],
                    expires="",
                    reason="approved by owner",
                )
            ]
            result = scanner.evaluate_skill(meta, skills_root, allow_entries, dt.datetime(2026, 2, 7, 12, 0, 0))

            self.assertEqual(result["recommendation"], "allow")
            self.assertEqual(result["findingCount"], 0)
            self.assertGreaterEqual(result["suppressedCount"], 1)

    def test_quarantine_proof_has_four_findings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            skills_root = Path(td) / "skills"
            skills_root.mkdir(parents=True, exist_ok=True)
            code = "\n".join(
                [
                    "const a = fetch('https://a.example');",
                    "const b = fetch('https://b.example');",
                    "const c = fetch('https://c.example');",
                    "const d = fetch('https://d.example');",
                    "const e = fetch('https://e.example');",
                ]
            )
            skill_dir = self.make_skill(skills_root, "highrisk", {"index.js": code})
            meta = scanner.SkillMeta(name="highrisk", path=skill_dir, digest=scanner.compute_skill_hash(skill_dir))
            result = scanner.evaluate_skill(meta, skills_root, [], dt.datetime(2026, 2, 7, 12, 0, 0))

            self.assertEqual(result["recommendation"], "quarantine")
            self.assertEqual(len(result.get("quarantineProof", [])), 4)

    def test_run_scan_writes_json_and_markdown_reports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            skills_root = root / "skills"
            report_dir = root / "reports"
            quarantine_dir = root / "quarantine"
            skills_root.mkdir(parents=True, exist_ok=True)

            self.make_skill(skills_root, "safe", {"SKILL.md": "Simple safe skill."})

            args = types.SimpleNamespace(
                skills_dir=str(skills_root),
                out=None,
                report_dir=str(report_dir),
                no_markdown=False,
                quarantine=False,
                quarantine_dir=str(quarantine_dir),
                allowlist=str(root / "missing-allowlist.json"),
                summary_limit=5,
                notify_config=str(root / "missing-notify.json"),
                notify_on="never",
                watch=False,
                watch_interval=30,
                watch_state=str(root / "watch-state.json"),
                watch_scan_on_start=False,
                watch_max_cycles=0,
                write_reports="always",
            )

            report = scanner.run_scan(args)
            json_path = Path(report["reportFiles"]["json"])
            md_path = Path(report["reportFiles"]["markdown"])
            log_path = Path(report["scanLog"])

            self.assertTrue(json_path.exists())
            self.assertTrue(md_path.exists())
            self.assertTrue(log_path.exists())
            self.assertRegex(json_path.name, r"^Security_Scan-\d{2}-\d{2}-\d{4}-\d{3}\.json$")

    def test_notification_message_contains_quarantine_reason(self) -> None:
        report = {
            "summary": {"total": 1},
            "reportFiles": {"markdown": "/tmp/Security_Scan-02-06-2026-001.md"},
            "results": [
                {
                    "skill": "x",
                    "severity": "high",
                    "riskScore": 9.5,
                    "confidence": 0.91,
                    "recommendation": "quarantine",
                    "quarantineProof": [
                        {
                            "rule_id": "network_egress",
                            "file": "x/index.js",
                            "line": 10,
                            "confidence": 0.92,
                        }
                    ],
                }
            ],
        }
        msg = scanner.build_notification_message(report)
        self.assertIn("quarantine alert", msg)
        self.assertIn("network_egress x/index.js:10", msg)

    def test_auto_mode_skips_reports_when_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            skills_root = root / "skills"
            report_dir = root / "reports"
            quarantine_dir = root / "quarantine"
            skills_root.mkdir(parents=True, exist_ok=True)

            self.make_skill(skills_root, "clean", {"SKILL.md": "This is a clean skill with no risky terms."})

            args = types.SimpleNamespace(
                skills_dir=str(skills_root),
                out=None,
                report_dir=str(report_dir),
                no_markdown=False,
                quarantine=False,
                quarantine_dir=str(quarantine_dir),
                allowlist=str(root / "missing-allowlist.json"),
                summary_limit=5,
                notify_config=str(root / "missing-notify.json"),
                notify_on="never",
                watch=False,
                watch_interval=30,
                watch_state=str(root / "watch-state.json"),
                watch_scan_on_start=False,
                watch_max_cycles=0,
                write_reports="on-findings",
            )
            ctx = {"mode": "auto", "reason": "new_or_changed_skill", "newSkills": ["clean"], "changedSkills": []}
            report = scanner.run_scan(args, scan_context=ctx)

            self.assertEqual(report["reportFiles"]["json"], "")
            self.assertEqual(report["reportFiles"]["markdown"], "")
            self.assertTrue(Path(report["scanLog"]).exists())

    def test_scan_log_line_format(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            report_dir = Path(td)
            ts = dt.datetime(2026, 4, 6, 12, 0, 0)
            log_path = scanner.append_monthly_scan_log(report_dir=report_dir, now_local=ts)
            self.assertEqual(log_path.name, "April.log")
            line = log_path.read_text(encoding="utf-8").strip().splitlines()[-1]
            self.assertEqual(line, "scan completed 04-06-26 12:00:00")


if __name__ == "__main__":
    unittest.main()
