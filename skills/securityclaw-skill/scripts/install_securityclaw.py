#!/usr/bin/env python3
"""Install SecurityClaw scheduled auto-scan service.

- macOS: configures launchd LaunchAgent
- Linux: configures systemd user service

Linux special handling:
- If systemd/systemctl is missing, installer notifies user, prints install command,
  and offers to run it automatically.
"""

from __future__ import annotations

import argparse
import os
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional
from xml.sax.saxutils import escape

DEFAULT_OPENCLAW_ROOT = Path.home() / ".openclaw"
DEFAULT_REPORT_DIR = DEFAULT_OPENCLAW_ROOT / "SecurityClaw_Scans"
DEFAULT_NOTIFY_CONFIG = DEFAULT_OPENCLAW_ROOT / "securityclaw-notify.json"
LAUNCHD_LABEL = "com.openclaw.securityclaw.watch"
SYSTEMD_SERVICE_NAME = "securityclaw-watch.service"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Install SecurityClaw auto-scan scheduler")
    ap.add_argument("--skills-dir", default=str(DEFAULT_OPENCLAW_ROOT / "skills"), help="OpenClaw skills directory")
    ap.add_argument(
        "--notify-config",
        default=str(DEFAULT_NOTIFY_CONFIG),
        help="Notification config path for scanner runtime",
    )
    ap.add_argument(
        "--report-dir",
        default=str(DEFAULT_REPORT_DIR),
        help="SecurityClaw report directory",
    )
    ap.add_argument("--watch-interval", type=int, default=30, help="Watch polling interval in seconds")
    ap.add_argument("--python-bin", default=sys.executable or "python3", help="Python interpreter for scanner")
    ap.add_argument(
        "--install-scheduler",
        dest="install_scheduler",
        action="store_true",
        default=True,
        help="Install and start scheduler after writing unit files (default: true)",
    )
    ap.add_argument(
        "--no-install-scheduler",
        dest="install_scheduler",
        action="store_false",
        help="Only write scheduler files; do not load/enable",
    )
    ap.add_argument(
        "--offer-install",
        action="store_true",
        default=True,
        help="On Linux when systemd missing, offer to install it (default: true)",
    )
    ap.add_argument(
        "--no-offer-install",
        dest="offer_install",
        action="store_false",
        help="Do not offer auto-install when Linux scheduler dependency is missing",
    )
    ap.add_argument("--assume-yes", action="store_true", help="Auto-confirm prompts")
    ap.add_argument("--dry-run", action="store_true", help="Print actions without changing system")
    return ap.parse_args()


def run(cmd: List[str], *, dry_run: bool, check: bool = True) -> int:
    printable = " ".join(shlex.quote(x) for x in cmd)
    print(f"$ {printable}")
    if dry_run:
        return 0
    proc = subprocess.run(cmd)
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {printable}")
    return proc.returncode


def ensure_dir(path: Path, dry_run: bool) -> None:
    if dry_run:
        print(f"[dry-run] mkdir -p {path}")
        return
    path.mkdir(parents=True, exist_ok=True)


def write_text(path: Path, text: str, dry_run: bool) -> None:
    if dry_run:
        print(f"[dry-run] write {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def scanner_command(args: argparse.Namespace, scanner_path: Path) -> List[str]:
    return [
        args.python_bin,
        str(scanner_path),
        "--skills-dir",
        str(Path(os.path.expanduser(args.skills_dir)).resolve()),
        "--notify-config",
        str(Path(os.path.expanduser(args.notify_config)).resolve()),
        "--watch",
        "--watch-scan-on-start",
        "--watch-interval",
        str(max(5, int(args.watch_interval))),
        "--write-reports",
        "on-findings",
    ]


def render_launchd_plist(cmd: List[str], out_log: Path, err_log: Path, workdir: Path) -> str:
    cmd_xml = "\n".join(f"      <string>{escape(x)}</string>" for x in cmd)
    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "  <dict>\n"
        f"    <key>Label</key><string>{escape(LAUNCHD_LABEL)}</string>\n"
        "    <key>ProgramArguments</key>\n"
        "    <array>\n"
        f"{cmd_xml}\n"
        "    </array>\n"
        f"    <key>WorkingDirectory</key><string>{escape(str(workdir))}</string>\n"
        "    <key>RunAtLoad</key><true/>\n"
        "    <key>KeepAlive</key><true/>\n"
        f"    <key>StandardOutPath</key><string>{escape(str(out_log))}</string>\n"
        f"    <key>StandardErrorPath</key><string>{escape(str(err_log))}</string>\n"
        "  </dict>\n"
        "</plist>\n"
    )


def install_launchd(args: argparse.Namespace, scanner_path: Path) -> int:
    uid = os.getuid()
    launch_agents = Path.home() / "Library" / "LaunchAgents"
    plist_path = launch_agents / f"{LAUNCHD_LABEL}.plist"
    report_dir = Path(os.path.expanduser(args.report_dir)).resolve()
    log_dir = report_dir / "Daemons"
    out_log = log_dir / "securityclaw-watch.out.log"
    err_log = log_dir / "securityclaw-watch.err.log"

    ensure_dir(launch_agents, args.dry_run)
    ensure_dir(log_dir, args.dry_run)

    cmd = scanner_command(args, scanner_path)
    plist = render_launchd_plist(cmd, out_log=out_log, err_log=err_log, workdir=scanner_path.parent)
    write_text(plist_path, plist, args.dry_run)

    print(f"launchd plist written: {plist_path}")
    if not args.install_scheduler:
        print("Scheduler file created. Not loading because --no-install-scheduler was set.")
        print(f"To load manually: launchctl bootstrap gui/{uid} {shlex.quote(str(plist_path))}")
        return 0

    # best-effort unload old definition before bootstrapping
    run(["launchctl", "bootout", f"gui/{uid}", str(plist_path)], dry_run=args.dry_run, check=False)
    run(["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)], dry_run=args.dry_run)
    run(["launchctl", "enable", f"gui/{uid}/{LAUNCHD_LABEL}"], dry_run=args.dry_run, check=False)
    run(["launchctl", "kickstart", "-k", f"gui/{uid}/{LAUNCHD_LABEL}"], dry_run=args.dry_run, check=False)

    print("launchd scheduler installed and started.")
    print(f"Status: launchctl print gui/{uid}/{LAUNCHD_LABEL}")
    return 0


def detect_systemd_install_command() -> Optional[str]:
    if shutil.which("apt-get"):
        return "sudo apt-get update && sudo apt-get install -y systemd"
    if shutil.which("dnf"):
        return "sudo dnf install -y systemd"
    if shutil.which("yum"):
        return "sudo yum install -y systemd"
    if shutil.which("pacman"):
        return "sudo pacman -Sy --noconfirm systemd"
    if shutil.which("zypper"):
        return "sudo zypper --non-interactive install systemd"
    return None


def maybe_install_missing_systemd(args: argparse.Namespace) -> bool:
    cmd = detect_systemd_install_command()

    print("systemd/systemctl was not detected on this Linux host.")
    if cmd:
        print(f"Suggested install command: {cmd}")
    else:
        print("Could not detect package manager for automatic systemd installation.")

    if not args.offer_install:
        return False

    should_install = False
    if args.assume_yes:
        should_install = True
    elif sys.stdin.isatty():
        try:
            answer = input("Install systemd now using the suggested command? [y/N]: ").strip().lower()
            should_install = answer in {"y", "yes"}
        except EOFError:
            should_install = False

    if not should_install:
        print("Skipped automatic systemd installation.")
        return False

    if not cmd:
        print("Cannot auto-install systemd because install command is unknown.")
        return False

    try:
        run(["bash", "-lc", cmd], dry_run=args.dry_run)
    except RuntimeError as exc:
        print(f"Automatic systemd installation failed: {exc}")
        return False

    return shutil.which("systemctl") is not None or args.dry_run


def render_systemd_service(cmd: List[str], workdir: Path, out_log: Path, err_log: Path) -> str:
    exec_cmd = " ".join(shlex.quote(x) for x in cmd)
    return (
        "[Unit]\n"
        "Description=SecurityClaw watch scanner for OpenClaw skills\n"
        "After=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={workdir}\n"
        "Environment=PYTHONUNBUFFERED=1\n"
        f"ExecStart={exec_cmd}\n"
        "Restart=always\n"
        "RestartSec=10\n"
        f"StandardOutput=append:{out_log}\n"
        f"StandardError=append:{err_log}\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def install_systemd(args: argparse.Namespace, scanner_path: Path) -> int:
    if shutil.which("systemctl") is None:
        ok = maybe_install_missing_systemd(args)
        if not ok:
            print("Linux scheduler setup aborted: systemd is required for the supported auto-start method.")
            print("Re-run installer after installing systemd, or run scanner manually in watch mode.")
            return 2

    user_dir = Path.home() / ".config" / "systemd" / "user"
    service_path = user_dir / SYSTEMD_SERVICE_NAME
    report_dir = Path(os.path.expanduser(args.report_dir)).resolve()
    log_dir = report_dir / "Daemons"
    out_log = log_dir / "securityclaw-watch.out.log"
    err_log = log_dir / "securityclaw-watch.err.log"

    ensure_dir(user_dir, args.dry_run)
    ensure_dir(log_dir, args.dry_run)

    cmd = scanner_command(args, scanner_path)
    service_text = render_systemd_service(cmd, workdir=scanner_path.parent, out_log=out_log, err_log=err_log)
    write_text(service_path, service_text, args.dry_run)

    print(f"systemd user service written: {service_path}")
    if not args.install_scheduler:
        print("Service file created. Not enabling because --no-install-scheduler was set.")
        print("To enable manually:")
        print("  systemctl --user daemon-reload")
        print(f"  systemctl --user enable --now {SYSTEMD_SERVICE_NAME}")
        return 0

    run(["systemctl", "--user", "daemon-reload"], dry_run=args.dry_run)
    run(["systemctl", "--user", "enable", "--now", SYSTEMD_SERVICE_NAME], dry_run=args.dry_run)

    print("systemd user scheduler installed and started.")
    print(f"Status: systemctl --user status {SYSTEMD_SERVICE_NAME}")
    print("Optional for running after logout: loginctl enable-linger $USER")
    return 0


def main() -> int:
    args = parse_args()
    scanner_path = (Path(__file__).resolve().parent / "securityclaw_scan.py").resolve()

    if not scanner_path.exists():
        print(f"Scanner script not found: {scanner_path}")
        return 1

    os_name = platform.system().lower()
    if os_name == "darwin":
        return install_launchd(args, scanner_path=scanner_path)
    if os_name == "linux":
        return install_systemd(args, scanner_path=scanner_path)

    print(f"Unsupported OS for scheduler install: {platform.system()}")
    print("Supported: macOS (launchd), Linux (systemd --user)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
