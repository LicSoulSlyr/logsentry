from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import __version__
from .detectors import Config, run_all
from .models import Severity
from .parsers import read_auth_log, read_web_log
from .report import render_json, render_markdown, render_text
from .rules import RULES

SEVERITIES = [s.name.lower() for s in Severity]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentry",
        description="Detect attacks in Linux auth logs and web access logs, mapped to MITRE ATT&CK.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyze log files and report findings")
    scan.add_argument("--auth", action="append", default=[], metavar="FILE",
                      help="Linux auth log (auth.log / secure), may be .gz; repeatable")
    scan.add_argument("--web", action="append", default=[], metavar="FILE",
                      help="Apache/Nginx combined access log, may be .gz; repeatable")
    scan.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")
    scan.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    scan.add_argument("--min-severity", choices=SEVERITIES, default="low",
                      help="hide findings below this severity (default: low)")
    scan.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                      help="exit with status 2 if any finding is at or above SEVERITY (for CI/cron)")
    scan.add_argument("--year", type=int, default=datetime.now(timezone.utc).year,
                      help="year for syslog timestamps, which omit it (default: current year)")
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colors")

    tune = scan.add_argument_group("detection thresholds")
    tune.add_argument("--bruteforce-threshold", type=int, default=Config.bruteforce_threshold,
                      help="failed SSH logins from one IP that count as brute force (default: %(default)s)")
    tune.add_argument("--bruteforce-window", type=int, default=5, metavar="MINUTES",
                      help="time window for the brute force threshold (default: %(default)s)")
    tune.add_argument("--spray-users", type=int, default=Config.spray_min_users,
                      help="distinct usernames from one IP that count as spraying (default: %(default)s)")
    tune.add_argument("--enum-threshold", type=int, default=Config.enum_404_threshold,
                      help="404s from one IP per minute that count as enumeration (default: %(default)s)")

    sub.add_parser("rules", help="list detection rules and their MITRE ATT&CK mapping")
    return p


def cmd_rules() -> int:
    print(f"{'ID':<9}{'MITRE':<11}{'Tactic':<22}Title")
    for r in RULES.values():
        print(f"{r.id:<9}{r.mitre_id:<11}{r.tactic:<22}{r.title}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if not args.auth and not args.web:
        print("logsentry: error: give at least one --auth or --web log", file=sys.stderr)
        return 1

    auth, web, sources = [], [], []
    try:
        for path in args.auth:
            events, stats = read_auth_log(path, args.year)
            auth += events
            sources.append(stats)
        for path in args.web:
            events, stats = read_web_log(path)
            web += events
            sources.append(stats)
    except OSError as exc:
        print(f"logsentry: error: {exc}", file=sys.stderr)
        return 1

    # Multiple files of one kind are merged into one timeline before detection.
    auth.sort(key=lambda e: e.timestamp)
    web.sort(key=lambda e: e.timestamp)

    cfg = Config(
        bruteforce_threshold=args.bruteforce_threshold,
        bruteforce_window=timedelta(minutes=args.bruteforce_window),
        spray_min_users=args.spray_users,
        enum_404_threshold=args.enum_threshold,
    )
    floor = Severity.parse(args.min_severity)
    findings = [f for f in run_all(auth, web, cfg) if f.severity >= floor]

    if args.format == "json":
        report = render_json(findings, sources)
    elif args.format == "markdown":
        report = render_markdown(findings, sources)
    else:
        color = not args.no_color and not args.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        if color and os.name == "nt":
            os.system("")  # enables ANSI escape processing in the legacy Windows console
        report = render_text(findings, sources, color=color)

    if args.output:
        out = Path(args.output)
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(report, encoding="utf-8")
        except OSError as exc:
            print(f"logsentry: error: cannot write report: {exc}", file=sys.stderr)
            return 1
        print(f"Report written to {args.output} ({len(findings)} findings)", file=sys.stderr)
    else:
        sys.stdout.reconfigure(errors="replace")
        sys.stdout.write(report)

    if args.fail_on and any(f.severity >= Severity.parse(args.fail_on) for f in findings):
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        return cmd_rules()
    return cmd_scan(args)
