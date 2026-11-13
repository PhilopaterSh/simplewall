"""Command line interface for goldfish-gate.

Exit codes: 0 = contract holds (warnings/waivers allowed), 1 = failures
found, 2 = usage or IO error.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .check import has_failures, load_source, run_checks
from .handoff import check_handoff
from .init import run_init
from .report import format_json, format_markdown, format_text
from .waivers import apply_waivers, collect_waivers

EXIT_OK = 0
EXIT_FAILURES = 1
EXIT_USAGE = 2


def _read(path: str) -> str:
    try:
        # utf-8-sig transparently strips a leading BOM that Windows editors
        # often add; files without one read identically.
        with open(path, "r", encoding="utf-8-sig") as fh:
            return fh.read()
    except OSError as exc:
        print(f"goldfish: cannot read {path}: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)
    except UnicodeDecodeError as exc:
        print(
            f"goldfish: {path} is not valid UTF-8 (re-save the file as UTF-8): {exc}",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_USAGE)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="goldfish",
        description=(
            "Machine-checked traceability between an approved design and "
            "spec-driven execution (spec.md, plan.md, tasks.md)."
        ),
    )
    parser.add_argument("--version", action="version", version=f"goldfish-gate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="check the design -> spec -> plan -> tasks contract")
    p_check.add_argument("design", help="approved design document (markdown)")
    p_check.add_argument("spec", help="generated spec.md")
    p_check.add_argument("plan", help="generated plan.md")
    p_check.add_argument("tasks", help="generated tasks.md")
    p_check.add_argument(
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="report format (default: text)",
    )
    p_check.add_argument(
        "--max-enabling",
        type=int,
        default=2,
        help="maximum [enabling] tasks allowed before a warning (default: 2)",
    )
    p_check.add_argument(
        "--no-waivers",
        action="store_true",
        help="ignore inline waivers entirely; every matching finding stays active",
    )

    p_handoff = sub.add_parser("handoff", help="validate one handoff package file")
    p_handoff.add_argument("file", help="handoff.md to validate")
    p_handoff.add_argument(
        "--format", choices=("text", "json"), default="text", help="report format (default: text)"
    )

    p_init = sub.add_parser("init", help="scaffold a 5-file feature chain in a directory")
    p_init.add_argument("target", nargs="?", default=".", help="target directory (default: .)")

    p_ids = sub.add_parser("ids", help="list traceability IDs found in one markdown file")
    p_ids.add_argument("file", help="markdown file to scan")
    return parser


def _cmd_check(args: argparse.Namespace) -> int:
    design = load_source(args.design, _read(args.design))
    spec = load_source(args.spec, _read(args.spec))
    plan = load_source(args.plan, _read(args.plan))
    tasks = load_source(args.tasks, _read(args.tasks))

    findings = run_checks(design, spec, plan, tasks, max_enabling=args.max_enabling)
    waived = []
    if not args.no_waivers:
        waivers = collect_waivers([design, spec, plan, tasks])
        findings, waived = apply_waivers(findings, waivers, date.today())

    if args.format == "json":
        print(format_json(findings))
    elif args.format == "markdown":
        print(format_markdown(design, spec, plan, tasks, findings + waived))
    else:
        print(format_text(findings))
    return EXIT_FAILURES if has_failures(findings) else EXIT_OK


def _cmd_handoff(args: argparse.Namespace) -> int:
    text = _read(args.file)
    findings = check_handoff(text, args.file)
    if args.format == "json":
        print(format_json(findings))
    else:
        print(format_text(findings))
    return EXIT_FAILURES if has_failures(findings) else EXIT_OK


def _cmd_init(args: argparse.Namespace) -> int:
    try:
        created = run_init(Path(args.target))
    except FileExistsError as exc:
        print(f"goldfish: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print("created feature chain:")
    for path in created:
        print(f"  {path}")
    print(
        "next: fill design.md, get human approval recorded in it, "
        "then: goldfish check design.md spec.md plan.md tasks.md"
    )
    return EXIT_OK


def _cmd_ids(args: argparse.Namespace) -> int:
    text = _read(args.file)
    from .ids import scan, unique_ids

    hits = scan(text)
    ids = unique_ids(hits)
    if not ids:
        print("no traceability IDs found")
        return EXIT_OK
    first_line: dict[str, int] = {}
    for h in hits:
        first_line.setdefault(h.id, h.line)
    for key in ids:
        print(f"{key}  (line {first_line[key]})")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "check":
        return _cmd_check(args)
    if args.command == "handoff":
        return _cmd_handoff(args)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "ids":
        return _cmd_ids(args)
    return EXIT_USAGE  # unreachable: subparsers are required
