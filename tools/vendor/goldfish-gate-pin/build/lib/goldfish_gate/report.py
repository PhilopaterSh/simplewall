"""Human and machine readable reports for goldfish-gate runs."""

from __future__ import annotations

import json

from .check import FAIL, WAIVED, WARN, Finding, Source


def summarize(findings: list[Finding]) -> str:
    fails = sum(1 for f in findings if f.severity == FAIL)
    warns = sum(1 for f in findings if f.severity == WARN)
    waived = sum(1 for f in findings if f.severity == WAIVED)
    base = f"{len(findings)} finding(s): {fails} failure(s), {warns} warning(s)"
    if waived:
        base += f", {waived} waived"
    return base


def format_text(findings: list[Finding]) -> str:
    lines: list[str] = []
    ordered = sorted(
        findings,
        key=lambda f: (f.severity == WAIVED, f.severity != FAIL, f.code, f.message),
    )
    for f in ordered:
        where = f" [{f.file}:{f.line}]" if f.file else ""
        lines.append(f"{f.severity}  {f.code}: {f.message}{where}")
    lines.append(summarize(findings))
    return "\n".join(lines)


def format_json(findings: list[Finding]) -> str:
    payload = {
        "findings": [
            {
                "severity": f.severity,
                "code": f.code,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "key": f.key,
            }
            for f in findings
        ],
        "summary": summarize(findings),
    }
    return json.dumps(payload, indent=2)


def format_markdown(design: Source, spec: Source, plan: Source, tasks: Source, findings: list[Finding]) -> str:
    """A traceability matrix plus the findings list, ready to paste into a PR."""
    from .ids import DECISION_PREFIXES, RISK_PREFIXES, REQUIREMENT_PREFIXES, ids_of_kind

    spec_ids = set(spec.ids)
    plan_ids = set(plan.ids)
    tasks_ids = set(tasks.ids)

    rows: list[str] = []
    for key in design.ids:
        kind = key.split("-")[0]
        if kind in REQUIREMENT_PREFIXES:
            dest = "spec + tasks"
            covered = key in spec_ids and key in tasks_ids
        elif kind in DECISION_PREFIXES:
            dest = "plan"
            covered = key in plan_ids
        elif kind in RISK_PREFIXES:
            dest = "plan or spec"
            covered = key in plan_ids or key in spec_ids
        else:
            dest = "-"
            covered = True
        rows.append(f"| {key} | {dest} | {'covered' if covered else 'NOT COVERED'} |")

    lines: list[str] = [
        "## goldfish-gate traceability report",
        "",
        f"Design source: `{design.name}`",
        "",
        "| Key | Required destination | Status |",
        "| --- | --- | --- |",
        *rows,
        "",
        "### Findings",
        "",
    ]
    if not findings:
        lines.append("None. The contract holds.")
    else:
        for f in sorted(findings, key=lambda x: (x.severity != FAIL, x.code)):
            where = f" (`{f.file}:{f.line}`)" if f.file else ""
            lines.append(f"- **{f.severity}** {f.code}: {f.message}{where}")
    lines.append("")
    lines.append(summarize(findings))
    return "\n".join(lines)
