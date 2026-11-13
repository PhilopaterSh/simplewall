"""The goldfish-gate contract checks.

The contract: an approved design is the single source of traceability keys.
Every requirement must reach the spec and the tasks, every approved decision
must be reflected in the plan, accepted risks must surface somewhere, and
nothing downstream may invent a key the design never approved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .ids import (
    ALL_PREFIXES,
    DECISION_PREFIXES,
    ID_PATTERN,
    RISK_PREFIXES,
    REQUIREMENT_PREFIXES,
    Hit,
    ids_of_kind,
    scan,
    strip_fenced_blocks,
    unique_ids,
)

FAIL = "FAIL"
WARN = "WARN"
WAIVED = "WAIVED"

#: Task bullets must either reference a traceability key or carry the
#: ``[enabling]`` tag for explicitly approved supporting work.
TASK_LINE = re.compile(r"^\s*[-*]\s+\[[ xX]?\]")
ENABLING_TAG = "[enabling]"

#: A key *definition* is a Traceability Key table row whose first cell is the
#: key (bold markers tolerated). Prose mentions and list items elsewhere in
#: the design are references, not definitions: the table is the canonical
#: definition home per the handoff contract, so only a second table row can
#: be a true duplicate.
DEFINITION_LINE = re.compile(
    r"^\s*\|\s*(?:\*\*)?((?:" + "|".join(ALL_PREFIXES) + r")-\d{2,3})\b"
)


@dataclass
class Finding:
    severity: str
    code: str
    message: str
    file: str = ""
    line: int = 0
    key: str = ""


@dataclass
class Source:
    """One checked markdown document and its extracted keys."""

    name: str
    text: str
    hits: list[Hit] = field(default_factory=list)
    ids: list[str] = field(default_factory=list)


def load_source(name: str, text: str) -> Source:
    hits = scan(text)
    return Source(name=name, text=text, hits=hits, ids=unique_ids(hits))


def run_checks(
    design: Source, spec: Source, plan: Source, tasks: Source, max_enabling: int = 2
) -> list[Finding]:
    findings: list[Finding] = []

    design_reqs = ids_of_kind(design.ids, REQUIREMENT_PREFIXES)
    design_decs = ids_of_kind(design.ids, DECISION_PREFIXES)
    design_rsks = ids_of_kind(design.ids, RISK_PREFIXES)
    design_all = set(design.ids)

    # 1. The design must declare traceability keys at all.
    if not design_all:
        findings.append(
            Finding(
                FAIL,
                "no-keys",
                "the design declares no traceability keys (FR-xx/NFR-xx/SEC-xx/DEC-xx/RSK-xx); "
                "add a Traceability Key section before generating downstream artifacts",
                design.name,
            )
        )
        return findings

    # 2. Duplicated key *definitions* inside the design are ambiguous.
    #    Prose references do not count; two definition lines for one key do.
    first_definition: dict[str, int] = {}
    for lineno, line in enumerate(strip_fenced_blocks(design.text).splitlines(), start=1):
        m = DEFINITION_LINE.match(line)
        if not m:
            continue
        key = m.group(1)
        if key in first_definition:
            findings.append(
                Finding(
                    WARN,
                    "duplicate-key",
                    f"{key} is defined more than once in the design; keep one canonical definition",
                    design.name,
                    lineno,
                )
            )
        else:
            first_definition[key] = lineno

    # 3. Every requirement must reach the spec and the tasks.
    for rid in sorted(design_reqs - set(spec.ids)):
        findings.append(
            Finding(
                FAIL,
                "missing-in-spec",
                f"{rid} is defined in the design but never covered by the spec",
                spec.name,
                key=rid,
            )
        )
    for rid in sorted(design_reqs - set(tasks.ids)):
        findings.append(
            Finding(
                FAIL,
                "missing-in-tasks",
                f"{rid} is defined in the design but no task implements it",
                tasks.name,
                key=rid,
            )
        )

    # 4. Approved decisions must be reflected in the plan.
    for did in sorted(design_decs - set(plan.ids)):
        findings.append(
            Finding(
                FAIL,
                "missing-in-plan",
                f"{did} is an approved design decision but the plan never reflects it",
                plan.name,
                key=did,
            )
        )

    # 5. Accepted risks must be acknowledged in plan or spec.
    for rid in sorted(design_rsks - (set(plan.ids) | set(spec.ids))):
        findings.append(
            Finding(
                WARN,
                "risk-unacknowledged",
                f"{rid} is an accepted risk in the design but neither the plan nor the spec acknowledges it",
                design.name,
                key=rid,
            )
        )

    # 6. No invented scope: downstream keys must exist in the approved design.
    #    Attribute each foreign key to the first downstream file that uses it.
    foreign: dict[str, tuple[str, int]] = {}
    for src in (spec, plan, tasks):
        for h in src.hits:
            if h.id not in design_all and h.id not in foreign:
                foreign[h.id] = (src.name, h.line)
    for key in sorted(foreign):
        where_file, where_line = foreign[key]
        findings.append(
            Finding(
                FAIL,
                "invented-key",
                f"{key} is referenced downstream but the approved design never defines it; "
                "amend and re-approve the design first",
                where_file,
                where_line,
                key=key,
            )
        )

    # 7. Every task traces to a key or is an explicitly approved enabling task.
    enabling_count = 0
    for lineno, line in enumerate(tasks.text.splitlines(), start=1):
        if not TASK_LINE.match(line):
            continue
        if ENABLING_TAG in line.lower():
            enabling_count += 1
            continue
        if not ID_PATTERN.search(line):
            findings.append(
                Finding(
                    WARN,
                    "orphan-task",
                    f"task has no requirement parent and no [enabling] tag: {line.strip()[:80]}",
                    tasks.name,
                    lineno,
                )
            )

    # 8. The [enabling] escape hatch has a volume budget; beyond it the hatch
    #    has become a bypass.
    if enabling_count > max_enabling:
        findings.append(
            Finding(
                WARN,
                "enabling-budget",
                f"{enabling_count} [enabling] tasks exceed the budget of {max_enabling}; "
                "at this volume enabling work is scope creep, route it through the design",
                tasks.name,
            )
        )

    return findings


def has_failures(findings: list[Finding]) -> bool:
    return any(f.severity == FAIL for f in findings)
