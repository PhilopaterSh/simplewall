"""Scaffold a goldfish-gate feature chain.

`goldfish init <dir>` writes five connected skeletons (design, handoff,
spec, plan, tasks). The design starts NOT approved and the key table holds
placeholders, so `goldfish check` fails until the chain is genuinely
coherent: the gate bites from the first minute instead of being retrofitted.
"""

from __future__ import annotations

from pathlib import Path

DESIGN = """# Design: <feature name>

> Status: DRAFT, NOT approved. The gate stays red until a human records the
> approval here (revision + approver). Nothing downstream is generated
> before that.

## Problem and intended outcomes

<!-- Observable user or system outcomes, each with a way to tell whether it occurred. -->

## In scope and out of scope

<!-- Explicit feature boundaries and prohibited adjacent work. -->

## User journeys and behavior

<!-- Primary flows, error cases, permissions, edge cases. -->

## Constraints and quality attributes

<!-- Performance, reliability, privacy, security (SEC-xx), operations, migration. -->

## Approved decisions

<!-- Architecture boundaries and decisions (DEC-xx) with one-line justifications. -->

## Risks and open questions

<!-- Accepted risks (RSK-xx) with owner + gate; blockers that must resolve pre-implementation. -->

## Traceability Key

<!-- The single source of key definitions. Downstream artifacts reference these keys, never define new ones. -->

| Key | Meaning |
| --- | --- |
| FR-01 | <functional requirement> |
| FR-02 | <functional requirement> |
| NFR-01 | <quality attribute> |
| SEC-01 | <security requirement> |
| DEC-01 | <approved decision> |
| RSK-01 | <accepted risk, with owner and gate> |
"""

HANDOFF = """# Handoff: <feature name>

> Generated from design.md via the egm-handoff skill once the design is
> approved. Validate with: goldfish handoff handoff.md

## Problem and intended outcomes

## In scope and out of scope

## User journeys and behavior

## Acceptance criteria

<!-- Given/When/Then scenarios referencing FR/NFR/SEC keys. -->

## Constraints and quality attributes

## Approved decisions

## Risks and open questions

## Traceability Key

<!-- Copy the table from the approved design verbatim. -->

| Key | Meaning |
| --- | --- |
| FR-01 | <functional requirement> |
| FR-02 | <functional requirement> |
| NFR-01 | <quality attribute> |
| SEC-01 | <security requirement> |
| DEC-01 | <approved decision> |
| RSK-01 | <accepted risk, with owner and gate> |
"""

SPEC = """# Specification: <feature name>

Derived from handoff.md. Preserve scope, identifiers, acceptance criteria,
decisions, and unresolved gates; do not re-interpret settled choices.

## User stories

<!-- US1: as a <role> I <do> so that <outcome> (FR-01). -->

## Acceptance scenarios

<!-- AS1: Given <state> when <action> then <observable> (FR-01, SEC-01). -->

## Success criteria
"""

PLAN = """# Implementation Plan: <feature name>

Derived from spec.md; preserves the approved decisions.

## Approach

<!-- How it is built; every DEC-xx reflected here by reference. -->

## Verification strategy

<!-- How each NFR/SEC key is proven: tests, benchmarks, reviews. -->

## Risks carried forward

<!-- RSK-xx stays acknowledged here; carry it, never resolve it silently. -->
"""

TASKS = """# Tasks: <feature name>

<!-- Every task references its key parent, or carries [enabling] for
explicitly approved supporting work. The enabling budget defaults to 2. -->

- [ ] T001 <implements FR-01> (FR-01)
- [ ] T002 <implements FR-02> (FR-02)
- [ ] T003 <supporting work> [enabling]
"""

CHAIN: dict[str, str] = {
    "design.md": DESIGN,
    "handoff.md": HANDOFF,
    "spec.md": SPEC,
    "plan.md": PLAN,
    "tasks.md": TASKS,
}


def run_init(target: Path) -> list[str]:
    """Create the 5-file chain. Refuse to overwrite any existing file."""
    target = Path(target)
    existing = sorted(name for name in CHAIN if (target / name).exists())
    if existing:
        raise FileExistsError(f"refusing to overwrite existing file(s): {', '.join(existing)}")
    target.mkdir(parents=True, exist_ok=True)
    created: list[str] = []
    for name, content in CHAIN.items():
        path = target / name
        path.write_text(content, encoding="utf-8", newline="\n")
        created.append(str(path))
    return created
