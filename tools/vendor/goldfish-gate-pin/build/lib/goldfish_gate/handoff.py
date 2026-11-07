"""Validator for the handoff package: guarding the chain's first link.

The egm-handoff skill generates a handoff from an approved design; this
module makes sure the package itself is complete before Spec Kit consumes
it: an approval marker, all eight required sections, a non-empty
Traceability Key table, and owner/gate evidence for every accepted risk.
"""

from __future__ import annotations

import re

from .check import FAIL, DEFINITION_LINE, Finding
from .ids import strip_fenced_blocks

SECTIONS = [
    "Problem and intended outcomes",
    "In scope and out of scope",
    "User journeys and behavior",
    "Acceptance criteria",
    "Constraints and quality attributes",
    "Approved decisions",
    "Risks and open questions",
    "Traceability Key",
]

_HEADING = re.compile(r"^\s*#{1,6}\s+(.*)$")
_RISK_KEY = re.compile(r"\b(RSK-\d{2,3})\b")
_RISK_EVIDENCE = re.compile(
    r"\b(owner|gate|accepted|acceptance|until|resolution|resolved)\b", re.IGNORECASE
)
_APPROVAL = re.compile(r"\b(revision|approved|approval|sign-off)\b", re.IGNORECASE)


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def check_handoff(text: str, name: str = "handoff.md") -> list[Finding]:
    findings: list[Finding] = []
    clean = strip_fenced_blocks(text)

    headings: list[str] = []
    body: list[tuple[int, str]] = []
    for lineno, line in enumerate(clean.splitlines(), start=1):
        m = _HEADING.match(line)
        if m:
            headings.append(_norm(m.group(1)))
        else:
            body.append((lineno, line))

    # 1. Approval marker: a body line (headings never count, so a bare
    #    "Approved decisions" heading cannot satisfy this).
    if not any(_APPROVAL.search(line) for _, line in body):
        findings.append(
            Finding(
                FAIL,
                "handoff-no-approval",
                "no approval marker: the handoff must record the approved design "
                "revision or the human approval on a body line",
                name,
            )
        )

    # 2. All eight required sections present (normalized substring match so
    #    suffixes like "(Given/When/Then)" are tolerated).
    for section in SECTIONS:
        if not any(_norm(section) in h for h in headings):
            findings.append(
                Finding(
                    FAIL,
                    "handoff-missing-section",
                    f"required section missing: {section}",
                    name,
                )
            )

    # 3. The Traceability Key table must carry at least one key row; prose
    #    lists do not count, the contract copies the design's table verbatim.
    if not any(DEFINITION_LINE.match(line) for _, line in body):
        findings.append(
            Finding(
                FAIL,
                "handoff-no-keys",
                "the Traceability Key table has no rows; copy the table from the "
                "approved design verbatim",
                name,
            )
        )

    # 4. Accepted-risk ownership evidence must live in the Risks section
    #    itself. RSK mentions elsewhere (out-of-scope notes, key tables) are
    #    references, not the risk's canonical statement.
    risks_norm = _norm("Risks and open questions")
    in_risks = False
    for lineno, line in enumerate(clean.splitlines(), start=1):
        hm = _HEADING.match(line)
        if hm:
            in_risks = _norm(hm.group(1)) == risks_norm
            continue
        if not in_risks:
            continue
        for m in _RISK_KEY.finditer(line):
            if not _RISK_EVIDENCE.search(line):
                findings.append(
                    Finding(
                        FAIL,
                        "handoff-risk-unowned",
                        f"{m.group(1)} carries no owner or gate evidence in the Risks "
                        "section (accepted/owner/gate/until/resolution on the same line)",
                        name,
                        lineno,
                        key=m.group(1),
                    )
                )

    return findings
