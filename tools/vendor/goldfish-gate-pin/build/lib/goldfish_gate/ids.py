"""The traceability ID grammar and markdown extraction.

IDs are uppercase PREFIX-NN tokens (NN is two or three digits):

- Requirements (must be implemented and verified downstream):
  ``FR`` functional, ``NFR`` quality attribute, ``SEC`` security,
  ``DATA`` data, ``OPS`` operations.
- ``DEC``: an approved architecture decision that planning must preserve.
- ``RSK``: an accepted risk or gated item.

Extraction ignores fenced code blocks so commands and example code inside
the documents never inject phantom IDs. Blank lines replace fence content
so reported line numbers always match the original file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

REQUIREMENT_PREFIXES = ("FR", "NFR", "SEC", "DATA", "OPS")
DECISION_PREFIXES = ("DEC",)
RISK_PREFIXES = ("RSK",)
ALL_PREFIXES = REQUIREMENT_PREFIXES + DECISION_PREFIXES + RISK_PREFIXES

ID_PATTERN = re.compile(r"\b(" + "|".join(ALL_PREFIXES) + r")-(\d{2,3})\b")

_FENCE_OPEN = re.compile(r"^\s*(`{3,}|~{3,})")


@dataclass(frozen=True)
class Hit:
    """One ID occurrence: the ID and its 1-based line number."""

    id: str
    line: int


def strip_fenced_blocks(text: str) -> str:
    """Blank out fenced code blocks while preserving the line count."""
    out: list[str] = []
    fence_char = ""
    for line in text.splitlines():
        stripped = line.lstrip()
        if fence_char:
            if stripped.startswith(fence_char * 3):
                fence_char = ""
            out.append("")
            continue
        m = _FENCE_OPEN.match(line)
        if m:
            fence_char = m.group(1)[0]
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


def scan(text: str) -> list[Hit]:
    """Return every ID occurrence in reading order, duplicates included."""
    clean = strip_fenced_blocks(text)
    hits: list[Hit] = []
    for lineno, line in enumerate(clean.splitlines(), start=1):
        for m in ID_PATTERN.finditer(line):
            hits.append(Hit(f"{m.group(1)}-{m.group(2)}", lineno))
    return hits


def unique_ids(hits: list[Hit]) -> list[str]:
    """Deduplicated IDs in first-occurrence order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for h in hits:
        if h.id not in seen:
            seen.add(h.id)
            ordered.append(h.id)
    return ordered


def ids_of_kind(ids, prefixes) -> set[str]:
    """Filter IDs to the given prefix family."""
    return {i for i in ids if i.split("-")[0] in prefixes}
