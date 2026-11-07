"""Inline waivers: dated, owner-attributed, and always loud.

A waiver suppresses one finding kind for one key:

    <!-- goldfish-waiver: invented-key FR-09 until=2027-01-31 owner=design-owner -->

Rules:

- ``until`` (YYYY-MM-DD) and ``owner`` are REQUIRED. A waiver missing either
  is never honored and produces a ``waiver-invalid`` warning so nothing is
  silenced silently.
- An expired waiver never suppresses; when it would have applied, an
  additional ``waiver-expired`` warning asks the owner to renew or remove it.
- Waived findings keep severity ``WAIVED``, are excluded from the exit code,
  and are always listed in every report format.
- Waivers inside fenced code blocks are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from .check import WARN, WAIVED, Finding, Source
from .ids import ALL_PREFIXES, strip_fenced_blocks

WAIVER_PATTERN = re.compile(
    r"<!--\s*goldfish-waiver:\s*([a-z][a-z-]*)\s+((?:" + "|".join(ALL_PREFIXES) + r")-\d{2,3})"
    r"(?:\s+until=(\d{4}-\d{2}-\d{2}))?(?:\s+owner=([^\s>]+))?\s*-->",
    re.IGNORECASE,
)
_LOOSE_MARKER = re.compile(r"goldfish-waiver", re.IGNORECASE)


@dataclass
class Waiver:
    code: str
    key: str
    until: str | None
    owner: str | None
    file: str
    line: int
    valid: bool
    problem: str = ""


def collect_waivers(sources: list[Source]) -> list[Waiver]:
    """Collect every waiver comment across the checked sources."""
    waivers: list[Waiver] = []
    for src in sources:
        clean = strip_fenced_blocks(src.text)
        for lineno, line in enumerate(clean.splitlines(), start=1):
            if not _LOOSE_MARKER.search(line):
                continue
            m = WAIVER_PATTERN.search(line)
            if not m:
                waivers.append(
                    Waiver("", "", None, None, src.name, lineno, False,
                           "unparsable waiver comment; expected "
                           "goldfish-waiver: <code> <KEY> until=YYYY-MM-DD owner=name")
                )
                continue
            code, key, until, owner = m.group(1).lower(), m.group(2), m.group(3), m.group(4)
            if not until or not owner:
                waivers.append(
                    Waiver(code, key, until, owner, src.name, lineno, False,
                           "waiver needs both until=YYYY-MM-DD and owner=name")
                )
                continue
            try:
                date.fromisoformat(until)
            except ValueError:
                waivers.append(
                    Waiver(code, key, until, owner, src.name, lineno, False,
                           f"unparsable until date {until}")
                )
                continue
            waivers.append(Waiver(code, key, until, owner, src.name, lineno, True))
    return waivers


def apply_waivers(
    findings: list[Finding], waivers: list[Waiver], today: date
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (active, waived) under the waiver contract."""
    by_pair: dict[tuple[str, str], list[int]] = {}
    for idx, w in enumerate(waivers):
        if w.valid:
            by_pair.setdefault((w.code, w.key), []).append(idx)

    active: list[Finding] = []
    waived: list[Finding] = []
    expired_applied: set[int] = set()

    for f in findings:
        hit: Waiver | None = None
        for idx in by_pair.get((f.code, f.key), []):
            w = waivers[idx]
            assert w.until is not None
            if date.fromisoformat(w.until) < today:
                expired_applied.add(idx)
                continue
            hit = w
            break
        if hit is not None:
            waived.append(
                Finding(
                    WAIVED,
                    f.code,
                    f"{f.message} [waived by {hit.owner} until {hit.until}]",
                    f.file,
                    f.line,
                    f.key,
                )
            )
        else:
            active.append(f)

    for w in waivers:
        if not w.valid:
            active.append(
                Finding(WARN, "waiver-invalid", f"{w.problem}", w.file, w.line)
            )
    for idx in sorted(expired_applied):
        w = waivers[idx]
        active.append(
            Finding(
                WARN,
                "waiver-expired",
                f"waiver for {w.code} {w.key} expired on {w.until}; renew or remove it",
                w.file,
                w.line,
            )
        )
    return active, waived
