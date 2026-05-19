"""Finite carriers and canonical value helpers for CGT bandwidth."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Literal

Mode = Literal["floor", "diag", "rel", "cmp", "avail", "prov"]
Verdict = Literal["pass", "fail", "inconclusive"]
Retention = Literal["active", "retained", "discharged", "boundary", "deleted"]
Polarity = Literal["capability", "obstruction", "mixed", "diagnostic"]
Variance = Literal["monotone", "antitone", "mixed"]

MODES: tuple[str, ...] = ("floor", "diag", "rel", "cmp", "avail", "prov")
STAGE_ORDER: tuple[str, ...] = (
    "presentable",
    "well_formed",
    "observable",
    "comparable",
    "available",
    "floor_safe",
    "release_safe",
    "selected",
)

JSONScalar = str | int | float | bool | None
JSONValue = JSONScalar | Sequence["JSONValue"] | Mapping[str, "JSONValue"]


def freeze_value(value: Any) -> Any:
    """Convert JSON-like values into a deterministic, hashable normal form."""

    if isinstance(value, Mapping):
        return tuple(
            (str(k), freeze_value(v)) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(freeze_value(v) for v in value)
    return value


def thaw_value(value: Any) -> Any:
    """Best-effort inverse of :func:`freeze_value` for JSON output."""

    if isinstance(value, tuple):
        if all(
            isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
            for item in value
        ):
            return {k: thaw_value(v) for k, v in value}
        return [thaw_value(v) for v in value]
    return value


def sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({str(v) for v in values}))


def canonical_pairs(pairs: Iterable[tuple[str, str]]) -> frozenset[tuple[str, str]]:
    return frozenset((str(a), str(b)) for a, b in pairs)
