"""Finite order, closure-store, and quotient data structures."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .finite import canonical_pairs, sorted_unique, thaw_value
from .rows import EvidenceAtom, Row


@dataclass(frozen=True)
class ClosureStore:
    record_id: str
    rows: tuple[Row, ...]
    failures: tuple[Row, ...] = ()
    bound: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "rows", tuple(sorted(self.rows, key=lambda r: r.rid)))
        object.__setattr__(self, "failures", tuple(sorted(self.failures, key=lambda r: r.rid)))

    @property
    def all_rows(self) -> tuple[Row, ...]:
        return tuple(sorted((*self.rows, *self.failures), key=lambda r: r.rid))

    def by_id(self) -> dict[str, Row]:
        return {row.rid: row for row in self.all_rows}

    def atoms(self) -> frozenset[EvidenceAtom]:
        atoms: set[EvidenceAtom] = set()
        for row in self.all_rows:
            atoms.update(row.atoms())
        return frozenset(atoms)

    def restriction(self, coordinates: Iterable[str]) -> tuple[tuple[str, Any], ...]:
        row_map = self.by_id()
        result = []
        for coord in sorted_unique(coordinates):
            row = row_map.get(coord)
            result.append((coord, row.congruence_key() if row else None))
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "rows": [row.to_dict() for row in self.rows],
            "failures": [row.to_dict() for row in self.failures],
            "bound": self.bound,
        }


@dataclass(frozen=True)
class RECH:
    nodes: frozenset[str]
    hyperarcs: tuple[tuple[str, tuple[str, ...], str], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": sorted(self.nodes),
            "hyperarcs": [
                {"kind": kind, "sources": list(sources), "target": target}
                for kind, sources, target in self.hyperarcs
            ],
        }


@dataclass(frozen=True)
class Preorder:
    elements: tuple[str, ...]
    pairs: frozenset[tuple[str, str]]

    def __post_init__(self) -> None:
        object.__setattr__(self, "elements", sorted_unique(self.elements))
        object.__setattr__(self, "pairs", canonical_pairs(self.pairs))

    def relates(self, left: str, right: str) -> bool:
        return (left, right) in self.pairs

    def symmetric_classes(self) -> tuple[tuple[str, ...], ...]:
        remaining = set(self.elements)
        classes: list[tuple[str, ...]] = []
        while remaining:
            seed = min(remaining)
            cls = {seed}
            cls.update(x for x in remaining if self.relates(seed, x) and self.relates(x, seed))
            classes.append(tuple(sorted(cls)))
            remaining -= cls
        return tuple(classes)

    def quotient_pairs(self) -> frozenset[tuple[tuple[str, ...], tuple[str, ...]]]:
        classes = self.symmetric_classes()
        index = {element: cls for cls in classes for element in cls}
        return frozenset((index[a], index[b]) for a, b in self.pairs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "elements": list(self.elements),
            "pairs": [list(pair) for pair in sorted(self.pairs)],
            "classes": [list(cls) for cls in self.symmetric_classes()],
        }


@dataclass(frozen=True)
class Completion:
    lens_name: str
    classes: tuple[tuple[str, ...], ...]
    observable_by_record: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "classes", tuple(tuple(sorted(cls)) for cls in self.classes))
        object.__setattr__(self, "observable_by_record", dict(self.observable_by_record))

    def class_of(self, record_id: str) -> tuple[str, ...]:
        for cls in self.classes:
            if record_id in cls:
                return cls
        raise KeyError(record_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "lens": self.lens_name,
            "classes": [list(cls) for cls in self.classes],
            "observable_by_record": {
                rid: thaw_value(value) for rid, value in sorted(self.observable_by_record.items())
            },
        }
