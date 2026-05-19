"""Finite row, record, frame, and lens data model."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .finite import MODES, freeze_value, sorted_unique, thaw_value


@dataclass(frozen=True)
class EvidenceAtom:
    """A mode-stratified row evidence atom.

    `name` is the typed atom identifier. `origin` and `prov` are retained for
    audits and deterministic derivation traces; equality and hashing include
    all three fields so that provenance-sensitive specs can distinguish atoms.
    """

    mode: str
    name: str
    origin: str = ""
    prov: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"unknown evidence mode: {self.mode!r}")
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "origin", str(self.origin))
        object.__setattr__(self, "prov", tuple(str(p) for p in self.prov))

    @property
    def key(self) -> tuple[str, str]:
        return (self.mode, self.name)

    def same_atom(self, other: EvidenceAtom) -> bool:
        return self.key == other.key

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"mode": self.mode, "name": self.name}
        if self.origin:
            data["origin"] = self.origin
        if self.prov:
            data["prov"] = list(self.prov)
        return data

    @classmethod
    def from_obj(cls, obj: Any) -> EvidenceAtom:
        if isinstance(obj, EvidenceAtom):
            return obj
        if isinstance(obj, str):
            if ":" not in obj:
                raise ValueError(f"atom string must be 'mode:name': {obj!r}")
            mode, name = obj.split(":", 1)
            return cls(mode=mode, name=name)
        if isinstance(obj, Mapping):
            return cls(
                mode=str(obj["mode"]),
                name=str(obj["name"]),
                origin=str(obj.get("origin", "")),
                prov=tuple(str(v) for v in obj.get("prov", ())),
            )
        if isinstance(obj, (tuple, list)) and len(obj) >= 2:
            return cls(mode=str(obj[0]), name=str(obj[1]))
        raise TypeError(f"cannot convert to EvidenceAtom: {obj!r}")


@dataclass(frozen=True)
class RowSchema:
    kind: str
    required_fields: tuple[str, ...] = ()
    allowed_refs: tuple[str, ...] = ()
    modes: tuple[str, ...] = MODES

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", str(self.kind))
        object.__setattr__(self, "required_fields", sorted_unique(self.required_fields))
        object.__setattr__(self, "allowed_refs", sorted_unique(self.allowed_refs))
        modes = tuple(str(m) for m in self.modes)
        for mode in modes:
            if mode not in MODES:
                raise ValueError(f"unknown schema mode {mode!r} for {self.kind}")
        object.__setattr__(self, "modes", modes)

    def validate(self, row: Row) -> tuple[bool, tuple[str, ...]]:
        missing = tuple(field for field in self.required_fields if field not in row.payload)
        bad_mode = bool(row.mode and row.mode not in self.modes)
        problems = list(missing)
        if bad_mode:
            problems.append(f"mode:{row.mode}")
        return not problems, tuple(problems)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "required_fields": list(self.required_fields),
            "allowed_refs": list(self.allowed_refs),
            "modes": list(self.modes),
        }


@dataclass(frozen=True)
class Row:
    rid: str
    kind: str
    sem: str
    verdict: str = "pass"
    retention: str = "active"
    refs: tuple[str, ...] = ()
    payload: Mapping[str, Any] = field(default_factory=dict)
    mode: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "rid", str(self.rid))
        object.__setattr__(self, "kind", str(self.kind))
        object.__setattr__(self, "sem", str(self.sem))
        object.__setattr__(self, "verdict", str(self.verdict))
        object.__setattr__(self, "retention", str(self.retention))
        object.__setattr__(self, "refs", sorted_unique(self.refs))
        object.__setattr__(self, "payload", dict(self.payload))
        if self.mode is not None:
            mode = str(self.mode)
            if mode not in MODES:
                raise ValueError(f"unknown row mode {mode!r}")
            object.__setattr__(self, "mode", mode)

    def __hash__(self) -> int:
        return hash(
            (
                self.rid,
                self.kind,
                self.sem,
                self.verdict,
                self.retention,
                self.refs,
                freeze_value(self.payload),
                self.mode,
            )
        )

    def atoms(self) -> tuple[EvidenceAtom, ...]:
        payload_atoms = self.payload.get("atoms", ())
        atoms = [EvidenceAtom.from_obj(atom) for atom in payload_atoms]
        if self.mode:
            atoms.append(
                EvidenceAtom(mode=self.mode, name=self.sem, origin=self.rid, prov=(self.rid,))
            )
        return tuple(dict.fromkeys(atoms))

    def congruence_key(self, include_row_id: bool = False) -> tuple[Any, ...]:
        base: tuple[Any, ...] = (
            self.kind,
            self.sem,
            self.verdict,
            self.retention,
            self.refs,
            freeze_value(self.payload),
            self.mode,
        )
        if include_row_id:
            return (self.rid, *base)
        return base

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "rid": self.rid,
            "kind": self.kind,
            "sem": self.sem,
            "verdict": self.verdict,
            "retention": self.retention,
            "refs": list(self.refs),
            "payload": thaw_value(freeze_value(self.payload)),
        }
        if self.mode:
            data["mode"] = self.mode
        return data

    @classmethod
    def from_obj(cls, obj: Mapping[str, Any]) -> Row:
        return cls(
            rid=str(obj["rid"]),
            kind=str(obj["kind"]),
            sem=str(obj.get("sem", obj["rid"])),
            verdict=str(obj.get("verdict", "pass")),
            retention=str(obj.get("retention", "active")),
            refs=tuple(str(r) for r in obj.get("refs", ())),
            payload=dict(obj.get("payload", {})),
            mode=str(obj["mode"]) if "mode" in obj and obj["mode"] is not None else None,
        )


@dataclass(frozen=True)
class EffectProfile:
    values: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", dict(self.values))

    def project(self, coordinates: Iterable[str]) -> tuple[tuple[str, Any], ...]:
        return tuple((coord, freeze_value(self.values.get(coord))) for coord in coordinates)

    def to_dict(self) -> dict[str, Any]:
        return {k: thaw_value(freeze_value(v)) for k, v in sorted(self.values.items())}


@dataclass(frozen=True)
class FiniteRecord:
    id: str
    report: Any
    rows: tuple[Row, ...] = ()
    effects: EffectProfile = field(default_factory=EffectProfile)
    active: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", str(self.id))
        object.__setattr__(self, "rows", tuple(self.rows))
        object.__setattr__(self, "active", dict(self.active))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def row_by_id(self) -> dict[str, Row]:
        return {row.rid: row for row in self.rows}

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "report": thaw_value(freeze_value(self.report)),
            "rows": [row.to_dict() for row in self.rows],
            "effects": self.effects.to_dict(),
            "active": thaw_value(freeze_value(self.active)),
            "metadata": thaw_value(freeze_value(self.metadata)),
        }

    @classmethod
    def from_obj(cls, obj: Mapping[str, Any]) -> FiniteRecord:
        return cls(
            id=str(obj["id"]),
            report=obj.get("report"),
            rows=tuple(Row.from_obj(row) for row in obj.get("rows", ())),
            effects=EffectProfile(obj.get("effects", {})),
            active=dict(obj.get("active", {})),
            metadata=dict(obj.get("metadata", {})),
        )


@dataclass(frozen=True)
class ReportLens:
    name: str = "report"
    coordinates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "coordinates", tuple(str(c) for c in self.coordinates))

    def read(self, record: FiniteRecord) -> Any:
        if not self.coordinates:
            return freeze_value(record.report)
        return record.effects.project(self.coordinates)


@dataclass(frozen=True)
class ActivePresentationLens(ReportLens):
    name: str = "active"

    def read(self, record: FiniteRecord) -> Any:
        if not self.coordinates:
            return freeze_value({"report": record.report, "active": record.active})
        effect_part = dict(record.effects.project(self.coordinates))
        return freeze_value(
            {"report": record.report, "active": record.active, "effects": effect_part}
        )


@dataclass(frozen=True)
class Frame:
    systems: tuple[str, ...] = ()
    effect_dimensions: tuple[str, ...] = ()
    occurrences: tuple[str, ...] = ()
    row_kinds: tuple[str, ...] = ()
    semantic_ids: tuple[str, ...] = ()
    verdicts: tuple[str, ...] = ("pass", "fail", "inconclusive")
    retentions: tuple[str, ...] = ("active", "retained", "discharged", "boundary", "deleted")
    laws: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "systems", sorted_unique(self.systems))
        object.__setattr__(self, "effect_dimensions", sorted_unique(self.effect_dimensions))
        object.__setattr__(self, "occurrences", sorted_unique(self.occurrences))
        object.__setattr__(self, "row_kinds", sorted_unique(self.row_kinds))
        object.__setattr__(self, "semantic_ids", sorted_unique(self.semantic_ids))
        object.__setattr__(self, "verdicts", sorted_unique(self.verdicts))
        object.__setattr__(self, "retentions", sorted_unique(self.retentions))
        object.__setattr__(self, "laws", dict(self.laws))


@dataclass(frozen=True)
class ConstraintOccurrence:
    id: str
    emits: tuple[Row, ...] = ()
    candidate: bool = False
