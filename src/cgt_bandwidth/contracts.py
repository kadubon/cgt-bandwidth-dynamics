"""Executable contracts and finite checker declarations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .finite import MODES, freeze_value, sorted_unique
from .rows import EvidenceAtom, Row


@dataclass(frozen=True)
class ModeDecision:
    """Finite mode-admissibility decision for one premise/conclusion pair."""

    allowed: bool
    requires_release: bool = False
    requires_retyping: bool = False
    required_modes: tuple[str, ...] = ()
    release_atoms: tuple[str, ...] = ()
    retyping_atoms: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for mode in self.required_modes:
            if mode not in MODES:
                raise ValueError(f"unknown required mode {mode!r}")
        object.__setattr__(self, "required_modes", sorted_unique(self.required_modes))
        object.__setattr__(self, "release_atoms", sorted_unique(self.release_atoms))
        object.__setattr__(self, "retyping_atoms", sorted_unique(self.retyping_atoms))

    @classmethod
    def from_obj(cls, obj: object) -> ModeDecision:
        if isinstance(obj, ModeDecision):
            return obj
        if isinstance(obj, bool):
            return cls(allowed=obj)
        if isinstance(obj, Mapping):
            return cls(
                allowed=bool(obj.get("allowed", False)),
                requires_release=bool(obj.get("requires_release", False)),
                requires_retyping=bool(obj.get("requires_retyping", False)),
                required_modes=tuple(str(mode) for mode in obj.get("required_modes", ())),
                release_atoms=tuple(str(atom) for atom in obj.get("release_atoms", ())),
                retyping_atoms=tuple(str(atom) for atom in obj.get("retyping_atoms", ())),
            )
        raise TypeError(f"cannot convert to ModeDecision: {obj!r}")

    @staticmethod
    def _path(atom: EvidenceAtom) -> tuple[str, ...]:
        return atom.prov or ((atom.origin,) if atom.origin else ())

    @classmethod
    def _same_diag_path(cls, diagnostic: EvidenceAtom, evidence: EvidenceAtom) -> bool:
        diag_path = cls._path(diagnostic)
        evidence_path = cls._path(evidence)
        if not diag_path or not evidence_path:
            return False
        return diag_path == evidence_path

    def _typed_path_evidence_present(
        self,
        premises: tuple[EvidenceAtom, ...],
        *,
        allowed_names: tuple[str, ...],
        strict: bool,
    ) -> bool:
        if strict and not allowed_names:
            return False
        rel_premises = [
            premise
            for premise in premises
            if premise.mode == "rel" and (not allowed_names or premise.name in allowed_names)
        ]
        if not rel_premises:
            return False
        diag_premises = [premise for premise in premises if premise.mode == "diag"]
        if not strict or not diag_premises:
            return True
        return any(
            self._same_diag_path(diag, rel) for diag in diag_premises for rel in rel_premises
        )

    def release_evidence_present(
        self, premises: tuple[EvidenceAtom, ...], *, strict: bool = False
    ) -> bool:
        if self.release_atoms:
            return self._typed_path_evidence_present(
                premises, allowed_names=self.release_atoms, strict=strict
            )
        if strict:
            return False
        return any(premise.mode == "rel" for premise in premises)

    def retyping_evidence_present(
        self, premises: tuple[EvidenceAtom, ...], *, strict: bool = False
    ) -> bool:
        if self.retyping_atoms:
            return self._typed_path_evidence_present(
                premises, allowed_names=self.retyping_atoms, strict=strict
            )
        if strict:
            return False
        return any(
            premise.mode == "rel" and premise.name.startswith(("ret", "retype"))
            for premise in premises
        )

    @property
    def uses_heuristic_retyping(self) -> bool:
        return self.requires_retyping and not self.retyping_atoms

    def permits(self, premises: tuple[EvidenceAtom, ...], *, strict: bool = False) -> bool:
        if not self.allowed:
            return False
        premise_modes = {premise.mode for premise in premises}
        if self.requires_release and not self.release_evidence_present(premises, strict=strict):
            return False
        if self.requires_retyping and not self.retyping_evidence_present(premises, strict=strict):
            return False
        return set(self.required_modes) <= premise_modes

    def to_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "requires_release": self.requires_release,
            "requires_retyping": self.requires_retyping,
            "required_modes": list(self.required_modes),
            "release_atoms": list(self.release_atoms),
            "retyping_atoms": list(self.retyping_atoms),
        }


@dataclass(frozen=True)
class ReadCoord:
    """Typed support/read coordinate.

    The JSON/CLI label form is stable and portable:
    `row:o_1` or `atom:diag:rig_1`. Legacy bare strings are interpreted as
    row coordinates.
    """

    kind: str
    id: str
    mode: str | None = None
    row_kind: str | None = None
    sem: str | None = None

    def __post_init__(self) -> None:
        kind = str(self.kind)
        if kind not in {"row", "atom"}:
            raise ValueError(f"unknown read coordinate kind {kind!r}")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "id", str(self.id))
        if self.mode is not None:
            mode = str(self.mode)
            if mode not in MODES:
                raise ValueError(f"unknown coordinate mode {mode!r}")
            object.__setattr__(self, "mode", mode)
        if kind == "atom" and not self.mode:
            raise ValueError("atom read coordinates require a mode")
        if self.row_kind is not None:
            object.__setattr__(self, "row_kind", str(self.row_kind))
        if self.sem is not None:
            object.__setattr__(self, "sem", str(self.sem))

    @property
    def label(self) -> str:
        if self.kind == "atom":
            return f"atom:{self.mode}:{self.id}"
        return f"row:{self.id}"

    @classmethod
    def from_obj(cls, obj: object) -> ReadCoord:
        if isinstance(obj, ReadCoord):
            return obj
        if isinstance(obj, str):
            parts = obj.split(":")
            if len(parts) == 3 and parts[0] == "atom":
                return cls(kind="atom", mode=parts[1], id=parts[2])
            if len(parts) == 2 and parts[0] == "row":
                return cls(kind="row", id=parts[1])
            return cls(kind="row", id=obj)
        if isinstance(obj, Mapping):
            return cls(
                kind=str(obj["kind"]),
                id=str(obj["id"]),
                mode=str(obj["mode"]) if obj.get("mode") is not None else None,
                row_kind=str(obj["row_kind"]) if obj.get("row_kind") is not None else None,
                sem=str(obj["sem"]) if obj.get("sem") is not None else None,
            )
        raise TypeError(f"cannot convert to ReadCoord: {obj!r}")

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {"kind": self.kind, "id": self.id}
        if self.mode:
            data["mode"] = self.mode
        if self.row_kind:
            data["row_kind"] = self.row_kind
        if self.sem:
            data["sem"] = self.sem
        return data


@dataclass(frozen=True)
class AtomKey:
    """Quotient atom identity used when provenance is intentionally ignored."""

    mode: str
    name: str

    def __post_init__(self) -> None:
        mode = str(self.mode)
        if mode not in MODES:
            raise ValueError(f"unknown atom key mode {mode!r}")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "name", str(self.name))

    @classmethod
    def from_atom(cls, atom: EvidenceAtom) -> AtomKey:
        return cls(atom.mode, atom.name)

    def to_dict(self) -> dict[str, object]:
        return {"mode": self.mode, "name": self.name}


@dataclass(frozen=True)
class AtomInstance:
    """Full atom identity retaining origin and provenance path."""

    mode: str
    name: str
    origin: str = ""
    prov: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        mode = str(self.mode)
        if mode not in MODES:
            raise ValueError(f"unknown atom instance mode {mode!r}")
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "origin", str(self.origin))
        object.__setattr__(self, "prov", tuple(str(item) for item in self.prov))

    @classmethod
    def from_atom(cls, atom: EvidenceAtom) -> AtomInstance:
        return cls(atom.mode, atom.name, atom.origin, atom.prov)

    @property
    def key(self) -> AtomKey:
        return AtomKey(self.mode, self.name)

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {"mode": self.mode, "name": self.name}
        if self.origin:
            data["origin"] = self.origin
        if self.prov:
            data["prov"] = list(self.prov)
        return data


@dataclass(frozen=True)
class WellFormednessIssue:
    """One machine-readable executable well-formedness audit item."""

    condition: str
    status: str
    message: str
    subject: str = ""
    evidence: Mapping[str, Any] | None = None
    witness_rows: tuple[str, ...] = ()
    severity: str | None = None
    repair_hint: str = ""

    def __post_init__(self) -> None:
        condition = str(self.condition)
        status = str(self.status)
        if status not in {"pass", "fail", "warning"}:
            raise ValueError(f"unknown well-formedness status {status!r}")
        severity = str(self.severity if self.severity is not None else status)
        object.__setattr__(self, "condition", condition)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "message", str(self.message))
        object.__setattr__(self, "subject", str(self.subject))
        object.__setattr__(self, "evidence", dict(self.evidence or {}))
        object.__setattr__(self, "witness_rows", sorted_unique(self.witness_rows))
        object.__setattr__(self, "severity", severity)
        object.__setattr__(self, "repair_hint", str(self.repair_hint))

    def to_dict(self) -> dict[str, object]:
        return {
            "condition": self.condition,
            "status": self.status,
            "message": self.message,
            "subject": self.subject,
            "evidence": self.evidence or {},
            "witness_rows": list(self.witness_rows),
            "severity": self.severity or self.status,
            "repair_hint": self.repair_hint,
        }


@dataclass(frozen=True)
class WellFormednessReport:
    """Executable well-formedness report aligned to the paper's 13 conditions."""

    issues: tuple[WellFormednessIssue, ...]
    checker_results: tuple[WellFormednessCheckerResult, ...] = ()
    schema_version: str = "cgt-bandwidth.wellformedness.v1"

    @property
    def ok(self) -> bool:
        return not any(issue.status == "fail" for issue in self.issues)

    @property
    def problems(self) -> tuple[str, ...]:
        return tuple(issue.message for issue in self.issues if issue.status == "fail")

    def condition_status(self) -> dict[str, str]:
        status_rank = {"pass": 0, "warning": 1, "fail": 2}
        statuses: dict[str, str] = {}
        for issue in self.issues:
            current = statuses.get(issue.condition, "pass")
            if status_rank[issue.status] > status_rank[current]:
                statuses[issue.condition] = issue.status
            else:
                statuses.setdefault(issue.condition, current)
        return dict(sorted(statuses.items()))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "ok": self.ok,
            "condition_status": self.condition_status(),
            "issues": [issue.to_dict() for issue in self.issues],
            "checker_results": [result.to_dict() for result in self.checker_results],
            "problems": list(self.problems),
        }


@dataclass(frozen=True)
class StrictConformanceOptions:
    """Portable strictness switches for executable conformance audits."""

    strict: bool = False
    require_declared_read_coordinates: bool = True
    reject_legacy_read_coordinates: bool = True
    reject_aggregate_components: bool = True
    require_lookup_eval_table: bool = True
    require_explicit_local_stability: bool = True
    reject_heuristic_retyping: bool = True
    require_full_provenance_matching: bool = True

    @classmethod
    def from_bool(cls, strict: bool) -> StrictConformanceOptions:
        return cls(strict=bool(strict))

    def active(self, field_name: str) -> bool:
        return self.strict and bool(getattr(self, field_name))

    def to_dict(self) -> dict[str, object]:
        return {
            "strict": self.strict,
            "require_declared_read_coordinates": self.require_declared_read_coordinates,
            "reject_legacy_read_coordinates": self.reject_legacy_read_coordinates,
            "reject_aggregate_components": self.reject_aggregate_components,
            "require_lookup_eval_table": self.require_lookup_eval_table,
            "require_explicit_local_stability": self.require_explicit_local_stability,
            "reject_heuristic_retyping": self.reject_heuristic_retyping,
            "require_full_provenance_matching": self.require_full_provenance_matching,
        }


@dataclass(frozen=True)
class WellFormednessChecker:
    """Descriptor for one executable well-formedness condition."""

    condition: str
    name: str
    description: str
    strict_notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "condition", str(self.condition))
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "description", str(self.description))
        object.__setattr__(self, "strict_notes", sorted_unique(self.strict_notes))

    def to_dict(self) -> dict[str, object]:
        return {
            "condition": self.condition,
            "name": self.name,
            "description": self.description,
            "strict_notes": list(self.strict_notes),
        }


@dataclass(frozen=True)
class WellFormednessCheckerResult:
    """Stable condition-level result for a finite well-formedness checker."""

    condition: str
    checker: str
    passed: bool
    issue_count: int = 0
    severity: str = "pass"
    witnesses: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "condition", str(self.condition))
        object.__setattr__(self, "checker", str(self.checker))
        object.__setattr__(self, "passed", bool(self.passed))
        object.__setattr__(self, "issue_count", int(self.issue_count))
        object.__setattr__(self, "severity", str(self.severity))
        object.__setattr__(self, "witnesses", sorted_unique(self.witnesses))

    def to_dict(self) -> dict[str, object]:
        return {
            "condition": self.condition,
            "checker": self.checker,
            "passed": self.passed,
            "issue_count": self.issue_count,
            "severity": self.severity,
            "witnesses": list(self.witnesses),
        }


@dataclass(frozen=True)
class ModeTableCertificate:
    """Certificate for the explicit finite mode admissibility table."""

    declared_pairs: tuple[tuple[str, str], ...]
    normalized_pairs: tuple[tuple[str, str], ...]
    missing_pairs: tuple[tuple[str, str], ...] = ()
    implicit_default_pairs: tuple[tuple[str, str], ...] = ()

    @property
    def explicit_total(self) -> bool:
        return not self.missing_pairs and not self.implicit_default_pairs

    def to_dict(self) -> dict[str, object]:
        def pair(pair_value: tuple[str, str]) -> str:
            return f"{pair_value[0]}->{pair_value[1]}"

        return {
            "explicit_total": self.explicit_total,
            "declared_pairs": [pair(item) for item in self.declared_pairs],
            "normalized_pairs": [pair(item) for item in self.normalized_pairs],
            "missing_pairs": [pair(item) for item in self.missing_pairs],
            "implicit_default_pairs": [pair(item) for item in self.implicit_default_pairs],
        }


@dataclass(frozen=True)
class StageFailure:
    stage: str
    row_kind: str
    sem: str
    row_id: str
    kind: str
    atom: EvidenceAtom

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage", str(self.stage))
        object.__setattr__(self, "row_kind", str(self.row_kind))
        object.__setattr__(self, "sem", str(self.sem))
        object.__setattr__(self, "row_id", str(self.row_id))
        object.__setattr__(self, "kind", str(self.kind))
        object.__setattr__(self, "atom", EvidenceAtom.from_obj(self.atom))

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.stage, self.row_kind, self.sem, self.row_id)

    def to_legacy_string(self) -> str:
        return f"{self.stage}:{self.kind}:{self.atom.mode}:{self.atom.name}"

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "row_kind": self.row_kind,
            "sem": self.sem,
            "row_id": self.row_id,
            "kind": self.kind,
            "atom": self.atom.to_dict(),
        }


@dataclass(frozen=True)
class MCVContract:
    requirement_rows: tuple[str, ...] = ()
    witness_rows: tuple[str, ...] = ()
    kernel_rows: tuple[str, ...] = ()
    lens_rows: tuple[str, ...] = ()
    floor_predicates: tuple[str, ...] = ()
    diagnostic_predicates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in (
            "requirement_rows",
            "witness_rows",
            "kernel_rows",
            "lens_rows",
            "floor_predicates",
            "diagnostic_predicates",
        ):
            object.__setattr__(self, field_name, sorted_unique(getattr(self, field_name)))


@dataclass(frozen=True)
class RowImplicationRule:
    premises: tuple[EvidenceAtom, ...]
    conclusion: EvidenceAtom
    origin: str = ""
    prov_path: tuple[str, ...] = ()
    non_synthetic: bool = True
    cost: int = 0
    locality: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "premises", tuple(EvidenceAtom.from_obj(atom) for atom in self.premises)
        )
        object.__setattr__(self, "conclusion", EvidenceAtom.from_obj(self.conclusion))
        object.__setattr__(self, "origin", str(self.origin))
        object.__setattr__(self, "prov_path", tuple(str(p) for p in self.prov_path))
        object.__setattr__(self, "cost", int(self.cost))
        object.__setattr__(self, "locality", sorted_unique(self.locality))

    @property
    def conclusion_mode(self) -> str:
        return self.conclusion.mode

    def to_dict(self) -> dict[str, Any]:
        return {
            "premises": [atom.to_dict() for atom in self.premises],
            "conclusion": self.conclusion.to_dict(),
            "origin": self.origin,
            "prov_path": list(self.prov_path),
            "non_synthetic": self.non_synthetic,
            "cost": self.cost,
            "locality": list(self.locality),
        }


@dataclass(frozen=True)
class RetypingCertificate:
    """Typed evidence that a diagnostic path may be retyped for usable modes."""

    id: str
    source_atom: EvidenceAtom
    target_atom: EvidenceAtom
    prov_path: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", str(self.id))
        object.__setattr__(self, "source_atom", EvidenceAtom.from_obj(self.source_atom))
        object.__setattr__(self, "target_atom", EvidenceAtom.from_obj(self.target_atom))
        object.__setattr__(self, "prov_path", tuple(str(item) for item in self.prov_path))

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "source_atom": self.source_atom.to_dict(),
            "target_atom": self.target_atom.to_dict(),
            "prov_path": list(self.prov_path),
        }


@dataclass(frozen=True)
class ReleaseEvidencePath:
    """Typed release/retyping evidence path used by mode-isolation audits."""

    id: str
    mode: str
    atom: EvidenceAtom
    prov_path: tuple[str, ...]
    certificate_id: str = ""

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"unknown release evidence mode {self.mode!r}")
        object.__setattr__(self, "id", str(self.id))
        object.__setattr__(self, "atom", EvidenceAtom.from_obj(self.atom))
        object.__setattr__(self, "prov_path", tuple(str(item) for item in self.prov_path))
        object.__setattr__(self, "certificate_id", str(self.certificate_id))

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "id": self.id,
            "mode": self.mode,
            "atom": self.atom.to_dict(),
            "prov_path": list(self.prov_path),
        }
        if self.certificate_id:
            data["certificate_id"] = self.certificate_id
        return data


@dataclass(frozen=True)
class ModeTrace:
    """Machine-readable trace for one mode-admissibility decision."""

    rule_id: str
    premise_modes: tuple[str, ...]
    conclusion_mode: str
    passed: bool
    required_release: bool = False
    required_retyping: bool = False
    evidence_path_ids: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", str(self.rule_id))
        object.__setattr__(self, "premise_modes", sorted_unique(self.premise_modes))
        object.__setattr__(self, "conclusion_mode", str(self.conclusion_mode))
        object.__setattr__(self, "evidence_path_ids", sorted_unique(self.evidence_path_ids))
        object.__setattr__(self, "problems", sorted_unique(self.problems))

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "premise_modes": list(self.premise_modes),
            "conclusion_mode": self.conclusion_mode,
            "passed": self.passed,
            "required_release": self.required_release,
            "required_retyping": self.required_retyping,
            "evidence_path_ids": list(self.evidence_path_ids),
            "problems": list(self.problems),
        }


@dataclass(frozen=True)
class StoreStepRule:
    """Pure-data store-step rule used by bounded closure."""

    id: str
    premise_rows: tuple[str, ...] = ()
    premise_kinds: tuple[str, ...] = ()
    premise_atoms: tuple[EvidenceAtom, ...] = ()
    emits: tuple[Row, ...] = ()
    origin: str = ""
    prov_path: tuple[str, ...] = ()
    non_synthetic: bool = True
    max_applications: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", str(self.id))
        object.__setattr__(self, "premise_rows", sorted_unique(self.premise_rows))
        object.__setattr__(self, "premise_kinds", sorted_unique(self.premise_kinds))
        object.__setattr__(
            self, "premise_atoms", tuple(EvidenceAtom.from_obj(atom) for atom in self.premise_atoms)
        )
        object.__setattr__(self, "emits", tuple(self.emits))
        object.__setattr__(self, "origin", str(self.origin))
        object.__setattr__(self, "prov_path", tuple(str(item) for item in self.prov_path))
        object.__setattr__(self, "max_applications", int(self.max_applications))

    @classmethod
    def from_obj(cls, obj: object) -> StoreStepRule:
        if isinstance(obj, StoreStepRule):
            return obj
        if not isinstance(obj, Mapping):
            raise TypeError(f"cannot convert to StoreStepRule: {obj!r}")
        return cls(
            id=str(obj["id"]),
            premise_rows=tuple(str(item) for item in obj.get("premise_rows", ())),
            premise_kinds=tuple(str(item) for item in obj.get("premise_kinds", ())),
            premise_atoms=tuple(
                EvidenceAtom.from_obj(atom) for atom in obj.get("premise_atoms", ())
            ),
            emits=tuple(Row.from_obj(row) for row in obj.get("emits", ())),
            origin=str(obj.get("origin", "")),
            prov_path=tuple(str(item) for item in obj.get("prov_path", ())),
            non_synthetic=bool(obj.get("non_synthetic", True)),
            max_applications=int(obj.get("max_applications", 1)),
        )

    def enabled_by(self, rows: Mapping[str, Row]) -> tuple[bool, tuple[str, ...]]:
        problems: list[str] = []
        if not self.non_synthetic:
            problems.append("synthetic-store-step")
        if self.premise_rows:
            missing = sorted(row_id for row_id in self.premise_rows if row_id not in rows)
            problems.extend(f"missing-row:{row_id}" for row_id in missing)
        if self.premise_kinds:
            kinds = {row.kind for row in rows.values()}
            problems.extend(
                f"missing-kind:{kind}" for kind in self.premise_kinds if kind not in kinds
            )
        if self.premise_atoms:
            atom_keys = {atom.key for row in rows.values() for atom in row.atoms()}
            problems.extend(
                f"missing-atom:{atom.mode}:{atom.name}"
                for atom in self.premise_atoms
                if atom.key not in atom_keys
            )
        return not problems, tuple(problems)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "premise_rows": list(self.premise_rows),
            "premise_kinds": list(self.premise_kinds),
            "premise_atoms": [atom.to_dict() for atom in self.premise_atoms],
            "emits": [row.to_dict() for row in self.emits],
            "origin": self.origin,
            "prov_path": list(self.prov_path),
            "non_synthetic": self.non_synthetic,
            "max_applications": self.max_applications,
        }


@dataclass(frozen=True)
class StoreStepCertificate:
    rule_id: str
    enabled: bool
    applied: bool
    emitted_rows: tuple[str, ...] = ()
    blocked_reasons: tuple[str, ...] = ()
    trace: tuple[str, ...] = ()
    checker_id: str = "store-step-rule"
    provenance: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", str(self.rule_id))
        object.__setattr__(self, "emitted_rows", sorted_unique(self.emitted_rows))
        object.__setattr__(self, "blocked_reasons", sorted_unique(self.blocked_reasons))
        object.__setattr__(self, "trace", tuple(str(item) for item in self.trace))
        object.__setattr__(self, "checker_id", str(self.checker_id))
        object.__setattr__(self, "provenance", dict(self.provenance or {}))

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "enabled": self.enabled,
            "applied": self.applied,
            "checker_id": self.checker_id,
            "emitted_rows": list(self.emitted_rows),
            "blocked_reasons": list(self.blocked_reasons),
            "trace": list(self.trace),
            "provenance": dict(self.provenance or {}),
        }


@dataclass(frozen=True)
class RuleTableCertificate:
    """Finite closure-rule table audit."""

    rules_declared: bool
    rule_count: int
    certificates: tuple[StoreStepCertificate, ...] = ()
    legacy_derivations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_count", int(self.rule_count))
        object.__setattr__(self, "legacy_derivations", sorted_unique(self.legacy_derivations))

    def to_dict(self) -> dict[str, object]:
        return {
            "rules_declared": self.rules_declared,
            "rule_count": self.rule_count,
            "certificates": [cert.to_dict() for cert in self.certificates],
            "legacy_derivations": list(self.legacy_derivations),
        }


@dataclass(frozen=True)
class RowDerivation:
    atom: EvidenceAtom
    mode: str
    rules: tuple[RowImplicationRule, ...] = ()


@dataclass(frozen=True)
class StageCheck:
    required: tuple[EvidenceAtom, ...] = ()
    blockers: tuple[EvidenceAtom, ...] = ()
    reads: tuple[EvidenceAtom, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "required", tuple(EvidenceAtom.from_obj(a) for a in self.required))
        object.__setattr__(self, "blockers", tuple(EvidenceAtom.from_obj(a) for a in self.blockers))
        object.__setattr__(self, "reads", tuple(EvidenceAtom.from_obj(a) for a in self.reads))


@dataclass(frozen=True)
class StageEvidence:
    candidate: str
    last_passed: str
    semantic_class: str
    first_failure: str | None
    comparison_bundle: tuple[str, ...] = ()
    floor_bundle: tuple[str, ...] = ()
    diagnostic_bundle: tuple[str, ...] = ()
    obstruction_bundle: tuple[str, ...] = ()
    release_safe: bool = False
    atoms: frozenset[EvidenceAtom] = field(default_factory=frozenset)
    failure: StageFailure | None = None
    s: str | None = None
    q: str | None = None
    phi: str | None = None
    gamma: tuple[str, ...] = ()
    ell: tuple[str, ...] = ()
    delta: tuple[str, ...] = ()
    omega: tuple[str, ...] = ()
    alpha: bool | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "s", self.s if self.s is not None else self.last_passed)
        object.__setattr__(self, "q", self.q if self.q is not None else self.semantic_class)
        object.__setattr__(self, "phi", self.phi if self.phi is not None else self.first_failure)
        object.__setattr__(self, "gamma", tuple(self.gamma or self.comparison_bundle))
        object.__setattr__(self, "ell", tuple(self.ell or self.floor_bundle))
        object.__setattr__(self, "delta", tuple(self.delta or self.diagnostic_bundle))
        object.__setattr__(self, "omega", tuple(self.omega or self.obstruction_bundle))
        object.__setattr__(
            self, "alpha", self.alpha if self.alpha is not None else self.release_safe
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate,
            "last_passed": self.last_passed,
            "semantic_class": self.semantic_class,
            "first_failure": self.first_failure,
            "comparison_bundle": list(self.comparison_bundle),
            "floor_bundle": list(self.floor_bundle),
            "diagnostic_bundle": list(self.diagnostic_bundle),
            "obstruction_bundle": list(self.obstruction_bundle),
            "release_safe": self.release_safe,
            "failure": self.failure.to_dict() if self.failure else None,
            "coordinates": {
                "s": self.s,
                "q": self.q,
                "phi": self.phi,
                "gamma": list(self.gamma),
                "ell": list(self.ell),
                "delta": list(self.delta),
                "omega": list(self.omega),
                "alpha": self.alpha,
            },
            "atoms": [
                atom.to_dict()
                for atom in sorted(self.atoms, key=lambda a: (a.mode, a.name, a.origin))
            ],
        }


@dataclass(frozen=True)
class ComponentFunctional:
    name: str
    polarity: str = "mixed"
    variance: str = "mixed"
    lower: int | float | None = None
    upper: int | float | None = None
    support_atoms: tuple[str, ...] = ()
    carrier: tuple[Any, ...] = ()
    bottom: Any = 0
    preorder: frozenset[tuple[Any, Any]] = field(default_factory=frozenset)
    congruence: Mapping[Any, Any] = field(default_factory=dict)
    input_kinds: tuple[str, ...] = ()
    read_modes: tuple[str, ...] = MODES
    read_atoms: tuple[str, ...] = ()
    aggregator: str = "max"
    default: Any = 0
    eval_table: Mapping[Any, Any] = field(default_factory=dict)
    eval_key: tuple[str, ...] = ()
    low_debt_table: Mapping[Any, tuple[str, ...]] = field(default_factory=dict)
    up_debt_table: Mapping[Any, tuple[str, ...]] = field(default_factory=dict)
    support_table: Mapping[Any, tuple[str, ...]] = field(default_factory=dict)
    emit_bound_debt: bool = True
    lower_debt_label: str | None = None
    upper_debt_label: str | None = None
    time_bound: int = 0
    contribution_atoms: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", str(self.name))
        if self.polarity not in {"capability", "obstruction", "mixed", "diagnostic"}:
            raise ValueError(f"unknown component polarity {self.polarity!r}")
        if self.variance not in {"monotone", "antitone", "mixed"}:
            raise ValueError(f"unknown component variance {self.variance!r}")
        object.__setattr__(self, "support_atoms", sorted_unique(self.support_atoms))
        object.__setattr__(self, "carrier", tuple(freeze_value(v) for v in self.carrier))
        object.__setattr__(
            self,
            "preorder",
            frozenset((freeze_value(a), freeze_value(b)) for a, b in self.preorder),
        )
        object.__setattr__(self, "congruence", dict(self.congruence))
        object.__setattr__(self, "input_kinds", sorted_unique(self.input_kinds))
        modes = tuple(str(m) for m in self.read_modes)
        for mode in modes:
            if mode not in MODES:
                raise ValueError(f"unknown component read mode {mode!r}")
        object.__setattr__(self, "read_modes", modes)
        object.__setattr__(self, "read_atoms", sorted_unique(self.read_atoms))
        object.__setattr__(self, "eval_key", sorted_unique(self.eval_key))
        object.__setattr__(
            self,
            "eval_table",
            {freeze_value(k): freeze_value(v) for k, v in self.eval_table.items()},
        )
        object.__setattr__(
            self,
            "low_debt_table",
            {freeze_value(k): sorted_unique(v) for k, v in self.low_debt_table.items()},
        )
        object.__setattr__(
            self,
            "up_debt_table",
            {freeze_value(k): sorted_unique(v) for k, v in self.up_debt_table.items()},
        )
        object.__setattr__(
            self,
            "support_table",
            {
                freeze_value(k): tuple(str(item) for item in v)
                for k, v in self.support_table.items()
            },
        )
        object.__setattr__(self, "emit_bound_debt", bool(self.emit_bound_debt))
        object.__setattr__(self, "time_bound", int(self.time_bound))
        object.__setattr__(self, "contribution_atoms", sorted_unique(self.contribution_atoms))
        if self.lower_debt_label is not None:
            object.__setattr__(self, "lower_debt_label", str(self.lower_debt_label))
        if self.upper_debt_label is not None:
            object.__setattr__(self, "upper_debt_label", str(self.upper_debt_label))
        if self.aggregator not in {
            "max",
            "sum",
            "min",
            "set",
            "last",
            "count",
            "lookup",
            "graph_count",
            "graph_reachability",
            "graph_cut",
        }:
            raise ValueError(f"unknown component aggregator {self.aggregator!r}")


@dataclass(frozen=True)
class ReleaseCertificate:
    id: str
    source: str
    target: str
    discharges: tuple[str, ...] = ()
    preserves: tuple[str, ...] = ()
    footprint: tuple[str, ...] = ()
    no_new_rows: bool = True
    noninterference: bool = True
    diagnostic_retyping: tuple[str, ...] = ()
    exact: bool = True
    stable: bool = True
    signature: Mapping[str, Any] = field(default_factory=dict)
    discharge_map: Mapping[str, str] = field(default_factory=dict)
    preservation_map: Mapping[str, str] = field(default_factory=dict)
    noninterference_rows: tuple[str, ...] = ()
    no_new_obstructions: tuple[str, ...] = ()
    retyping_map: Mapping[str, str] = field(default_factory=dict)
    checker_trace: tuple[str, ...] = ()
    local_stability: Mapping[str, bool] = field(default_factory=dict)
    local_stability_declared: tuple[str, ...] = field(
        default=(), init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", str(self.id))
        object.__setattr__(self, "source", str(self.source))
        object.__setattr__(self, "target", str(self.target))
        for field_name in ("discharges", "preserves", "footprint", "diagnostic_retyping"):
            object.__setattr__(self, field_name, sorted_unique(getattr(self, field_name)))
        object.__setattr__(self, "signature", dict(self.signature))
        object.__setattr__(
            self, "discharge_map", {str(k): str(v) for k, v in self.discharge_map.items()}
        )
        object.__setattr__(
            self, "preservation_map", {str(k): str(v) for k, v in self.preservation_map.items()}
        )
        object.__setattr__(self, "noninterference_rows", sorted_unique(self.noninterference_rows))
        object.__setattr__(self, "no_new_obstructions", sorted_unique(self.no_new_obstructions))
        object.__setattr__(
            self, "retyping_map", {str(k): str(v) for k, v in self.retyping_map.items()}
        )
        object.__setattr__(self, "checker_trace", tuple(str(x) for x in self.checker_trace))
        declared_local_stability = sorted_unique(str(k) for k in self.local_stability)
        defaults = {
            "FootprintDet": True,
            "ComponentDebtPres": True,
            "StageStab": True,
            "SelKerStab": True,
            "OneStepReleaseBisim": True,
        }
        defaults.update({str(k): bool(v) for k, v in self.local_stability.items()})
        object.__setattr__(self, "local_stability_declared", declared_local_stability)
        object.__setattr__(self, "local_stability", defaults)

    @property
    def accepted(self) -> bool:
        return (
            self.exact
            and self.stable
            and self.no_new_rows
            and self.noninterference
            and all(self.local_stability.values())
        )

    def foot_sig(
        self,
        target_report: Any,
        target_band_rows: Any,
        delta: Mapping[str, Any] | None = None,
        *,
        source_footprint_reading: Any = None,
        checker_verdict: Any = None,
    ) -> Any:
        release_label = "idFoot" if self.signature.get("kind") == "identity" else self.id
        data = {
            "source_footprint_reading": freeze_value(source_footprint_reading or self.footprint),
            "release_congruence_class": release_label,
            "target_report": target_report,
            "target_band_rows": freeze_value(target_band_rows),
            "delta": freeze_value(delta or {}),
            "checker_verdict": freeze_value(
                checker_verdict
                if checker_verdict is not None
                else ("pass" if self.accepted else "fail")
            ),
            "signature": freeze_value(self.signature),
        }
        return freeze_value(data)

    @classmethod
    def strict(
        cls,
        id: str,
        source: str,
        target: str,
        *,
        footprint: tuple[str, ...],
        discharges: tuple[str, ...] = (),
        preserves: tuple[str, ...] = (),
        discharge_map: Mapping[str, str] | None = None,
        preservation_map: Mapping[str, str] | None = None,
        noninterference_rows: tuple[str, ...] = (),
        no_new_obstructions: tuple[str, ...] = (),
        retyping_map: Mapping[str, str] | None = None,
        diagnostic_retyping: tuple[str, ...] = (),
        signature: Mapping[str, Any] | None = None,
        checker_trace: tuple[str, ...] = (),
        require_total_maps: bool = True,
    ) -> ReleaseCertificate:
        """Build a release certificate that declares every strict proof field."""

        discharge_map = discharge_map or {}
        preservation_map = preservation_map or {}
        retyping_map = retyping_map or {}
        if require_total_maps:
            missing_discharges = set(discharges) - set(discharge_map)
            missing_preserves = set(preserves) - set(preservation_map)
            missing_retyping = set(diagnostic_retyping) - set(retyping_map)
            if missing_discharges or missing_preserves or missing_retyping:
                raise ValueError(
                    "strict release certificate maps are incomplete: "
                    f"discharge={sorted(missing_discharges)}, "
                    f"preservation={sorted(missing_preserves)}, "
                    f"retyping={sorted(missing_retyping)}"
                )
        local_stability = {
            "FootprintDet": True,
            "ComponentDebtPres": True,
            "StageStab": True,
            "SelKerStab": True,
            "OneStepReleaseBisim": True,
        }
        return cls(
            id=id,
            source=source,
            target=target,
            discharges=discharges,
            preserves=preserves,
            footprint=footprint,
            diagnostic_retyping=diagnostic_retyping,
            signature=signature or {},
            discharge_map=discharge_map,
            preservation_map=preservation_map,
            noninterference_rows=noninterference_rows,
            no_new_obstructions=no_new_obstructions,
            retyping_map=retyping_map,
            checker_trace=checker_trace or ("strict-constructor",),
            local_stability=local_stability,
        )


@dataclass(frozen=True)
class CandidateSpec:
    id: str
    semantic_class: str | None = None
    rows: tuple[Row, ...] = ()
    evidence: tuple[EvidenceAtom, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", str(self.id))
        object.__setattr__(
            self,
            "semantic_class",
            str(self.semantic_class) if self.semantic_class is not None else self.id,
        )
        object.__setattr__(self, "rows", tuple(self.rows))
        object.__setattr__(self, "evidence", tuple(EvidenceAtom.from_obj(a) for a in self.evidence))


@dataclass(frozen=True)
class ReleaseCheckTable:
    obstruction_rows: tuple[str, ...] = ()
    lower_bound_rows: tuple[str, ...] = ()
    allowed_new_rows: tuple[str, ...] = ()
    footprint_predicates: Mapping[str, Mapping[str, bool]] = field(default_factory=dict)
    footprint_coordinates: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    predicate_coordinates: Mapping[str, Mapping[str, tuple[str, ...]]] = field(default_factory=dict)
    required_predicates: tuple[str, ...] = (
        "obstructionCoverage",
        "lowerBoundSuccessor",
        "noNewRow",
        "noninterference",
        "diagnosticRetyping",
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "obstruction_rows", sorted_unique(self.obstruction_rows))
        object.__setattr__(self, "lower_bound_rows", sorted_unique(self.lower_bound_rows))
        object.__setattr__(self, "allowed_new_rows", sorted_unique(self.allowed_new_rows))
        object.__setattr__(
            self,
            "footprint_predicates",
            {
                str(cert_id): {str(name): bool(value) for name, value in predicates.items()}
                for cert_id, predicates in self.footprint_predicates.items()
            },
        )
        object.__setattr__(
            self,
            "footprint_coordinates",
            {
                str(cert_id): sorted_unique(coords)
                for cert_id, coords in self.footprint_coordinates.items()
            },
        )
        object.__setattr__(
            self,
            "predicate_coordinates",
            {
                str(cert_id): {
                    str(predicate): sorted_unique(coords)
                    for predicate, coords in predicates.items()
                }
                for cert_id, predicates in self.predicate_coordinates.items()
            },
        )
        object.__setattr__(self, "required_predicates", sorted_unique(self.required_predicates))

    def declared_predicates_for(self, certificate_id: str) -> Mapping[str, bool]:
        return self.footprint_predicates.get(str(certificate_id), {})

    def declared_coordinates_for(self, certificate_id: str) -> tuple[str, ...]:
        return self.footprint_coordinates.get(str(certificate_id), ())

    def declared_predicate_coordinates_for(
        self, certificate_id: str, predicate: str
    ) -> tuple[str, ...]:
        return self.predicate_coordinates.get(str(certificate_id), {}).get(str(predicate), ())

    def to_dict(self) -> dict[str, object]:
        return {
            "obstruction_rows": list(self.obstruction_rows),
            "lower_bound_rows": list(self.lower_bound_rows),
            "allowed_new_rows": list(self.allowed_new_rows),
            "footprint_predicates": {
                cert_id: dict(predicates)
                for cert_id, predicates in sorted(self.footprint_predicates.items())
            },
            "footprint_coordinates": {
                cert_id: list(coords)
                for cert_id, coords in sorted(self.footprint_coordinates.items())
            },
            "predicate_coordinates": {
                cert_id: {
                    predicate: list(coords) for predicate, coords in sorted(predicates.items())
                }
                for cert_id, predicates in sorted(self.predicate_coordinates.items())
            },
            "required_predicates": list(self.required_predicates),
        }


@dataclass(frozen=True)
class WorkBounds:
    closure_steps: int = 256
    candidate_rows: int = 256
    trace_depth: int = 64
    branch_depth: int = 64
    snapshot_depth: int = 64
    component_evals: int = 1024
    support_subsets: int = 4096
    release_checks: int = 1024
    quotient_classes: int = 1024

    def __post_init__(self) -> None:
        for field_name in (
            "closure_steps",
            "candidate_rows",
            "trace_depth",
            "branch_depth",
            "snapshot_depth",
            "component_evals",
            "support_subsets",
            "release_checks",
            "quotient_classes",
        ):
            object.__setattr__(self, field_name, int(getattr(self, field_name)))


@dataclass(frozen=True)
class AuditUniverseScope:
    whole_domain: bool = True
    abstraction_map_declared: bool = False
    preservation_checks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "preservation_checks", sorted_unique(self.preservation_checks))
