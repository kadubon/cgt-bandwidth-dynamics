"""Candidate pipeline and applicability support."""

from __future__ import annotations

from collections.abc import Mapping

from .closure import close_store
from .core import (
    STAGE_ORDER,
    EvidenceAtom,
    ExecutableBandSpec,
    FiniteRecord,
    Preorder,
    StageEvidence,
    StageFailure,
    as_exec_spec,
)
from .evidence import evidence_closure, stage_implication


def _has_atom(atoms: frozenset[EvidenceAtom], required: EvidenceAtom) -> bool:
    return required.key in {atom.key for atom in atoms}


def _bundle(atoms: frozenset[EvidenceAtom], mode: str) -> tuple[str, ...]:
    return tuple(sorted(atom.name for atom in atoms if atom.mode == mode))


def _visible_atoms(
    spec: ExecutableBandSpec, candidate: str, atoms: frozenset[EvidenceAtom]
) -> frozenset[EvidenceAtom]:
    declared = spec.candidate_evidence.get(candidate, ())
    if not declared:
        return atoms
    keys = {atom.key for atom in declared}
    return frozenset(atom for atom in atoms if atom.key in keys)


def _row_order_key(
    rows_by_id: Mapping[str, object],
    stage: str,
    failure_kind: str,
    atom: EvidenceAtom,
) -> tuple[object, ...]:
    stage_index = STAGE_ORDER.index(stage) if stage in STAGE_ORDER else len(STAGE_ORDER)
    origin = atom.origin or (atom.prov[0] if atom.prov else "")
    row = rows_by_id.get(origin)
    if row is not None:
        return (
            stage_index,
            getattr(row, "kind"),
            getattr(row, "sem"),
            getattr(row, "rid"),
            failure_kind,
            atom.mode,
            atom.name,
        )
    return (stage_index, atom.mode, atom.name, origin, failure_kind)


def _least_failure_atom(
    rows_by_id: Mapping[str, object],
    stage: str,
    failure_kind: str,
    atom: EvidenceAtom,
    atoms: frozenset[EvidenceAtom],
) -> EvidenceAtom:
    if failure_kind == "missing":
        return atom
    matches = [candidate for candidate in atoms if candidate.key == atom.key]
    if not matches:
        return atom
    return min(
        matches, key=lambda candidate: _row_order_key(rows_by_id, stage, failure_kind, candidate)
    )


def _stage_failure(
    rows_by_id: Mapping[str, object],
    stage: str,
    failure_kind: str,
    atom: EvidenceAtom,
) -> StageFailure:
    origin = atom.origin or (atom.prov[0] if atom.prov else "")
    row = rows_by_id.get(origin)
    return StageFailure(
        stage=stage,
        row_kind=getattr(row, "kind", ""),
        sem=getattr(row, "sem", atom.name),
        row_id=getattr(row, "rid", origin),
        kind=failure_kind,
        atom=atom,
    )


def stage_evidence(
    spec: ExecutableBandSpec, record: str | FiniteRecord, candidate: str
) -> StageEvidence:
    """Compute deterministic finite stage evidence for one candidate."""

    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    closure = evidence_closure(exec_spec, rec)
    rows_by_id = close_store(exec_spec, rec).by_id()
    all_atoms = closure.atoms
    atoms = _visible_atoms(exec_spec, candidate, all_atoms)
    checks = exec_spec.stage_checks.get(candidate, {})
    last_passed = "none"
    first_failure: str | None = None
    failure_obj: StageFailure | None = None

    for stage in STAGE_ORDER:
        check = checks.get(stage)
        if check is None:
            last_passed = stage
            continue
        missing = [atom for atom in check.required if not _has_atom(atoms, atom)]
        blocking = [atom for atom in check.blockers if _has_atom(atoms, atom)]
        if missing or blocking:
            failures = [
                *(
                    (
                        "missing",
                        stage,
                        _least_failure_atom(rows_by_id, stage, "missing", atom, atoms),
                    )
                    for atom in missing
                ),
                *(
                    (
                        "blocked",
                        stage,
                        _least_failure_atom(rows_by_id, stage, "blocked", atom, atoms),
                    )
                    for atom in blocking
                ),
            ]
            ordered = sorted(
                [
                    (
                        kind,
                        fail_stage,
                        atom.mode,
                        atom.name,
                        _row_order_key(rows_by_id, fail_stage, kind, atom),
                    )
                    for kind, fail_stage, atom in failures
                ],
                key=lambda item: item[4],
            )
            kind, fail_stage, mode, name, _key = ordered[0]
            first_failure = f"{fail_stage}:{kind}:{mode}:{name}"
            failure_obj = _stage_failure(
                rows_by_id,
                fail_stage,
                kind,
                next(
                    atom
                    for failure_kind, stage_name, atom in failures
                    if failure_kind == kind
                    and stage_name == fail_stage
                    and atom.mode == mode
                    and atom.name == name
                ),
            )
            break
        last_passed = stage

    sem = exec_spec.candidate_semantics.get(candidate, candidate)
    release_safe = first_failure is None or not first_failure.startswith("release_safe:")
    return StageEvidence(
        candidate=candidate,
        last_passed=last_passed,
        semantic_class=sem,
        first_failure=first_failure,
        failure=failure_obj if first_failure is not None else None,
        comparison_bundle=_bundle(atoms, "cmp"),
        floor_bundle=_bundle(atoms, "floor"),
        diagnostic_bundle=_bundle(atoms, "diag"),
        obstruction_bundle=tuple(
            sorted(name for name in _bundle(atoms, "diag") if name.startswith(("ob", "lb", "rig")))
        ),
        release_safe=release_safe,
        atoms=atoms,
        s=last_passed,
        q=sem,
        phi=first_failure,
        gamma=_bundle(atoms, "cmp"),
        ell=_bundle(atoms, "floor"),
        delta=_bundle(atoms, "diag"),
        omega=tuple(
            sorted(name for name in _bundle(atoms, "diag") if name.startswith(("ob", "lb", "rig")))
        ),
        alpha=release_safe,
    )


def all_stage_evidence(
    spec: ExecutableBandSpec, record: str | FiniteRecord
) -> dict[str, StageEvidence]:
    exec_spec = as_exec_spec(spec)
    return {
        candidate: stage_evidence(exec_spec, record, candidate)
        for candidate in exec_spec.candidates
    }


def selected_kernel(spec: ExecutableBandSpec, record: str | FiniteRecord) -> tuple[str, ...]:
    exec_spec = as_exec_spec(spec)
    selected: set[str] = set()
    for candidate, evidence in all_stage_evidence(exec_spec, record).items():
        if evidence.first_failure is None and any(
            atom.key == ("floor", f"sel_{candidate}") for atom in evidence.atoms
        ):
            selected.add(exec_spec.candidate_semantics.get(candidate, candidate))
    return tuple(sorted(selected))


def applicability_support(spec: ExecutableBandSpec, record: str | FiniteRecord) -> Preorder:
    """Compute the finite applicability-support preorder on candidate ids.

    The orientation follows the paper: ``c <= d`` when the evidence carried by
    `d` derives the evidence needed for `c`.
    """

    exec_spec = as_exec_spec(spec)
    evidence_by_candidate = all_stage_evidence(exec_spec, record)
    active_candidates = tuple(
        candidate
        for candidate in exec_spec.candidates
        if evidence_by_candidate[candidate].first_failure is None
    )
    pairs: set[tuple[str, str]] = set()
    for c in active_candidates:
        for d in active_candidates:
            if stage_implication(
                exec_spec, evidence_by_candidate[d].atoms, evidence_by_candidate[c].atoms
            ):
                pairs.add((c, d))
    return Preorder(elements=active_candidates, pairs=frozenset(pairs))
