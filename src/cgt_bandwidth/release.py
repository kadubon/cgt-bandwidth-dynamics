"""Release certificates, raw release graph, and quotient-level release actions."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .closure import close_store
from .core import (
    ExecutableBandSpec,
    FiniteRecord,
    ReleaseCertificate,
    ReportLens,
    as_exec_spec,
    freeze_value,
)


@dataclass(frozen=True)
class AmbientRowUniverse:
    record_id: str
    row_ids: tuple[str, ...]
    semantic_ids: tuple[str, ...] = ()
    candidate_ids: tuple[str, ...] = ()
    release_ids: tuple[str, ...] = ()
    authority_ids: tuple[str, ...] = ()

    @classmethod
    def for_record(cls, spec: ExecutableBandSpec, record: str | FiniteRecord) -> AmbientRowUniverse:
        rec = spec.record(record)
        store = close_store(spec, rec)
        row_ids = ambient_row_universe(spec)
        return cls(
            record_id=rec.id,
            row_ids=tuple(sorted(row_ids)),
            semantic_ids=tuple(sorted({row.sem for row in store.all_rows})),
            candidate_ids=tuple(sorted(spec.candidates)),
            release_ids=tuple(sorted(cert.id for cert in spec.releases)),
            authority_ids=tuple(
                sorted(
                    str(row.payload.get("authority"))
                    for row in store.all_rows
                    if row.payload.get("authority")
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "row_ids": list(self.row_ids),
            "semantic_ids": list(self.semantic_ids),
            "candidate_ids": list(self.candidate_ids),
            "release_ids": list(self.release_ids),
            "authority_ids": list(self.authority_ids),
        }


@dataclass(frozen=True)
class AmbientStoreEnumerator:
    universe: AmbientRowUniverse
    candidate_store_count: int
    rejected_rows: tuple[str, ...] = ()
    bound_exhausted: bool = False

    @property
    def passed(self) -> bool:
        return not self.rejected_rows and not self.bound_exhausted

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "universe": self.universe.to_dict(),
            "candidate_store_count": self.candidate_store_count,
            "rejected_rows": list(self.rejected_rows),
            "bound_exhausted": self.bound_exhausted,
        }


@dataclass(frozen=True)
class ReleaseTransformationCertificate:
    certificate_id: str
    source: str
    target: str
    footprint: tuple[str, ...]
    changed_rows: tuple[str, ...]
    new_rows: tuple[str, ...]
    outside_footprint_changed: tuple[str, ...]
    no_new_row_passed: bool
    noninterference_passed: bool

    @property
    def passed(self) -> bool:
        return self.no_new_row_passed and self.noninterference_passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "source": self.source,
            "target": self.target,
            "footprint": list(self.footprint),
            "changed_rows": list(self.changed_rows),
            "new_rows": list(self.new_rows),
            "outside_footprint_changed": list(self.outside_footprint_changed),
            "no_new_row_passed": self.no_new_row_passed,
            "noninterference_passed": self.noninterference_passed,
            "passed": self.passed,
        }


@dataclass(frozen=True)
class CertifiedExactReleaseCertificate:
    certificate_id: str
    passed: bool
    check_result: ReleaseCheckResult
    transformation: ReleaseTransformationCertificate
    ambient_source: AmbientStoreEnumerator
    ambient_target: AmbientStoreEnumerator
    problems: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "passed": self.passed,
            "check_result": self.check_result.to_dict(),
            "transformation": self.transformation.to_dict(),
            "ambient_source": self.ambient_source.to_dict(),
            "ambient_target": self.ambient_target.to_dict(),
            "problems": list(self.problems),
        }


@dataclass(frozen=True)
class ReleaseGraph:
    edges: frozenset[tuple[str, str, str]]

    def outgoing(self, source: str) -> tuple[tuple[str, str], ...]:
        return tuple(
            sorted((target, cert_id) for src, target, cert_id in self.edges if src == source)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "edges": [
                {"source": s, "target": t, "certificate": c} for s, t, c in sorted(self.edges)
            ]
        }


@dataclass(frozen=True)
class ReleaseCheckResult:
    passed: bool
    trace: tuple[str, ...] = ()
    predicate_results: Mapping[str, bool] | None = None
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "trace": list(self.trace),
            "predicate_results": dict(self.predicate_results or {}),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class ReleasePredicateWitness:
    certificate_id: str
    predicate: str
    coordinate: str
    passed: bool
    detail: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "predicate": self.predicate,
            "coordinate": self.coordinate,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ReleaseCongruencePair:
    certificate_id: str
    peer_certificate_id: str
    source: str
    peer_source: str
    support_signature_equal: bool
    footprint_signature_equal: bool
    target_class_equal: bool
    one_step_bisimulation: bool

    @property
    def passed(self) -> bool:
        return (
            self.support_signature_equal
            and self.footprint_signature_equal
            and self.target_class_equal
            and self.one_step_bisimulation
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "peer_certificate_id": self.peer_certificate_id,
            "source": self.source,
            "peer_source": self.peer_source,
            "support_signature_equal": self.support_signature_equal,
            "footprint_signature_equal": self.footprint_signature_equal,
            "target_class_equal": self.target_class_equal,
            "one_step_bisimulation": self.one_step_bisimulation,
            "passed": self.passed,
        }


@dataclass(frozen=True)
class ReleaseDescentProof:
    certificate_id: str
    congruence_pairs: tuple[ReleaseCongruencePair, ...] = ()
    predicate_witnesses: tuple[ReleasePredicateWitness, ...] = ()

    @property
    def passed(self) -> bool:
        return all(pair.passed for pair in self.congruence_pairs) and all(
            witness.passed for witness in self.predicate_witnesses
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "passed": self.passed,
            "congruence_pairs": [pair.to_dict() for pair in self.congruence_pairs],
            "predicate_witnesses": [witness.to_dict() for witness in self.predicate_witnesses],
        }


@dataclass(frozen=True)
class ReleaseDescentCertificate:
    certificate_id: str
    source_class: tuple[str, ...]
    target_class: tuple[str, ...]
    support_signature: Any
    local_stability: Mapping[str, bool]
    one_step_bisimulation: bool
    certificate_congruence: bool = True
    local_stability_witnesses: Mapping[str, Any] | None = None
    one_step_witness: Mapping[str, Any] | None = None
    descent_proof: ReleaseDescentProof | None = None

    @property
    def passed(self) -> bool:
        return (
            self.certificate_congruence
            and self.one_step_bisimulation
            and all(self.local_stability.values())
            and (self.descent_proof.passed if self.descent_proof else True)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate": self.certificate_id,
            "source_class": list(self.source_class),
            "target_class": list(self.target_class),
            "support_signature": self.support_signature,
            "local_stability": dict(self.local_stability),
            "certificate_congruence": self.certificate_congruence,
            "one_step_bisimulation": self.one_step_bisimulation,
            "local_stability_witnesses": dict(self.local_stability_witnesses or {}),
            "one_step_witness": dict(self.one_step_witness or {}),
            "descent_proof": self.descent_proof.to_dict() if self.descent_proof else None,
            "passed": self.passed,
        }


@dataclass(frozen=True)
class ReleaseActionCertificate:
    """Certificate view of release-action descent to completion classes."""

    relation: Mapping[tuple[str, ...], tuple[tuple[str, ...], ...]]
    accepted_certificates: tuple[str, ...] = ()
    skipped_certificates: Mapping[str, tuple[str, ...]] | None = None
    check_results: Mapping[str, ReleaseCheckResult] | None = None
    descent_certificates: Mapping[str, ReleaseDescentCertificate] | None = None
    descent_proofs: Mapping[str, ReleaseDescentProof] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cgt-bandwidth.release-descent.v1",
            "relation": {
                repr(source): [list(target) for target in targets]
                for source, targets in sorted(self.relation.items(), key=lambda item: repr(item[0]))
            },
            "accepted_certificates": list(self.accepted_certificates),
            "skipped_certificates": {
                cert_id: list(reasons)
                for cert_id, reasons in sorted((self.skipped_certificates or {}).items())
            },
            "check_results": {
                cert_id: result.to_dict()
                for cert_id, result in sorted((self.check_results or {}).items())
            },
            "descent_certificates": {
                cert_id: cert.to_dict()
                for cert_id, cert in sorted((self.descent_certificates or {}).items())
            },
            "descent_proofs": {
                cert_id: proof.to_dict()
                for cert_id, proof in sorted((self.descent_proofs or {}).items())
            },
        }


def ambient_row_universe(spec: ExecutableBandSpec) -> frozenset[str]:
    rows = {row.rid for record in spec.audit_universe for row in record.rows}
    rows.update(row.rid for candidate in spec.cand_enum.values() for row in candidate.rows)
    rows.update(row.rid for rule in spec.store_step_rules for row in rule.emits)
    rows.update(spec.release_check_table.allowed_new_rows)
    return frozenset(rows)


def ambient_store_enumerator(
    spec: ExecutableBandSpec, record: str | FiniteRecord
) -> AmbientStoreEnumerator:
    rec = spec.record(record)
    store = close_store(spec, rec)
    row_ids = ambient_row_universe(spec)
    rejected = tuple(sorted(row.rid for row in store.all_rows if row.rid not in row_ids))
    universe = AmbientRowUniverse.for_record(spec, rec)
    candidate_store_count = 2 ** min(len(row_ids), spec.work_bounds.branch_depth)
    return AmbientStoreEnumerator(
        universe=universe,
        candidate_store_count=candidate_store_count,
        rejected_rows=rejected,
        bound_exhausted=candidate_store_count > spec.work_bounds.release_checks,
    )


def _diagnostic_debt_names(store: Any) -> set[str]:
    names: set[str] = set()
    for row in store.all_rows:
        if row.payload.get("debt", False):
            names.update(atom.name for atom in row.atoms() if atom.mode == "diag")
    return names


def check_release(
    spec: ExecutableBandSpec, cert: ReleaseCertificate, strict: bool = False
) -> ReleaseCheckResult:
    trace: list[str] = []
    errors: list[str] = []
    predicates: dict[str, bool] = {}
    failed = False

    def reject(message: str) -> None:
        nonlocal failed
        failed = True
        errors.append(message)
        trace.append(message)

    def predicate(name: str, ok: bool, message: str | None = None) -> None:
        predicates[name] = bool(ok)
        if not ok and message:
            reject(message)

    if cert.source not in spec.records or cert.target not in spec.records:
        return ReleaseCheckResult(
            False, ("missing-source-or-target",), {}, ("missing-source-or-target",)
        )
    source_store = close_store(spec, cert.source)
    target_store = close_store(spec, cert.target)
    ambient = ambient_row_universe(spec)
    if strict:
        source_ambient = ambient_store_enumerator(spec, cert.source)
        target_ambient = ambient_store_enumerator(spec, cert.target)
        predicate(
            "ambientSource",
            source_ambient.passed,
            (
                f"ambient-source-rejected:{','.join(source_ambient.rejected_rows)}"
                if source_ambient.rejected_rows
                else "ambient-source-bound-exhausted"
                if source_ambient.bound_exhausted
                else None
            ),
        )
        predicate(
            "ambientTarget",
            target_ambient.passed,
            (
                f"ambient-target-rejected:{','.join(target_ambient.rejected_rows)}"
                if target_ambient.rejected_rows
                else "ambient-target-bound-exhausted"
                if target_ambient.bound_exhausted
                else None
            ),
        )
    declared_predicates = spec.release_check_table.declared_predicates_for(cert.id)
    if strict:
        missing_declared = set(spec.release_check_table.required_predicates) - set(
            declared_predicates
        )
        predicate(
            "footprintPredicateTable",
            not missing_declared,
            f"release-predicate-table-incomplete:{','.join(sorted(missing_declared))}"
            if missing_declared
            else None,
        )
    for pred_name, pred_ok in sorted(declared_predicates.items()):
        pred_coords = spec.release_check_table.declared_predicate_coordinates_for(
            cert.id, pred_name
        )
        if strict:
            predicate(
                f"predicateCoordinatesDeclared:{pred_name}",
                bool(pred_coords),
                f"predicate-coordinates-missing:{pred_name}" if not pred_coords else None,
            )
        if pred_coords:
            outside_predicate = set(pred_coords) - set(cert.footprint)
            predicate(
                f"predicateCoordinates:{pred_name}",
                not outside_predicate,
                f"predicate-coordinates-outside-footprint:{pred_name}:"
                f"{','.join(sorted(outside_predicate))}"
                if outside_predicate
                else None,
            )
        predicate(
            f"declaredPredicate:{pred_name}",
            bool(pred_ok),
            f"declared-predicate-failed:{pred_name}" if not pred_ok else None,
        )
    declared_coords = spec.release_check_table.declared_coordinates_for(cert.id)
    if strict:
        predicate(
            "footprintCoordinatesDeclared",
            bool(declared_coords),
            "footprint-coordinates-missing" if not declared_coords else None,
        )
    if declared_coords:
        outside_declared = set(cert.footprint) - set(declared_coords)
        predicate(
            "footprintCoordinates",
            not outside_declared,
            f"footprint-outside-declared-coordinates:{','.join(sorted(outside_declared))}"
            if outside_declared
            else None,
        )
    predicate("footprint", bool(cert.footprint), "missing-footprint")
    outside_footprint = set(cert.footprint) - ambient
    predicate(
        "footprintAmbient",
        not outside_footprint,
        f"footprint-outside-ambient:{','.join(sorted(outside_footprint))}"
        if outside_footprint
        else None,
    )
    target_new = set(target_store.by_id()) - set(source_store.by_id())
    unallowed_new = (
        target_new - set(spec.release_check_table.allowed_new_rows) - set(cert.footprint)
    )
    predicate(
        "noNewRow",
        cert.no_new_rows and not unallowed_new,
        f"new-row:{','.join(sorted(unallowed_new))}" if unallowed_new else "no-new-row-failed",
    )
    if strict:
        missing_discharge_map = set(cert.discharges) - set(cert.discharge_map)
        missing_preservation_map = set(cert.preserves) - set(cert.preservation_map)
        missing_retyping_map = set(cert.diagnostic_retyping) - set(cert.retyping_map)
        predicate(
            "strictDischargeMapTotal",
            not missing_discharge_map,
            f"strict-discharge-map-missing:{','.join(sorted(missing_discharge_map))}"
            if missing_discharge_map
            else None,
        )
        predicate(
            "strictPreservationMapTotal",
            not missing_preservation_map,
            f"strict-preservation-map-missing:{','.join(sorted(missing_preservation_map))}"
            if missing_preservation_map
            else None,
        )
        predicate(
            "strictRetypingMapTotal",
            not missing_retyping_map,
            f"strict-retyping-map-missing:{','.join(sorted(missing_retyping_map))}"
            if missing_retyping_map
            else None,
        )
        predicate(
            "strictCheckerTracePresent",
            bool(cert.checker_trace),
            "strict-checker-trace-missing" if not cert.checker_trace else None,
        )
    source_obstructions = set()
    if cert.source != cert.target:
        source_obstructions = _diagnostic_debt_names(source_store) & set(
            spec.release_check_table.obstruction_rows
        )
    undischarged = source_obstructions - set(cert.discharges)
    predicate(
        "obstructionCoverage",
        not undischarged,
        f"undischarged:{','.join(sorted(undischarged))}" if undischarged else None,
    )
    source_lower = _diagnostic_debt_names(source_store) & set(
        spec.release_check_table.lower_bound_rows
    )
    lower_successors = (
        set(cert.preserves) | set(cert.preservation_map) | set(cert.preservation_map.values())
    )
    unrepaired_lower = source_lower - lower_successors
    predicate(
        "lowerBoundSuccessor",
        not unrepaired_lower,
        f"lower-bound-unrepaired:{','.join(sorted(unrepaired_lower))}"
        if unrepaired_lower
        else None,
    )
    source_rows = source_store.by_id()
    target_rows = target_store.by_id()
    footprint = set(cert.footprint)
    changed_outside = [
        rid
        for rid in sorted(set(source_rows) & set(target_rows) - footprint)
        if source_rows[rid].congruence_key() != target_rows[rid].congruence_key()
    ]
    predicate(
        "noninterference",
        cert.noninterference and not changed_outside,
        f"outside-footprint-changed:{','.join(changed_outside)}"
        if changed_outside
        else "noninterference-failed",
    )
    target_debt = _diagnostic_debt_names(target_store)
    new_obstructions = (
        target_debt & set(spec.release_check_table.obstruction_rows) - source_obstructions
    )
    uncovered_new = new_obstructions - set(cert.no_new_obstructions)
    predicate(
        "noNewObstruction",
        not uncovered_new,
        f"new-obstruction:{','.join(sorted(uncovered_new))}" if uncovered_new else None,
    )
    retyping_ok = not source_obstructions or bool(
        cert.diagnostic_retyping or cert.retyping_map or cert.discharges
    )
    predicate("diagnosticRetyping", retyping_ok, "diagnostic-retyping-missing")
    required_local_stability = (
        "FootprintDet",
        "ComponentDebtPres",
        "StageStab",
        "SelKerStab",
        "OneStepReleaseBisim",
    )
    if strict:
        for name in required_local_stability:
            declared = name in cert.local_stability_declared
            predicate(
                f"localStabilityDeclared:{name}",
                declared,
                f"local-stability-defaulted:{name}" if not declared else None,
            )
    for name, ok in cert.local_stability.items():
        predicates[name] = bool(ok)
        if not ok:
            reject(f"local-stability:{name}")
    if cert.checker_trace:
        trace.extend(cert.checker_trace)
        if any(
            item in {"fail", "failed"} or item.endswith("-failed") for item in cert.checker_trace
        ):
            failed = True
    passed = not failed and all(predicates.values())
    return ReleaseCheckResult(passed, tuple(trace or ("pass",)), predicates, tuple(errors))


def release_transformation_certificate(
    spec: ExecutableBandSpec, cert: ReleaseCertificate
) -> ReleaseTransformationCertificate:
    source_store = close_store(spec, cert.source)
    target_store = close_store(spec, cert.target)
    source_rows = source_store.by_id()
    target_rows = target_store.by_id()
    footprint = set(cert.footprint)
    changed = tuple(
        sorted(
            rid
            for rid in set(source_rows) & set(target_rows)
            if source_rows[rid].congruence_key() != target_rows[rid].congruence_key()
        )
    )
    new_rows = tuple(sorted(set(target_rows) - set(source_rows)))
    outside_changed = tuple(sorted(rid for rid in changed if rid not in footprint))
    unallowed_new = set(new_rows) - set(spec.release_check_table.allowed_new_rows) - footprint
    return ReleaseTransformationCertificate(
        certificate_id=cert.id,
        source=cert.source,
        target=cert.target,
        footprint=tuple(sorted(footprint)),
        changed_rows=changed,
        new_rows=new_rows,
        outside_footprint_changed=outside_changed,
        no_new_row_passed=cert.no_new_rows and not unallowed_new,
        noninterference_passed=cert.noninterference and not outside_changed,
    )


def certified_exact_release_certificate(
    spec: ExecutableBandSpec, cert: ReleaseCertificate
) -> CertifiedExactReleaseCertificate:
    check = check_release(spec, cert, strict=True)
    transformation = release_transformation_certificate(spec, cert)
    ambient_source = ambient_store_enumerator(spec, cert.source)
    ambient_target = ambient_store_enumerator(spec, cert.target)
    problems = tuple(
        sorted(
            set(check.errors)
            | set(() if transformation.passed else ("store-transformation-failed",))
            | set(() if ambient_source.passed else ("ambient-source-failed",))
            | set(() if ambient_target.passed else ("ambient-target-failed",))
        )
    )
    return CertifiedExactReleaseCertificate(
        certificate_id=cert.id,
        passed=check.passed
        and transformation.passed
        and ambient_source.passed
        and ambient_target.passed,
        check_result=check,
        transformation=transformation,
        ambient_source=ambient_source,
        ambient_target=ambient_target,
        problems=problems,
    )


def release_graph(spec: ExecutableBandSpec, *, strict: bool = True) -> ReleaseGraph:
    exec_spec = as_exec_spec(spec)
    edges = frozenset(
        (cert.source, cert.target, cert.id)
        for cert in exec_spec.releases
        if cert.accepted and check_release(exec_spec, cert, strict=strict).passed
    )
    return ReleaseGraph(edges=edges)


def _band_row_reading(spec: ExecutableBandSpec, record: FiniteRecord) -> Any:
    store = close_store(spec, record)
    coords = spec.band_rows or tuple(row.rid for row in store.rows)
    return store.restriction(coords)


def action_signature(
    spec: ExecutableBandSpec,
    record: str | FiniteRecord,
    lens: ReportLens,
    *,
    strict: bool = True,
) -> tuple[Any, ...]:
    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    signatures: list[Any] = []
    for cert in sorted(exec_spec.releases, key=lambda c: c.id):
        check = check_release(exec_spec, cert, strict=strict)
        if cert.source != rec.id or not cert.accepted or not check.passed:
            continue
        if cert.target == rec.id and cert.signature.get("kind") == "identity":
            continue
        target = exec_spec.record(cert.target)
        source_store = close_store(exec_spec, rec)
        target_store = close_store(exec_spec, target)
        source_values = dict(source_store.restriction(cert.footprint))
        target_values = dict(target_store.restriction(cert.footprint))
        delta = {
            key: (source_values.get(key), target_values.get(key))
            for key in sorted(set(source_values) | set(target_values))
            if source_values.get(key) != target_values.get(key)
        }
        signatures.append(
            cert.foot_sig(
                lens.read(target),
                _band_row_reading(exec_spec, target),
                delta | {"trace": check.trace},
                source_footprint_reading=source_store.restriction(cert.footprint),
                checker_verdict=check.to_dict(),
            )
        )
    return tuple(sorted(signatures))


def _outgoing_congruence_signatures(
    spec: ExecutableBandSpec,
    record: str | FiniteRecord,
    lens: ReportLens,
    *,
    strict: bool = True,
) -> tuple[Any, ...]:
    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    signatures: list[Any] = []
    for cert in sorted(exec_spec.releases, key=lambda item: item.id):
        check = check_release(exec_spec, cert, strict=strict)
        if cert.source != rec.id or not cert.accepted or not check.passed:
            continue
        if cert.target == rec.id and cert.signature.get("kind") == "identity":
            continue
        target = exec_spec.record(cert.target)
        source_store = close_store(exec_spec, rec)
        signatures.append(
            cert.foot_sig(
                lens.read(target),
                _band_row_reading(exec_spec, target),
                {"check": check.to_dict()},
                source_footprint_reading=source_store.restriction(cert.footprint),
                checker_verdict=check.to_dict(),
            )
        )
    return tuple(sorted(signatures, key=repr))


def _one_step_release_bisim_holds(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    source_class: tuple[str, ...],
    *,
    strict: bool = True,
) -> bool:
    signatures = [
        _outgoing_congruence_signatures(spec, record_id, lens, strict=strict)
        for record_id in source_class
    ]
    return all(signature == signatures[0] for signature in signatures[1:])


def raw_release_closure(
    spec: ExecutableBandSpec,
    record: str | FiniteRecord,
    lens: ReportLens,
    *,
    strict: bool = True,
) -> tuple[Any, ...]:
    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    graph = release_graph(exec_spec, strict=strict)
    cert_by_id = {cert.id: cert for cert in exec_spec.releases}
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(rec.id, ())])
    seen_states: set[tuple[str, tuple[str, ...]]] = set()
    outputs: set[Any] = set()
    max_path_len = max(len(exec_spec.releases), len(exec_spec.records), 1)

    while queue:
        current, path = queue.popleft()
        state = (current, path)
        if state in seen_states:
            continue
        seen_states.add(state)
        current_record = exec_spec.record(current)
        from .bandwidth import is_in_band

        if is_in_band(exec_spec, current_record):
            outputs.add(
                freeze_value(
                    (
                        lens.read(current_record),
                        _band_row_reading(exec_spec, current_record),
                        path or ("idPath",),
                    )
                )
            )
        for target, cert_id in graph.outgoing(current):
            cert = cert_by_id[cert_id]
            if target == current and cert.signature.get("kind") == "identity":
                continue
            if cert_id in path:
                continue
            next_path = (*path, cert_id)
            if len(next_path) <= max_path_len:
                queue.append((target, next_path))
    return tuple(sorted(outputs, key=repr))


def raw_release_closure_exact(
    spec: ExecutableBandSpec, record: str | FiniteRecord, lens: ReportLens
) -> tuple[Any, ...]:
    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    exact_edges = frozenset(
        (cert.source, cert.target, cert.id)
        for cert in exec_spec.releases
        if cert.accepted and certified_exact_release_certificate(exec_spec, cert).passed
    )
    graph = ReleaseGraph(exact_edges)
    cert_by_id = {cert.id: cert for cert in exec_spec.releases}
    queue: deque[tuple[str, tuple[str, ...]]] = deque([(rec.id, ())])
    seen_states: set[tuple[str, tuple[str, ...]]] = set()
    outputs: set[Any] = set()
    max_path_len = max(len(exec_spec.releases), len(exec_spec.records), 1)

    while queue:
        current, path = queue.popleft()
        state = (current, path)
        if state in seen_states:
            continue
        seen_states.add(state)
        current_record = exec_spec.record(current)
        from .bandwidth import is_in_band

        if is_in_band(exec_spec, current_record):
            outputs.add(
                freeze_value(
                    (
                        lens.read(current_record),
                        _band_row_reading(exec_spec, current_record),
                        path or ("idPath",),
                    )
                )
            )
        for target, cert_id in graph.outgoing(current):
            cert = cert_by_id[cert_id]
            if target == current and cert.signature.get("kind") == "identity":
                continue
            if cert_id in path:
                continue
            next_path = (*path, cert_id)
            if len(next_path) <= max_path_len:
                queue.append((target, next_path))
    return tuple(sorted(outputs, key=repr))


def release_action_certificate(
    spec: ExecutableBandSpec, lens: ReportLens, strict: bool = True
) -> ReleaseActionCertificate:
    exec_spec = as_exec_spec(spec)
    from .completion import completion_classes

    completion = completion_classes(exec_spec, lens, strict_release=strict)
    relation: dict[tuple[str, ...], set[tuple[str, ...]]] = defaultdict(set)
    accepted: list[str] = []
    skipped: dict[str, tuple[str, ...]] = {}
    checks: dict[str, ReleaseCheckResult] = {}
    descent: dict[str, ReleaseDescentCertificate] = {}
    proofs: dict[str, ReleaseDescentProof] = {}
    from .support import support_signature

    for cert in exec_spec.releases:
        reasons: list[str] = []
        check = check_release(exec_spec, cert, strict=strict)
        checks[cert.id] = check
        if not cert.accepted:
            reasons.append("certificate-not-accepted")
        if not cert.stable:
            reasons.append("certificate-not-stable")
        if not check.passed:
            reasons.append("checker-failed")
        if reasons:
            skipped[cert.id] = tuple(reasons)
            continue
        source_class = completion.class_of(cert.source)
        support_signatures = {
            record_id: support_signature(exec_spec, lens, record_id, strict_release=strict)
            for record_id in source_class
        }
        certificate_congruence = (
            len({freeze_value(value) for value in support_signatures.values()}) <= 1
        )
        one_step = _one_step_release_bisim_holds(exec_spec, lens, source_class, strict=strict)
        target_class = completion.class_of(cert.target)
        outgoing_witness = {
            record_id: _outgoing_congruence_signatures(exec_spec, record_id, lens, strict=strict)
            for record_id in source_class
        }
        predicate_witnesses: list[ReleasePredicateWitness] = []
        declared_coords = exec_spec.release_check_table.declared_coordinates_for(cert.id) or ("*",)
        for predicate_name, predicate_passed in sorted((check.predicate_results or {}).items()):
            for coord in declared_coords:
                predicate_witnesses.append(
                    ReleasePredicateWitness(
                        certificate_id=cert.id,
                        predicate=predicate_name,
                        coordinate=coord,
                        passed=predicate_passed,
                    )
                )
        congruence_pairs: list[ReleaseCongruencePair] = []
        source_signature = freeze_value(
            support_signature(exec_spec, lens, cert.source, strict_release=strict)
        )
        source_footprint = freeze_value(
            _outgoing_congruence_signatures(exec_spec, cert.source, lens, strict=strict)
        )
        for peer in exec_spec.releases:
            peer_check = checks.get(peer.id) or check_release(exec_spec, peer, strict=strict)
            checks.setdefault(peer.id, peer_check)
            if not peer.accepted or not peer_check.passed:
                continue
            try:
                peer_source_class = completion.class_of(peer.source)
                peer_target_class = completion.class_of(peer.target)
            except KeyError:
                continue
            if peer_source_class != source_class:
                continue
            peer_signature = freeze_value(
                support_signature(exec_spec, lens, peer.source, strict_release=strict)
            )
            peer_footprint = freeze_value(
                _outgoing_congruence_signatures(exec_spec, peer.source, lens, strict=strict)
            )
            congruence_pairs.append(
                ReleaseCongruencePair(
                    certificate_id=cert.id,
                    peer_certificate_id=peer.id,
                    source=cert.source,
                    peer_source=peer.source,
                    support_signature_equal=source_signature == peer_signature,
                    footprint_signature_equal=source_footprint == peer_footprint,
                    target_class_equal=target_class == peer_target_class,
                    one_step_bisimulation=one_step
                    and _one_step_release_bisim_holds(
                        exec_spec, lens, peer_source_class, strict=strict
                    ),
                )
            )
        proof = ReleaseDescentProof(
            certificate_id=cert.id,
            congruence_pairs=tuple(congruence_pairs),
            predicate_witnesses=tuple(predicate_witnesses),
        )
        proofs[cert.id] = proof
        descent[cert.id] = ReleaseDescentCertificate(
            certificate_id=cert.id,
            source_class=source_class,
            target_class=target_class,
            support_signature=support_signature(
                exec_spec, lens, cert.source, strict_release=strict
            ),
            local_stability=cert.local_stability,
            certificate_congruence=certificate_congruence,
            one_step_bisimulation=one_step,
            local_stability_witnesses={
                name: {
                    "passed": passed,
                    "declared": name in cert.local_stability_declared,
                }
                for name, passed in sorted(cert.local_stability.items())
            },
            one_step_witness={
                record_id: list(signatures)
                for record_id, signatures in sorted(outgoing_witness.items())
            },
            descent_proof=proof,
        )
        if not certificate_congruence:
            skipped[cert.id] = ("certificate-congruence-failed",)
            continue
        if not one_step:
            skipped[cert.id] = ("one-step-release-bisim-failed",)
            continue
        if strict and not proof.passed:
            skipped[cert.id] = ("release-descent-proof-failed",)
            continue
        relation[source_class].add(target_class)
        accepted.append(cert.id)
    return ReleaseActionCertificate(
        relation={src: tuple(sorted(targets)) for src, targets in relation.items()},
        accepted_certificates=tuple(sorted(accepted)),
        skipped_certificates=skipped,
        check_results=checks,
        descent_certificates=descent,
        descent_proofs=proofs,
    )


def release_action(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict: bool = True
) -> dict[tuple[str, ...], tuple[tuple[str, ...], ...]]:
    return dict(release_action_certificate(spec, lens, strict=strict).relation)


def release_closure_fixed_point(
    spec: ExecutableBandSpec, start: str, *, strict: bool = True
) -> tuple[str, ...]:
    graph = release_graph(spec, strict=strict)
    reached = {start}
    changed = True
    while changed:
        changed = False
        for source, target, _cert in graph.edges:
            if source in reached and target not in reached:
                reached.add(target)
                changed = True
    return tuple(sorted(reached))


def _legacy_release_certificate_exact(cert: ReleaseCertificate) -> bool:
    return (
        cert.exact
        and cert.no_new_rows
        and cert.noninterference
        and all(cert.local_stability.values())
        and bool(cert.discharges or cert.source == cert.target)
    )
