"""Bounded closure stores and row-checker support."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .core import (
    ClosureStore,
    ExecutableBandSpec,
    FiniteRecord,
    Row,
    RuleTableCertificate,
    StoreStepCertificate,
    as_exec_spec,
)


def _failure_row(source: Row, problem: str) -> Row:
    return Row(
        rid=f"fail::{source.rid}::{problem}",
        kind="failure",
        sem=f"failure:{source.sem}",
        verdict="fail",
        retention="retained",
        refs=(),
        payload={
            "problem": problem,
            "source": source.rid,
            "atoms": [{"mode": "diag", "name": f"fail_{source.rid}", "origin": source.rid}],
        },
        mode="diag",
    )


@dataclass(frozen=True)
class RowCheckerResult:
    row_id: str
    passed: bool
    fail_rows: tuple[Row, ...] = ()
    derived_rows: tuple[Row, ...] = ()
    checked_refs: tuple[str, ...] = ()
    trace: tuple[str, ...] = ()
    checker_id: str = "row-schema-totality"
    enabled_step_id: str = ""
    provenance: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "row_id": self.row_id,
            "passed": self.passed,
            "checker_id": self.checker_id,
            "enabled_step_id": self.enabled_step_id,
            "fail_rows": [row.to_dict() for row in self.fail_rows],
            "derived_rows": [row.to_dict() for row in self.derived_rows],
            "checked_refs": list(self.checked_refs),
            "trace": list(self.trace),
            "provenance": dict(self.provenance or {}),
        }


@dataclass(frozen=True)
class StoreStepTrace:
    step: int
    row_id: str
    action: str
    source: str
    emitted_rows: tuple[str, ...] = ()
    retained_failures: tuple[str, ...] = ()
    trace: tuple[str, ...] = ()
    checker_id: str = ""
    provenance: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "row_id": self.row_id,
            "action": self.action,
            "source": self.source,
            "checker_id": self.checker_id,
            "emitted_rows": list(self.emitted_rows),
            "retained_failures": list(self.retained_failures),
            "trace": list(self.trace),
            "provenance": dict(self.provenance or {}),
        }


@dataclass(frozen=True)
class ClosureCertificate:
    store: ClosureStore
    row_results: tuple[RowCheckerResult, ...]
    steps: tuple[StoreStepTrace, ...]
    boundary_rows: tuple[str, ...] = ()
    rule_table: RuleTableCertificate | None = None
    accepted_rows: tuple[str, ...] = ()
    failure_rows: tuple[str, ...] = ()
    candidate_rows: tuple[str, ...] = ()
    derived_rows: tuple[str, ...] = ()
    fixed_point_reason: str = "pending-empty"
    bound_exhaustion_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "cgt-bandwidth.closure-certificate.v1",
            "store": self.store.to_dict(),
            "row_results": [result.to_dict() for result in self.row_results],
            "steps": [step.to_dict() for step in self.steps],
            "boundary_rows": list(self.boundary_rows),
            "rule_table": self.rule_table.to_dict() if self.rule_table else None,
            "accepted_rows": list(self.accepted_rows),
            "failure_rows": list(self.failure_rows),
            "candidate_rows": list(self.candidate_rows),
            "derived_rows": list(self.derived_rows),
            "fixed_point_reason": self.fixed_point_reason,
            "bound_exhaustion_reason": self.bound_exhaustion_reason,
        }


def check_row_result(
    spec: ExecutableBandSpec,
    row: Row,
    known_row_ids: frozenset[str] | None = None,
    *,
    enabled_step_id: str = "",
    source: str = "row",
    strict: bool = False,
) -> RowCheckerResult:
    """Total row checker with retained proof data."""

    checker_id = "row-schema-totality"
    trace: list[str] = [
        f"check:{row.rid}",
        f"step:{enabled_step_id or row.rid}",
        f"kind:{row.kind}",
        f"verdict:{row.verdict}",
    ]
    schema = spec.row_schemas.get(row.kind)
    checked_refs = tuple(row.refs)
    failures: list[Row] = []
    if schema is None:
        failures.append(_failure_row(row, "missing_schema"))
        trace.append("fail:missing_schema")
    else:
        ok, problems = schema.validate(row)
        if not ok:
            failures.extend(_failure_row(row, problem) for problem in problems)
            trace.extend(f"fail:{problem}" for problem in problems)
        if known_row_ids is not None:
            for ref in row.refs:
                if ref not in known_row_ids:
                    failures.append(_failure_row(row, f"unknown_ref:{ref}"))
                    trace.append(f"fail:unknown_ref:{ref}")
    if failures:
        return RowCheckerResult(
            row_id=row.rid,
            passed=False,
            fail_rows=tuple(failures),
            checked_refs=checked_refs,
            trace=tuple(trace),
            checker_id=checker_id,
            enabled_step_id=enabled_step_id,
            provenance={"source": source, "row": row.rid, "failures": [r.rid for r in failures]},
        )
    if strict and row.payload.get("derives"):
        failure = _failure_row(row, "legacy_derives_forbidden")
        return RowCheckerResult(
            row_id=row.rid,
            passed=False,
            fail_rows=(failure,),
            checked_refs=checked_refs,
            trace=tuple((*trace, "fail:legacy_derives_forbidden")),
            checker_id=checker_id,
            enabled_step_id=enabled_step_id,
            provenance={"source": source, "row": row.rid, "failures": [failure.rid]},
        )
    derived = tuple(Row.from_obj(raw) for raw in row.payload.get("derives", ()))
    trace.extend(f"derive:{row.rid}->{derived_row.rid}" for derived_row in derived)
    trace.append("pass")
    return RowCheckerResult(
        row_id=row.rid,
        passed=True,
        derived_rows=derived,
        checked_refs=checked_refs,
        trace=tuple(trace),
        checker_id=checker_id,
        enabled_step_id=enabled_step_id,
        provenance={"source": source, "row": row.rid, "derived": [r.rid for r in derived]},
    )


def check_row(spec: ExecutableBandSpec, row: Row) -> tuple[bool, tuple[Row, ...]]:
    """Total row checker.

    Unknown schemas and missing required fields become retained diagnostic rows,
    which is the executable counterpart of retaining failed semantic checks.
    """

    result = check_row_result(spec, row)
    return result.passed, result.derived_rows if result.passed else result.fail_rows


def close_store(spec: ExecutableBandSpec, record: str | FiniteRecord) -> ClosureStore:
    return close_store_with_certificate(spec, record).store


def close_store_with_certificate(
    spec: ExecutableBandSpec, record: str | FiniteRecord, *, strict: bool = False
) -> ClosureCertificate:
    """Compute the finite closure store for a record.

    The reference implementation uses the record's explicit finite row set and
    declared candidate rows as the bounded universe. It validates every row,
    retains failures, applies enabled finite ``StoreStepRule`` entries in
    deterministic order, and keeps legacy ``payload.derives`` rows as
    compatibility input. Evidence closure is handled separately in
    :mod:`cgt_bandwidth.evidence`.
    """

    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    accepted: dict[str, Row] = {}
    failures: list[Row] = []
    row_results: list[RowCheckerResult] = []
    traces: list[StoreStepTrace] = []
    boundary_rows: list[str] = []
    candidate_row_ids: list[str] = []
    derived_row_ids: list[str] = []
    bound_exhaustion_reason = ""
    rule_certificates: list[StoreStepCertificate] = []
    applied_rule_counts: dict[str, int] = {rule.id: 0 for rule in exec_spec.store_step_rules}
    legacy_derivations: list[str] = []
    pending: list[Row] = list(sorted(rec.rows, key=lambda r: r.rid))
    candidate_pending: list[Row] = []
    for candidate_id in exec_spec.candidates:
        candidate_pending.extend(exec_spec.cand_enum[candidate_id].rows)
    candidate_row_ids.extend(row.rid for row in candidate_pending)
    if len(candidate_pending) > exec_spec.work_bounds.candidate_rows:
        boundary = Row(
            rid=f"boundary::{rec.id}::candidate_rows",
            kind="boundary",
            sem="candidate_bound_exhausted",
            verdict="fail",
            retention="boundary",
            payload={
                "source": rec.id,
                "atoms": [{"mode": "diag", "name": "candidate_bound_exhausted", "origin": rec.id}],
            },
            mode="diag",
        )
        failures.append(boundary)
        boundary_rows.append(boundary.rid)
        bound_exhaustion_reason = "candidate-row-bound"
        candidate_pending = candidate_pending[: exec_spec.work_bounds.candidate_rows]
    pending.extend(candidate_pending)

    steps = 0
    while pending:
        if steps >= exec_spec.work_bounds.closure_steps:
            boundary = Row(
                rid=f"boundary::{rec.id}::closure_steps",
                kind="boundary",
                sem="bound_exhausted",
                verdict="fail",
                retention="boundary",
                payload={
                    "source": rec.id,
                    "atoms": [{"mode": "diag", "name": "bound_exhausted", "origin": rec.id}],
                },
                mode="diag",
            )
            failures.append(boundary)
            boundary_rows.append(boundary.rid)
            bound_exhaustion_reason = "closure-step-bound"
            break
        steps += 1
        row = pending.pop(0)
        enabled_step_id = f"{rec.id}:{steps}:{row.rid}"
        if row.rid in accepted:
            failure = _failure_row(row, "duplicate_row_id")
            failures.append(failure)
            traces.append(
                StoreStepTrace(
                    step=steps,
                    row_id=row.rid,
                    action="retain_failure",
                    source="duplicate",
                    retained_failures=(failure.rid,),
                    trace=("fail:duplicate_row_id",),
                    checker_id="duplicate-row-id",
                    provenance={"source": rec.id, "row": row.rid},
                )
            )
            continue
        known_row_ids = frozenset(
            set(accepted)
            | {queued.rid for queued in pending}
            | {candidate.rid for candidate in candidate_pending}
        )
        result = check_row_result(
            exec_spec,
            row,
            known_row_ids | {row.rid},
            enabled_step_id=enabled_step_id,
            source=rec.id,
            strict=strict,
        )
        row_results.append(result)
        if result.passed:
            accepted[row.rid] = row
            emitted: list[str] = []
            for derived in result.derived_rows:
                legacy_derivations.append(f"{row.rid}->{derived.rid}")
                derived_row_ids.append(derived.rid)
                if derived.rid not in accepted and all(
                    derived.rid != queued.rid for queued in pending
                ):
                    pending.append(derived)
                    emitted.append(derived.rid)
            for rule in sorted(exec_spec.store_step_rules, key=lambda item: item.id):
                if applied_rule_counts[rule.id] >= rule.max_applications:
                    continue
                enabled, problems = rule.enabled_by(accepted)
                if not enabled:
                    continue
                rule_emitted: list[str] = []
                for emitted_row in rule.emits:
                    if emitted_row.rid in accepted or any(
                        emitted_row.rid == queued.rid for queued in pending
                    ):
                        continue
                    pending.append(emitted_row)
                    emitted.append(emitted_row.rid)
                    rule_emitted.append(emitted_row.rid)
                    derived_row_ids.append(emitted_row.rid)
                applied = bool(rule_emitted)
                if applied:
                    applied_rule_counts[rule.id] += 1
                rule_certificates.append(
                    StoreStepCertificate(
                        rule_id=rule.id,
                        enabled=True,
                        applied=applied,
                        emitted_rows=tuple(rule_emitted),
                        trace=(
                            f"store-rule:{rule.id}",
                            f"enabled:{enabled}",
                            f"applied:{applied}",
                        ),
                        provenance={
                            "origin": rule.origin,
                            "prov_path": list(rule.prov_path),
                            "source_row": row.rid,
                        },
                    )
                )
            pending.sort(key=lambda r: r.rid)
            traces.append(
                StoreStepTrace(
                    step=steps,
                    row_id=row.rid,
                    action="accept",
                    source="record-or-candidate",
                    emitted_rows=tuple(emitted),
                    trace=result.trace,
                    checker_id=result.checker_id,
                    provenance=result.provenance,
                )
            )
        else:
            failures.extend(result.fail_rows)
            traces.append(
                StoreStepTrace(
                    step=steps,
                    row_id=row.rid,
                    action="retain_failure",
                    source="row_checker",
                    retained_failures=tuple(failure.rid for failure in result.fail_rows),
                    trace=result.trace,
                    checker_id=result.checker_id,
                    provenance=result.provenance,
                )
            )

    if len(accepted) > exec_spec.work_bounds.candidate_rows:
        boundary = Row(
            rid=f"boundary::{rec.id}",
            kind="boundary",
            sem="bound_exhausted",
            verdict="fail",
            retention="boundary",
            payload={
                "source": rec.id,
                "atoms": [{"mode": "diag", "name": "bound_exhausted", "origin": rec.id}],
            },
            mode="diag",
        )
        failures.append(boundary)
        boundary_rows.append(boundary.rid)
        bound_exhaustion_reason = bound_exhaustion_reason or "accepted-row-bound"

    current_rows = accepted
    for rule in sorted(exec_spec.store_step_rules, key=lambda item: item.id):
        if applied_rule_counts[rule.id]:
            continue
        enabled, problems = rule.enabled_by(current_rows)
        rule_certificates.append(
            StoreStepCertificate(
                rule_id=rule.id,
                enabled=enabled,
                applied=False,
                blocked_reasons=problems,
                trace=(f"store-rule:{rule.id}", f"enabled:{enabled}", "applied:False"),
                provenance={"origin": rule.origin, "prov_path": list(rule.prov_path)},
            )
        )

    fixed_point_reason = "bound-exhausted" if bound_exhaustion_reason else "pending-empty"
    store = ClosureStore(
        record_id=rec.id, rows=tuple(accepted.values()), failures=tuple(failures), bound=steps
    )
    return ClosureCertificate(
        store=store,
        row_results=tuple(row_results),
        steps=tuple(traces),
        boundary_rows=tuple(boundary_rows),
        accepted_rows=tuple(sorted(accepted)),
        failure_rows=tuple(sorted(row.rid for row in failures)),
        candidate_rows=tuple(sorted(candidate_row_ids)),
        derived_rows=tuple(sorted(set(derived_row_ids))),
        fixed_point_reason=fixed_point_reason,
        bound_exhaustion_reason=bound_exhaustion_reason,
        rule_table=RuleTableCertificate(
            rules_declared=exec_spec.rule_table_declared,
            rule_count=len(exec_spec.store_step_rules),
            certificates=tuple(rule_certificates),
            legacy_derivations=tuple(legacy_derivations),
        ),
    )
