"""Bandwidth completion as the kernel pair of the finite observable."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from .bandwidth import bandwidth_observable
from .core import Completion, ExecutableBandSpec, ReportLens, as_exec_spec
from .support import separation_coordinates


@dataclass(frozen=True)
class CompletionCertificate:
    completion: Completion
    report_fibers: tuple[tuple[str, ...], ...]
    report_fiber_splits: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...]
    factorization_ok: bool
    separating_classes: tuple[tuple[str, ...], ...]
    separation_coordinates: tuple[str, ...]
    universal_property_checks: dict[str, bool] | None = None
    universal_property_witnesses: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "completion": self.completion.to_dict(),
            "report_fibers": [list(fiber) for fiber in self.report_fibers],
            "report_fiber_splits": [
                {"report": report, "completion_classes": [list(cls) for cls in classes]}
                for report, classes in self.report_fiber_splits
            ],
            "factorization_ok": self.factorization_ok,
            "separating_classes": [list(cls) for cls in self.separating_classes],
            "separation_coordinates": list(self.separation_coordinates),
            "universal_property_checks": dict(self.universal_property_checks or {}),
            "universal_property_witnesses": dict(self.universal_property_witnesses or {}),
        }


@dataclass(frozen=True)
class CompletionLawCertificate:
    observable_table: dict[str, Any]
    kernel_pair: tuple[tuple[str, ...], ...]
    operator_laws: dict[str, bool]
    report_fiber_splits: tuple[tuple[str, tuple[tuple[str, ...], ...]], ...] = ()
    law_witnesses: dict[str, Any] | None = None

    @property
    def passed(self) -> bool:
        return all(self.operator_laws.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "observable_table": self.observable_table,
            "kernel_pair": [list(cls) for cls in self.kernel_pair],
            "operator_laws": dict(self.operator_laws),
            "law_witnesses": dict(self.law_witnesses or {}),
            "report_fiber_splits": [
                {"report": report, "completion_classes": [list(cls) for cls in classes]}
                for report, classes in self.report_fiber_splits
            ],
        }


@dataclass(frozen=True)
class CompletionUniversalPropertyCertificate:
    completion_classes: tuple[tuple[str, ...], ...]
    report_fibers: tuple[tuple[str, ...], ...]
    quotient_map_witnesses: dict[str, tuple[str, ...]]
    checks: dict[str, bool]
    bounded_exhaustive: bool = False

    @property
    def passed(self) -> bool:
        return all(self.checks.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "completion_classes": [list(cls) for cls in self.completion_classes],
            "report_fibers": [list(fiber) for fiber in self.report_fibers],
            "quotient_map_witnesses": {
                key: list(value) for key, value in sorted(self.quotient_map_witnesses.items())
            },
            "checks": dict(self.checks),
            "bounded_exhaustive": self.bounded_exhaustive,
        }


def completion_classes(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> Completion:
    exec_spec = as_exec_spec(spec)
    buckets: dict[Any, list[str]] = defaultdict(list)
    observable_by_record: dict[str, Any] = {}
    for record in exec_spec.audit_universe:
        observable = bandwidth_observable(
            exec_spec, lens, record, strict_release=strict_release
        ).key()
        observable_by_record[record.id] = observable
        buckets[observable].append(record.id)
    classes = tuple(
        tuple(sorted(ids)) for ids in sorted(buckets.values(), key=lambda cls: (cls[0], len(cls)))
    )
    return Completion(
        lens_name=lens.name, classes=classes, observable_by_record=observable_by_record
    )


def completion_operator(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    refinement: tuple[tuple[str, ...], ...],
    *,
    strict_release: bool = True,
) -> tuple[tuple[str, ...], ...]:
    completion = completion_classes(spec, lens, strict_release=strict_release)
    completed: list[tuple[str, ...]] = []
    for q_class in refinement:
        q_set = set(q_class)
        for c_class in completion.classes:
            inter = tuple(sorted(q_set & set(c_class)))
            if inter:
                completed.append(inter)
    return tuple(sorted(completed))


def report_factorization_obstruction(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> tuple[bool, tuple[tuple[str, ...], ...]]:
    exec_spec = as_exec_spec(spec)
    completion = completion_classes(exec_spec, lens, strict_release=strict_release)
    report_buckets: dict[Any, list[str]] = defaultdict(list)
    for record in exec_spec.audit_universe:
        report_buckets[lens.read(record)].append(record.id)
    report_classes = tuple(tuple(sorted(v)) for v in report_buckets.values())
    completion_set = {frozenset(cls) for cls in completion.classes}
    report_set = {frozenset(cls) for cls in report_classes}
    separating = tuple(cls for cls in completion.classes if frozenset(cls) not in report_set)
    return completion_set == report_set, separating


def completion_certificate(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> CompletionCertificate:
    exec_spec = as_exec_spec(spec)
    completion = completion_classes(exec_spec, lens, strict_release=strict_release)
    report_buckets: dict[Any, list[str]] = defaultdict(list)
    for record in exec_spec.audit_universe:
        report_buckets[lens.read(record)].append(record.id)
    report_fibers = tuple(tuple(sorted(v)) for v in report_buckets.values())
    splits: list[tuple[str, tuple[tuple[str, ...], ...]]] = []
    for report_value, ids in report_buckets.items():
        classes = tuple(cls for cls in completion.classes if set(cls) & set(ids))
        if len(classes) > 1:
            splits.append((repr(report_value), classes))
    factorization_ok, separating = report_factorization_obstruction(
        exec_spec, lens, strict_release=strict_release
    )
    completion_set = {frozenset(cls) for cls in completion.classes}
    covers_universe = (
        set().union(*completion_set) == set(exec_spec.records) if completion_set else False
    )
    pairwise_disjoint = (
        sum(len(cls) for cls in completion.classes) == len(set().union(*completion_set))
        if completion_set
        else False
    )
    return CompletionCertificate(
        completion=completion,
        report_fibers=report_fibers,
        report_fiber_splits=tuple(splits),
        factorization_ok=factorization_ok,
        separating_classes=separating,
        separation_coordinates=separation_coordinates(exec_spec, lens),
        universal_property_checks={
            "kernel_pair_partition": covers_universe and pairwise_disjoint,
            "report_refinement": all(
                len({lens.read(exec_spec.record(record_id)) for record_id in cls}) == 1
                for cls in completion.classes
            ),
            "idempotent": completion_operator(
                exec_spec,
                lens,
                completion.classes,
                strict_release=strict_release,
            )
            == completion.classes,
            "least_complete_refinement": all(
                frozenset(cls) <= frozenset(report_fiber)
                for cls in completion.classes
                for report_fiber in report_fibers
                if set(cls) & set(report_fiber)
            ),
        },
        universal_property_witnesses={
            "completion_classes": [list(cls) for cls in completion.classes],
            "report_fibers": [list(fiber) for fiber in report_fibers],
            "observable_table": dict(completion.observable_by_record),
            "idempotent_application": [
                list(cls)
                for cls in completion_operator(
                    exec_spec,
                    lens,
                    completion.classes,
                    strict_release=strict_release,
                )
            ],
        },
    )


def completion_universal_property_certificate(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    refinement: tuple[tuple[str, ...], ...] | None = None,
    *,
    strict_release: bool = True,
) -> CompletionUniversalPropertyCertificate:
    exec_spec = as_exec_spec(spec)
    cert = completion_certificate(exec_spec, lens, strict_release=strict_release)
    refinement = refinement or cert.report_fibers
    completed = completion_operator(exec_spec, lens, refinement, strict_release=strict_release)
    quotient_map = {}
    for source_class in refinement:
        image = tuple(
            sorted(
                record_id
                for completed_class in completed
                for record_id in completed_class
                if record_id in source_class
            )
        )
        quotient_map[",".join(source_class)] = image
    checks = dict(cert.universal_property_checks or {})
    checks["supplied_refinement_maps_to_completion"] = all(
        bool(value) for value in quotient_map.values()
    )
    return CompletionUniversalPropertyCertificate(
        completion_classes=cert.completion.classes,
        report_fibers=cert.report_fibers,
        quotient_map_witnesses=quotient_map,
        checks=checks,
        bounded_exhaustive=len(exec_spec.records) <= exec_spec.work_bounds.quotient_classes,
    )


def completion_law_certificate(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> CompletionLawCertificate:
    cert = completion_certificate(spec, lens, strict_release=strict_release)
    return CompletionLawCertificate(
        observable_table={
            record_id: value for record_id, value in cert.completion.observable_by_record.items()
        },
        kernel_pair=cert.completion.classes,
        operator_laws=dict(cert.universal_property_checks or {}),
        report_fiber_splits=cert.report_fiber_splits,
        law_witnesses=dict(cert.universal_property_witnesses or {}),
    )
