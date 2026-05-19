"""Bandwidth object, component debt, and finite observable construction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .closure import close_store
from .components import component_profile
from .core import (
    ExecutableBandSpec,
    FiniteRecord,
    ReportLens,
    as_exec_spec,
    freeze_value,
    thaw_value,
)
from .pipeline import applicability_support, selected_kernel


@dataclass(frozen=True)
class RawBandwidth:
    values: tuple[tuple[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {k: thaw_value(v) for k, v in self.values}


@dataclass(frozen=True)
class DebtProfile:
    debts: tuple[str, ...]

    @property
    def is_bottom(self) -> bool:
        return not self.debts

    def to_dict(self) -> dict[str, Any]:
        return {"debts": list(self.debts), "bottom": self.is_bottom}


@dataclass(frozen=True)
class DebtCertificate:
    debts: tuple[str, ...]
    explicit: tuple[tuple[str, str], ...] = ()
    component_bounds: tuple[tuple[str, str, Any, Any], ...] = ()

    @property
    def is_bottom(self) -> bool:
        return not self.debts

    def to_profile(self) -> DebtProfile:
        return DebtProfile(self.debts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "debts": list(self.debts),
            "bottom": self.is_bottom,
            "explicit": [{"debt": debt, "row": row_id} for debt, row_id in self.explicit],
            "component_bounds": [
                {
                    "debt": debt,
                    "component": component,
                    "value": thaw_value(value),
                    "bound": thaw_value(bound),
                }
                for debt, component, value, bound in self.component_bounds
            ],
        }


@dataclass(frozen=True)
class BandwidthObject:
    applicability_support: Any
    raw: RawBandwidth
    debt: DebtProfile

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicability_support": self.applicability_support.to_dict(),
            "raw": self.raw.to_dict(),
            "debt": self.debt.to_dict(),
        }


@dataclass(frozen=True)
class BWObservable:
    base: Any
    release_closure: Any
    action_signature: Any

    def key(self) -> Any:
        return freeze_value(
            {
                "base": self.base,
                "release_closure": self.release_closure,
                "action_signature": self.action_signature,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "base": thaw_value(freeze_value(self.base)),
            "release_closure": thaw_value(freeze_value(self.release_closure)),
            "action_signature": thaw_value(freeze_value(self.action_signature)),
        }


def compute_raw_bandwidth(spec: ExecutableBandSpec, record: str | FiniteRecord) -> RawBandwidth:
    exec_spec = as_exec_spec(spec)
    values = tuple(
        (name, freeze_value(value))
        for name, value in sorted(component_profile(exec_spec, record).items())
    )
    return RawBandwidth(values=values)


def compute_debt(spec: ExecutableBandSpec, record: str | FiniteRecord) -> DebtProfile:
    return compute_debt_certificate(spec, record).to_profile()


def compute_debt_certificate(
    spec: ExecutableBandSpec, record: str | FiniteRecord
) -> DebtCertificate:
    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    profile = dict(compute_raw_bandwidth(exec_spec, rec).values)
    debts: set[str] = set()
    explicit_debts: set[str] = set()
    explicit_pairs: set[tuple[str, str]] = set()
    component_pairs: set[tuple[str, str, Any, Any]] = set()
    for row in close_store(exec_spec, rec).all_rows:
        explicit_debt = tuple(str(atom) for atom in row.payload.get("debt_atoms", ()))
        explicit_debts.update(explicit_debt)
        explicit_pairs.update((debt, row.rid) for debt in explicit_debt)
        if row.payload.get("debt", False) and not explicit_debt:
            for atom in row.atoms():
                if atom.mode == "diag":
                    explicit_debts.add(atom.name)
                    explicit_pairs.add((atom.name, row.rid))
    debts.update(explicit_debts)
    for component in exec_spec.components:
        if not component.emit_bound_debt:
            continue
        if component.name not in profile:
            continue
        value = profile[component.name]
        for label in component.low_debt_table.get(
            value, component.low_debt_table.get(str(value), ())
        ):
            debts.add(label)
            component_pairs.add((label, component.name, value, "low-debt-table"))
        for label in component.up_debt_table.get(
            value, component.up_debt_table.get(str(value), ())
        ):
            debts.add(label)
            component_pairs.add((label, component.name, value, "up-debt-table"))
        comparable = value if isinstance(value, (int, float)) else None
        if component.lower is not None and comparable is not None and comparable < component.lower:
            label = component.lower_debt_label or f"low:{component.name}"
            debts.add(label)
            component_pairs.add((label, component.name, value, component.lower))
        if component.upper is not None and comparable is not None and comparable > component.upper:
            label = component.upper_debt_label or f"up:{component.name}"
            debts.add(label)
            component_pairs.add((label, component.name, value, component.upper))
    return DebtCertificate(
        tuple(sorted(debts)),
        explicit=tuple(sorted(explicit_pairs)),
        component_bounds=tuple(sorted(component_pairs, key=repr)),
    )


def bandwidth_object(spec: ExecutableBandSpec, record: str | FiniteRecord) -> BandwidthObject:
    exec_spec = as_exec_spec(spec)
    return BandwidthObject(
        applicability_support=applicability_support(exec_spec, record),
        raw=compute_raw_bandwidth(exec_spec, record),
        debt=compute_debt(exec_spec, record),
    )


def is_in_band(spec: ExecutableBandSpec, record: str | FiniteRecord) -> bool:
    return compute_debt(spec, record).is_bottom


def base_observable(spec: ExecutableBandSpec, lens: ReportLens, record: str | FiniteRecord) -> Any:
    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    app_supp = applicability_support(exec_spec, rec).to_dict()
    return freeze_value(
        {
            "lens": lens.read(rec),
            "applicability_support": app_supp,
            "raw": compute_raw_bandwidth(exec_spec, rec).to_dict(),
            "debt": compute_debt(exec_spec, rec).to_dict(),
            "selected_kernel": selected_kernel(exec_spec, rec),
        }
    )


def bandwidth_observable(
    spec: ExecutableBandSpec, lens: ReportLens, record: str | FiniteRecord
) -> BWObservable:
    exec_spec = as_exec_spec(spec)
    from .release import action_signature, raw_release_closure

    rec = exec_spec.record(record)
    return BWObservable(
        base=base_observable(exec_spec, lens, rec),
        release_closure=raw_release_closure(exec_spec, rec, lens),
        action_signature=action_signature(exec_spec, rec, lens),
    )
