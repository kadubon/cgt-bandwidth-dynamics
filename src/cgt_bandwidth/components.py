"""Executable component functionals from the bandwidth paper."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .closure import close_store
from .core import (
    ComponentFunctional,
    EvidenceAtom,
    ExecutableBandSpec,
    FiniteRecord,
    as_exec_spec,
    freeze_value,
)
from .evidence import evidence_closure

BUILTIN_COMPONENTS: tuple[str, ...] = (
    "ObsRank",
    "CmpInv",
    "PreProbe",
    "PostProbe",
    "MCVFront",
    "RelCap",
    "RepSlack",
    "Rig",
    "RevRes",
    "RevSlack",
    "NonRed",
)


@dataclass(frozen=True)
class ComponentAuditResult:
    component: str
    problems: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    law_results: Mapping[str, bool] | None = None

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "ok": self.ok,
            "problems": list(self.problems),
            "warnings": list(self.warnings),
            "law_results": dict(self.law_results or {}),
        }


@dataclass(frozen=True)
class ComponentLawCertificate:
    component: str
    law_results: Mapping[str, bool]
    problems: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return all(self.law_results.values()) and not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "passed": self.passed,
            "law_results": dict(self.law_results),
            "problems": list(self.problems),
            "warnings": list(self.warnings),
        }


def audit_component_functional(
    component: ComponentFunctional, strict: bool = False
) -> ComponentAuditResult:
    problems: list[str] = []
    warnings: list[str] = []
    laws: dict[str, bool] = {
        "eval_total": True,
        "preorder_reflexive": True,
        "preorder_transitive": True,
        "congruence_respects_eval": True,
        "debt_morphism_total": True,
        "support_procedure_total": True,
    }
    carrier = set(component.carrier)
    if component.carrier:
        if component.bottom not in carrier:
            problems.append("bottom-outside-carrier")
        if component.default not in carrier:
            problems.append("default-outside-carrier")
        if component.preorder:
            missing_reflexive = [
                value for value in component.carrier if (value, value) not in component.preorder
            ]
            if missing_reflexive:
                problems.append("preorder-not-reflexive")
                laws["preorder_reflexive"] = False
            for left, middle in component.preorder:
                for mid2, right in component.preorder:
                    if middle == mid2 and (left, right) not in component.preorder:
                        problems.append("preorder-not-transitive")
                        laws["preorder_transitive"] = False
                        break
                if "preorder-not-transitive" in problems:
                    break
        for key, value in component.eval_table.items():
            if value not in carrier:
                problems.append(f"eval-table-outside-carrier:{key!r}")
                laws["eval_total"] = False
        for value in component.congruence:
            if value not in carrier:
                problems.append(f"congruence-outside-carrier:{value!r}")
                laws["congruence_respects_eval"] = False
    theorem_aligned = component.aggregator == "lookup" or component.aggregator.startswith("graph_")
    if component.aggregator == "lookup" and not component.eval_table:
        laws["eval_total"] = False
    if component.aggregator.startswith("graph_") and not (
        component.input_kinds or component.read_atoms or component.eval_table
    ):
        problems.append("graph-evaluator-has-empty-read-domain")
        laws["eval_total"] = False
    if component.polarity == "capability" and component.upper is not None:
        problems.append("capability-has-upper-obstruction-debt")
        laws["debt_morphism_total"] = False
    if component.polarity == "obstruction" and component.lower is not None:
        problems.append("obstruction-has-lower-capability-debt")
        laws["debt_morphism_total"] = False
    for coord in component.support_atoms:
        try:
            from .core import ReadCoord

            ReadCoord.from_obj(coord)
        except Exception:
            problems.append(f"invalid-support-coordinate:{coord!r}")
            laws["support_procedure_total"] = False
    if strict and not theorem_aligned:
        warnings.append("aggregate-evaluator-is-convenience-only")
    if strict and component.aggregator == "lookup" and not component.eval_table:
        problems.append("lookup-evaluator-missing-eval-table")
    if strict and component.carrier:
        for table_name, table in (
            ("low-debt", component.low_debt_table),
            ("up-debt", component.up_debt_table),
            ("support", component.support_table),
        ):
            missing = [
                value
                for value in component.carrier
                if value not in table and str(value) not in table
            ]
            if missing:
                problems.append(f"{table_name}-table-not-total")
                if table_name == "support":
                    laws["support_procedure_total"] = False
                else:
                    laws["debt_morphism_total"] = False
    return ComponentAuditResult(
        component.name,
        tuple(sorted(set(problems))),
        tuple(warnings),
        law_results=laws,
    )


def component_law_certificate(
    component: ComponentFunctional, strict: bool = False
) -> ComponentLawCertificate:
    audit = audit_component_functional(component, strict=strict)
    return ComponentLawCertificate(
        component=component.name,
        law_results=dict(audit.law_results or {}),
        problems=audit.problems,
        warnings=audit.warnings,
    )


def _names(atoms: frozenset[EvidenceAtom], mode: str) -> set[str]:
    return {atom.name for atom in atoms if atom.mode == mode}


def _component_names(spec: ExecutableBandSpec) -> tuple[str, ...]:
    if spec.components:
        return tuple(component.name for component in spec.components)
    return BUILTIN_COMPONENTS


def _component_spec(spec: ExecutableBandSpec, name: str) -> ComponentFunctional:
    for component in spec.components:
        if component.name == name:
            return component
    return ComponentFunctional(name)


def _aggregate(values: list[Any], component: ComponentFunctional) -> Any:
    if not values:
        return component.default
    if component.aggregator == "lookup":
        return values[-1]
    if component.aggregator == "sum":
        return sum(values)
    if component.aggregator == "min":
        return min(values)
    if component.aggregator == "set":
        return tuple(sorted({freeze_value(value) for value in values}, key=repr))
    if component.aggregator == "last":
        return values[-1]
    if component.aggregator == "count":
        return len(values)
    return max(values)


def _graph_value(rows: list[Any], component: ComponentFunctional) -> Any:
    edges: set[tuple[Any, Any]] = set()
    nodes: set[Any] = set()
    cut: set[Any] = set()
    for row in rows:
        for left, right in row.payload.get("graph_edges", ()):
            edges.add((freeze_value(left), freeze_value(right)))
            nodes.update((freeze_value(left), freeze_value(right)))
        for node in row.payload.get("graph_nodes", ()):
            nodes.add(freeze_value(node))
        for node in row.payload.get("graph_cut", ()):
            cut.add(freeze_value(node))
    if component.aggregator == "graph_count":
        return len(edges) if edges else len(nodes)
    if component.aggregator == "graph_cut":
        return len(cut)
    if component.aggregator == "graph_reachability":
        source = component.eval_table.get("source", component.default)
        target = component.eval_table.get("target", component.default)
        frontier = [freeze_value(source)]
        seen: set[Any] = set()
        adjacency: dict[Any, set[Any]] = {}
        for left, right in edges:
            adjacency.setdefault(left, set()).add(right)
        while frontier:
            current = frontier.pop()
            if current in seen:
                continue
            if current == freeze_value(target):
                return True
            seen.add(current)
            frontier.extend(sorted(adjacency.get(current, ()), key=repr))
        return False
    return component.default


def evaluate_component(
    name: str,
    spec: ExecutableBandSpec,
    record: str | FiniteRecord,
    atoms: frozenset[EvidenceAtom] | None = None,
) -> Any:
    """Evaluate a built-in finite component.

    These evaluators are intentionally finite atom readers. Domain projects can
    replace them by declaring their own component tables while preserving the
    same public component interface.
    """

    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    component = _component_spec(exec_spec, name)
    atoms = atoms if atoms is not None else evidence_closure(exec_spec, rec).atoms
    atom_names = {atom.name for atom in atoms if atom.mode in component.read_modes}
    values: list[Any] = []
    graph_rows: list[Any] = []
    for row in close_store(exec_spec, rec).all_rows:
        if component.input_kinds and row.kind not in component.input_kinds:
            continue
        row_atoms = row.atoms()
        if component.read_atoms and not (
            {atom.name for atom in row_atoms} & set(component.read_atoms)
        ):
            continue
        if not any(atom.mode in component.read_modes for atom in row_atoms):
            continue
        if component.read_atoms and not (atom_names & set(component.read_atoms)):
            continue
        if component.aggregator.startswith("graph_"):
            graph_rows.append(row)
            continue
        component_values = row.payload.get("component_values", {})
        if component.aggregator == "lookup":
            lookup_keys = row.payload.get("component_lookup", {})
            lookup_key = lookup_keys.get(name)
            if lookup_key is None and component.eval_key:
                lookup_key = tuple((key, row.payload.get(key)) for key in component.eval_key)
            if lookup_key is not None:
                values.append(component.eval_table.get(freeze_value(lookup_key), component.default))
        elif name in component_values:
            values.append(component_values[name])
    if component.aggregator.startswith("graph_"):
        return _graph_value(graph_rows, component)
    return _aggregate(values, component)


def component_profile(spec: ExecutableBandSpec, record: str | FiniteRecord) -> dict[str, Any]:
    exec_spec = as_exec_spec(spec)
    rec = exec_spec.record(record)
    atoms = evidence_closure(exec_spec, rec).atoms
    return {
        name: evaluate_component(name, exec_spec, rec, atoms)
        for name in _component_names(exec_spec)
    }


def component_support_coordinates(spec: ExecutableBandSpec, component: str) -> tuple[str, ...]:
    exec_spec = as_exec_spec(spec)
    functional = _component_spec(exec_spec, component)
    if functional.support_table:
        table_coords = {coord for support in functional.support_table.values() for coord in support}
        return tuple(sorted(table_coords))
    if functional.support_atoms:
        return functional.support_atoms
    coords: set[str] = set(functional.read_atoms)
    coords.update(functional.input_kinds)
    return tuple(sorted(coords))


def default_component_specs() -> tuple[ComponentFunctional, ...]:
    return (
        ComponentFunctional("ObsRank", polarity="capability", lower=1, aggregator="max"),
        ComponentFunctional("CmpInv", polarity="mixed", lower=1, aggregator="max"),
        ComponentFunctional("PreProbe", polarity="mixed", lower=1, aggregator="max"),
        ComponentFunctional("PostProbe", polarity="capability", lower=1, aggregator="max"),
        ComponentFunctional("MCVFront", polarity="mixed", aggregator="last", default="bad"),
        ComponentFunctional("RelCap", polarity="capability", lower=1, aggregator="max"),
        ComponentFunctional("RepSlack", polarity="capability", lower=1, aggregator="max"),
        ComponentFunctional("Rig", polarity="obstruction", upper=0, aggregator="max"),
        ComponentFunctional("RevRes", polarity="mixed", aggregator="max"),
        ComponentFunctional("RevSlack", polarity="mixed", aggregator="max"),
        ComponentFunctional("NonRed", polarity="mixed", aggregator="set", default=()),
    )
