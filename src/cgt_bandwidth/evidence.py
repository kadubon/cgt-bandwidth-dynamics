"""Mode-stratified evidence atoms and finite row-implication closure."""

from __future__ import annotations

from dataclasses import dataclass

from .closure import close_store
from .core import (
    MODES,
    AtomInstance,
    AtomKey,
    EvidenceAtom,
    ExecutableBandSpec,
    FiniteRecord,
    ModeDecision,
    ModeTrace,
    RowDerivation,
    RowImplicationRule,
    as_exec_spec,
)


@dataclass(frozen=True)
class EvidenceClosureResult:
    atoms: frozenset[EvidenceAtom]
    derivations: dict[tuple[str, str, str, tuple[str, ...]], RowDerivation]
    mode_traces: tuple[ModeTrace, ...] = ()

    def by_mode(self, mode: str) -> frozenset[EvidenceAtom]:
        return frozenset(atom for atom in self.atoms if atom.mode == mode)

    def names_by_mode(self, mode: str) -> frozenset[str]:
        return frozenset(atom.name for atom in self.by_mode(mode))

    def instances(self) -> frozenset[AtomInstance]:
        return frozenset(AtomInstance.from_atom(atom) for atom in self.atoms)

    def quotient_keys(self) -> frozenset[AtomKey]:
        return frozenset(AtomKey.from_atom(atom) for atom in self.atoms)


@dataclass(frozen=True)
class EvidenceAudit:
    closure: EvidenceClosureResult
    mode_isolation_problems: tuple[str, ...] = ()
    no_free_row_problems: tuple[str, ...] = ()
    provenance_collisions: tuple[tuple[str, str, tuple[dict[str, object], ...]], ...] = ()

    @property
    def ok(self) -> bool:
        return not (
            self.mode_isolation_problems or self.no_free_row_problems or self.provenance_collisions
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "atoms": [
                atom.to_dict()
                for atom in sorted(
                    self.closure.atoms,
                    key=lambda item: (item.mode, item.name, item.origin, item.prov),
                )
            ],
            "mode_isolation_problems": list(self.mode_isolation_problems),
            "no_free_row_problems": list(self.no_free_row_problems),
            "provenance_collisions": [
                {"mode": mode, "name": name, "instances": list(instances)}
                for mode, name, instances in self.provenance_collisions
            ],
            "mode_traces": [trace.to_dict() for trace in self.closure.mode_traces],
        }


def _atom_matches(required: EvidenceAtom, available: EvidenceAtom, *, strict: bool = False) -> bool:
    if strict:
        return required == available
    if required.origin or required.prov:
        return required == available
    return required.key == available.key


def _rule_enabled(
    spec: ExecutableBandSpec,
    rule: RowImplicationRule,
    atoms: set[EvidenceAtom],
    *,
    strict: bool = False,
) -> bool:
    if not rule.origin or not rule.prov_path or not rule.non_synthetic or rule.cost < 0:
        return False
    if not all(
        any(_atom_matches(prem, atom, strict=strict) for atom in atoms) for prem in rule.premises
    ):
        return False
    for prem in rule.premises:
        raw_decision = spec.mode_matrix.get((prem.mode, rule.conclusion.mode))
        decision = ModeDecision.from_obj(raw_decision) if raw_decision is not None else None
        if decision is not None and decision.permits(rule.premises, strict=strict):
            continue
        return False
    return bool(rule.non_synthetic)


def _trace_key(atom: EvidenceAtom) -> tuple[str, str, str, tuple[str, ...]]:
    return (atom.mode, atom.name, atom.origin, atom.prov)


def evidence_closure(
    spec: ExecutableBandSpec,
    atoms_or_record: frozenset[EvidenceAtom] | set[EvidenceAtom] | str | FiniteRecord,
    *,
    strict: bool = False,
) -> EvidenceClosureResult:
    """Compute the least mode-stratified row closure."""

    exec_spec = as_exec_spec(spec)
    if isinstance(atoms_or_record, (str, FiniteRecord)):
        store = close_store(exec_spec, atoms_or_record)
        atoms: set[EvidenceAtom] = set(store.atoms())
    else:
        atoms = set(atoms_or_record)

    derivations: dict[tuple[str, str, str, tuple[str, ...]], RowDerivation] = {
        _trace_key(atom): RowDerivation(atom=atom, mode=atom.mode, rules=()) for atom in atoms
    }
    mode_traces: list[ModeTrace] = []
    changed = True
    ordered_rules = tuple(
        sorted(exec_spec.rules, key=lambda r: (r.conclusion.mode, r.conclusion.name, r.origin))
    )
    while changed:
        changed = False
        for rule in ordered_rules:
            for prem in rule.premises:
                raw_decision = exec_spec.mode_matrix.get((prem.mode, rule.conclusion.mode))
                decision = ModeDecision.from_obj(raw_decision) if raw_decision is not None else None
                if decision is not None:
                    passed = decision.permits(rule.premises, strict=strict)
                    mode_traces.append(
                        ModeTrace(
                            rule_id=f"{rule.origin}:{rule.conclusion.mode}:{rule.conclusion.name}",
                            premise_modes=tuple(atom.mode for atom in rule.premises),
                            conclusion_mode=rule.conclusion.mode,
                            passed=passed,
                            required_release=decision.requires_release,
                            required_retyping=decision.requires_retyping,
                            evidence_path_ids=tuple(
                                f"{atom.mode}:{atom.name}:{'->'.join(atom.prov)}"
                                for atom in rule.premises
                                if atom.mode == "rel"
                            ),
                            problems=()
                            if passed
                            else (f"mode-pair-rejected:{prem.mode}->{rule.conclusion.mode}",),
                        )
                    )
            if not _rule_enabled(exec_spec, rule, atoms, strict=strict):
                continue
            if rule.conclusion in atoms:
                continue
            atoms.add(rule.conclusion)
            premise_rules: list[RowImplicationRule] = []
            for prem in rule.premises:
                premise_der = next(
                    (
                        der
                        for der in derivations.values()
                        if _atom_matches(prem, der.atom, strict=strict)
                    ),
                    None,
                )
                if premise_der:
                    premise_rules.extend(premise_der.rules)
            derivations[_trace_key(rule.conclusion)] = RowDerivation(
                atom=rule.conclusion,
                mode=rule.conclusion.mode,
                rules=tuple((*premise_rules, rule)),
            )
            changed = True

    # Ensure every mode projection exists conceptually.
    for mode in MODES:
        _ = [atom for atom in atoms if atom.mode == mode]
    return EvidenceClosureResult(
        atoms=frozenset(atoms),
        derivations=derivations,
        mode_traces=tuple(mode_traces),
    )


def evidence_audit(
    spec: ExecutableBandSpec,
    atoms_or_record: frozenset[EvidenceAtom] | set[EvidenceAtom] | str | FiniteRecord,
    *,
    strict: bool = False,
) -> EvidenceAudit:
    closure = evidence_closure(spec, atoms_or_record, strict=strict)
    by_key: dict[AtomKey, list[AtomInstance]] = {}
    for atom in closure.atoms:
        by_key.setdefault(AtomKey.from_atom(atom), []).append(AtomInstance.from_atom(atom))
    collisions = []
    for key, instances in by_key.items():
        unique = sorted(
            {instance for instance in instances},
            key=lambda item: (item.origin, item.prov),
        )
        if len(unique) > 1:
            collisions.append(
                (
                    key.mode,
                    key.name,
                    tuple(instance.to_dict() for instance in unique),
                )
            )
    return EvidenceAudit(
        closure=closure,
        mode_isolation_problems=mode_isolation_audit(spec),
        no_free_row_problems=no_free_row_closure_audit(spec),
        provenance_collisions=tuple(collisions if strict else ()),
    )


def stage_implication(
    spec: ExecutableBandSpec,
    left: frozenset[EvidenceAtom],
    right: frozenset[EvidenceAtom],
    *,
    quotient: bool = False,
) -> bool:
    """Return whether `left` evidence derives every atom in `right`."""

    closure = evidence_closure(spec, left)
    if quotient:
        keys = {atom.key for atom in closure.atoms}
        return all(atom.key in keys for atom in right)
    return all(any(_atom_matches(atom, available) for available in closure.atoms) for atom in right)


def mode_isolation_audit(spec: ExecutableBandSpec) -> tuple[str, ...]:
    """Return rule and derivation-level diagnostic leakage problems."""

    problems: list[str] = []
    for rule in spec.rules:
        for prem in rule.premises:
            if prem.mode != "diag" or rule.conclusion.mode not in {"floor", "rel", "avail"}:
                continue
            raw_decision = spec.mode_matrix.get((prem.mode, rule.conclusion.mode))
            decision = ModeDecision.from_obj(raw_decision) if raw_decision is not None else None
            if decision is None or not decision.permits(rule.premises, strict=True):
                problems.append(
                    f"{rule.origin}:{prem.mode}->{rule.conclusion.mode}: no passing release/retyping path"
                )
    for record in spec.audit_universe:
        closure = evidence_closure(spec, record)
        for derivation in closure.derivations.values():
            for rule in derivation.rules:
                if rule.conclusion.mode not in {"floor", "rel", "avail"}:
                    continue
                diag_premises = [prem for prem in rule.premises if prem.mode == "diag"]
                if not diag_premises:
                    continue
                has_retyping_or_release = any(prem.mode == "rel" for prem in rule.premises)
                if not has_retyping_or_release:
                    problems.append(
                        f"{record.id}:{rule.origin}:{rule.conclusion.mode}: "
                        "diagnostic premise reaches usable conclusion without release/retyping trace"
                    )
    return tuple(problems)


def no_free_row_closure_audit(spec: ExecutableBandSpec) -> tuple[str, ...]:
    """Return rules that synthesize usable rows without finite provenance obligations."""

    problems: list[str] = []
    for rule in spec.rules:
        if not rule.origin or not rule.prov_path or not rule.non_synthetic:
            problems.append(
                f"{rule.conclusion.mode}:{rule.conclusion.name}: missing provenance/non-synthetic guard"
            )
        if rule.conclusion.mode in {"floor", "avail", "rel"} and not rule.premises:
            problems.append(
                f"{rule.conclusion.mode}:{rule.conclusion.name}: free usable conclusion"
            )
    return tuple(sorted(set(problems)))
