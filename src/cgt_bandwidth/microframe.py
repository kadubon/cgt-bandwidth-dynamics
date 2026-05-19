"""Deterministic microframe from the bandwidth paper."""

from __future__ import annotations

from .core import (
    CandidateSpec,
    ComponentFunctional,
    EvidenceAtom,
    ExecutableBandSpec,
    FiniteRecord,
    Frame,
    ReleaseCertificate,
    ReleaseCheckTable,
    ReportLens,
    Row,
    RowImplicationRule,
    RowSchema,
    StageCheck,
)


def atom(mode: str, name: str) -> EvidenceAtom:
    return EvidenceAtom(mode=mode, name=name)


def row(
    rid: str,
    kind: str,
    mode: str,
    *atoms: str,
    retention: str = "active",
    verdict: str = "pass",
    component_values: dict[str, object] | None = None,
    debt_atoms: tuple[str, ...] = (),
) -> Row:
    payload_atoms = []
    for item in atoms:
        if ":" in item:
            atom_mode, atom_name = item.split(":", 1)
        else:
            atom_mode, atom_name = mode, item
        payload_atoms.append({"mode": atom_mode, "name": atom_name, "origin": rid, "prov": [rid]})
    return Row(
        rid=rid,
        kind=kind,
        sem=rid,
        verdict=verdict,
        retention=retention,
        payload={
            "atoms": payload_atoms,
            "component_values": component_values or {},
            "debt_atoms": list(debt_atoms),
            "debt": bool(debt_atoms),
        },
    )


def _record(record_id: str, rows: tuple[Row, ...]) -> FiniteRecord:
    return FiniteRecord(id=record_id, report="r", rows=rows)


def _candidate_evidence() -> dict[str, tuple[EvidenceAtom, ...]]:
    return {
        "a": (
            atom("avail", "obs_1"),
            atom("avail", "marg_1"),
            atom("cmp", "cmp_1"),
            atom("cmp", "cmp_a"),
            atom("floor", "w_1"),
            atom("floor", "sel_a"),
            atom("floor", "fl_a"),
            atom("rel", "rel_1"),
            atom("diag", "ob_1"),
            atom("diag", "obs_1"),
            atom("diag", "lb_1"),
            atom("diag", "rig_1"),
        ),
        "b": (
            atom("avail", "obs_1"),
            atom("avail", "marg_1"),
            atom("cmp", "cmp_1"),
            atom("cmp", "cmp_b"),
            atom("floor", "w_1"),
            atom("floor", "sel_a"),
            atom("floor", "fl_a"),
            atom("floor", "sel_b"),
            atom("floor", "fl_b"),
            atom("rel", "rel_1"),
            atom("diag", "lb_1"),
            atom("diag", "rig_1"),
        ),
    }


def build_microframe_spec() -> ExecutableBandSpec:
    local_stability = {
        "FootprintDet": True,
        "ComponentDebtPres": True,
        "StageStab": True,
        "SelKerStab": True,
        "OneStepReleaseBisim": True,
    }
    schemas = {
        kind: RowSchema(kind=kind)
        for kind in (
            "observation",
            "comparison",
            "witness",
            "release",
            "diagnostic",
            "repair",
            "rigidity",
            "failure",
            "boundary",
        )
    }

    o1 = row(
        "o_1",
        "observation",
        "avail",
        "obs_1",
        "marg_1",
        component_values={"ObsRank": 1, "PreProbe": 2},
    )
    c1 = row("c_1", "comparison", "cmp", "cmp_1", component_values={"CmpInv": 1})
    rel1 = row("rel_1", "release", "rel", "rel_1", component_values={"RelCap": 1})
    w_ab = row(
        "w_1",
        "witness",
        "floor",
        "w_1",
        "sel_a",
        "sel_b",
        "fl_a",
        "fl_b",
        component_values={"PostProbe": 2, "RepSlack": 1},
    )
    w_b = row("w_1", "witness", "floor", "w_1", "sel_b", "fl_b", component_values={"PostProbe": 1})
    c2 = row(
        "c_2",
        "comparison",
        "cmp",
        "cmp_2",
        "cmp_a",
        "cmp_b",
        "avail:obs_2",
        "avail:marg_2",
        "prov:marg_2",
        component_values={"ObsRank": 2, "CmpInv": 2, "PreProbe": 3},
    )
    ob1 = row(
        "ob_1",
        "diagnostic",
        "diag",
        "ob_1",
        "obs_1",
        retention="retained",
        component_values={"Rig": 1},
        debt_atoms=("ob_1",),
    )
    lb1 = row(
        "lb_1",
        "diagnostic",
        "diag",
        "lb_1",
        retention="retained",
        component_values={"Rig": 1},
        debt_atoms=("lb_1",),
    )
    rc1 = row("rc_1", "release", "rel", "rc_1", "rel_1")
    p1 = row("p_1", "repair", "rel", "p_1", "floor:fl_a")
    ret1 = row("ret_1", "release", "rel", "ret_1")
    rig1 = row(
        "rig_1",
        "rigidity",
        "diag",
        "rig_1",
        retention="retained",
        component_values={"Rig": 2},
        debt_atoms=("rig_1",),
    )

    records = {
        "H0": _record("H0", (o1, c1, w_ab, rel1)),
        "H1": _record("H1", (o1, c1, w_b, ob1)),
        "H2": _record("H2", (o1, c1, w_ab, rel1, c2)),
        "H3": _record("H3", (o1, c1, ob1, lb1)),
        "H4": _record("H4", (o1, c1, w_ab, rel1, rc1, p1, ret1)),
        "H5": _record("H5", (o1, c1, w_ab, rel1, rig1)),
    }

    stage_checks = {}
    for candidate in ("a", "b"):
        blockers = [atom("diag", "lb_1")]
        if candidate == "a":
            blockers.extend((atom("diag", "ob_1"), atom("diag", "obs_1")))
        stage_checks[candidate] = {
            "presentable": StageCheck(required=(atom("avail", "obs_1"),)),
            "well_formed": StageCheck(),
            "observable": StageCheck(required=(atom("avail", "obs_1"),)),
            "comparable": StageCheck(required=(atom("cmp", "cmp_1"),)),
            "available": StageCheck(required=(atom("avail", "marg_1"),)),
            "floor_safe": StageCheck(required=(atom("floor", f"fl_{candidate}"),)),
            "release_safe": StageCheck(blockers=tuple(blockers)),
            "selected": StageCheck(
                required=(atom("floor", f"sel_{candidate}"),), blockers=tuple(blockers)
            ),
        }

    rules: tuple[RowImplicationRule, ...] = ()
    components = (
        ComponentFunctional(
            "ObsRank",
            polarity="capability",
            lower=1,
            aggregator="max",
            support_atoms=("o_1", "c_2"),
            emit_bound_debt=False,
        ),
        ComponentFunctional(
            "CmpInv",
            polarity="mixed",
            lower=1,
            aggregator="max",
            support_atoms=("c_1", "c_2"),
            emit_bound_debt=False,
        ),
        ComponentFunctional(
            "PreProbe",
            polarity="mixed",
            lower=1,
            aggregator="max",
            support_atoms=("o_1", "c_2"),
            emit_bound_debt=False,
        ),
        ComponentFunctional(
            "PostProbe",
            polarity="capability",
            lower=1,
            aggregator="max",
            support_atoms=("w_1", "lb_1"),
            emit_bound_debt=False,
        ),
        ComponentFunctional(
            "RelCap",
            polarity="capability",
            lower=1,
            aggregator="max",
            support_atoms=("rel_1", "rc_1", "ob_1"),
            emit_bound_debt=False,
        ),
        ComponentFunctional(
            "RepSlack",
            polarity="capability",
            lower=1,
            aggregator="max",
            support_atoms=("w_1", "p_1", "ob_1", "lb_1"),
            emit_bound_debt=False,
        ),
        ComponentFunctional(
            "Rig",
            polarity="obstruction",
            upper=0,
            aggregator="max",
            support_atoms=("rig_1", "ob_1", "lb_1"),
            emit_bound_debt=False,
        ),
    )
    releases = (
        ReleaseCertificate(
            id="id_H0",
            source="H0",
            target="H0",
            footprint=("o_1", "c_1", "w_1", "rel_1"),
            signature={"kind": "identity"},
            local_stability=local_stability,
        ),
        ReleaseCertificate(
            id="rc_1",
            source="H1",
            target="H4",
            discharges=("ob_1",),
            preserves=("w_1", "p_1"),
            footprint=("ob_1", "w_1", "rc_1", "p_1", "ret_1"),
            diagnostic_retyping=("ret_1",),
            discharge_map={"ob_1": "rc_1"},
            preservation_map={"w_1": "p_1"},
            retyping_map={"ob_1": "ret_1"},
            signature={"kind": "release", "row": "rc_1"},
            local_stability=local_stability,
        ),
        ReleaseCertificate(
            id="id_H2",
            source="H2",
            target="H2",
            footprint=("o_1", "c_1", "c_2", "w_1", "rel_1"),
            signature={"kind": "identity"},
            local_stability=local_stability,
        ),
        ReleaseCertificate(
            id="id_H4",
            source="H4",
            target="H4",
            footprint=("o_1", "c_1", "w_1", "rel_1"),
            signature={"kind": "identity"},
            local_stability=local_stability,
        ),
        ReleaseCertificate(
            id="id_H5",
            source="H5",
            target="H5",
            footprint=("o_1", "c_1", "w_1", "rel_1", "rig_1"),
            signature={"kind": "identity"},
            local_stability=local_stability,
        ),
    )

    return ExecutableBandSpec(
        name="deterministic-microframe",
        frame=Frame(
            systems=tuple(records),
            effect_dimensions=("obs", "cmp", "repair", "release"),
            row_kinds=tuple(schemas),
            semantic_ids=("A", "B"),
        ),
        row_schemas=schemas,
        records=records,
        candidates=("a", "b"),
        cand_enum={"a": CandidateSpec("a", "A"), "b": CandidateSpec("b", "B")},
        candidate_semantics={"a": "A", "b": "B"},
        candidate_evidence=_candidate_evidence(),
        stage_checks=stage_checks,
        rules=rules,
        components=components,
        releases=releases,
        release_check_table=ReleaseCheckTable(
            obstruction_rows=("ob_1", "rig_1"),
            lower_bound_rows=("lb_1",),
            allowed_new_rows=("rel_1", "rc_1", "p_1", "ret_1"),
        ),
        band_rows=("o_1", "c_1", "w_1", "rel_1"),
        read_coordinates=(
            "o_1",
            "c_1",
            "w_1",
            "rel_1",
            "ob_1",
            "lb_1",
            "c_2",
            "rc_1",
            "p_1",
            "ret_1",
            "rig_1",
        ),
        exact_support_limit=12,
    )


def microframe_summary() -> dict[str, object]:
    from .bandwidth import compute_debt, compute_raw_bandwidth
    from .completion import completion_classes
    from .pipeline import all_stage_evidence, applicability_support
    from .release import release_action, release_graph

    spec = build_microframe_spec()
    lens = ReportLens("report")
    rows = {}
    for record in spec.audit_universe:
        rows[record.id] = {
            "band_vector": compute_raw_bandwidth(spec, record).to_dict(),
            "debt": compute_debt(spec, record).to_dict()["debts"],
            "applicability_support": applicability_support(spec, record).to_dict()["pairs"],
            "stage_evidence": {
                candidate: evidence.to_dict()
                for candidate, evidence in all_stage_evidence(spec, record).items()
            },
        }
    return {
        "records": rows,
        "completion": completion_classes(spec, lens).to_dict()["classes"],
        "release_graph": release_graph(spec).to_dict()["edges"],
        "release_action": {
            str(k): [list(vv) for vv in v] for k, v in release_action(spec, lens).items()
        },
    }
