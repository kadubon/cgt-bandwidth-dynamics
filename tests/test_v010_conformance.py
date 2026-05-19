import json

import pytest

from cgt_bandwidth.cli import main
from cgt_bandwidth.closure import close_store_with_certificate
from cgt_bandwidth.completion import completion_certificate, completion_law_certificate
from cgt_bandwidth.components import (
    audit_component_functional,
    component_law_certificate,
    component_support_coordinates,
    default_component_specs,
    evaluate_component,
)
from cgt_bandwidth.core import (
    AuditUniverseScope,
    CandidateSpec,
    ComponentFunctional,
    EvidenceAtom,
    ExecutableBandSpec,
    FiniteRecord,
    Frame,
    ModeDecision,
    ModeTrace,
    ReadCoord,
    ReleaseCertificate,
    ReleaseCheckTable,
    ReleaseEvidencePath,
    ReportLens,
    RetypingCertificate,
    Row,
    RowImplicationRule,
    RowSchema,
    StoreStepRule,
    StrictConformanceOptions,
    WorkBounds,
)
from cgt_bandwidth.evidence import evidence_audit, evidence_closure
from cgt_bandwidth.io import dump_json, load_data, report_lens_from_name, spec_from_dict
from cgt_bandwidth.microframe import build_microframe_spec
from cgt_bandwidth.rech import build_rech_certificate
from cgt_bandwidth.release import (
    ambient_store_enumerator,
    check_release,
    release_action_certificate,
)
from cgt_bandwidth.support import support_exact_certificate, support_table_certificate


def _base_spec(rows=(), *, read_coordinates=("row:r1",), releases=()):
    return ExecutableBandSpec(
        name="v010",
        frame=Frame(systems=("H",)),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "same", rows=tuple(rows))},
        candidates=(),
        read_coordinates=read_coordinates,
        releases=tuple(releases),
    )


def test_strict_conformance_options_and_checker_descriptors():
    options = StrictConformanceOptions.from_bool(True)
    assert options.active("reject_heuristic_retyping")
    assert options.to_dict()["require_full_provenance_matching"] is True
    checkers = ExecutableBandSpec.wellformedness_checkers()
    assert len(checkers) == 13
    assert {checker.condition for checker in checkers} == {
        f"WF{index:02d}" for index in range(1, 14)
    }
    assert checkers[0].to_dict()["name"] == "row-schema-totality"
    assert ReadCoord.from_obj({"kind": "atom", "mode": "diag", "id": "x"}).label == "atom:diag:x"


def test_strict_validation_rejects_legacy_coordinates_and_heuristic_retyping():
    diag = EvidenceAtom("diag", "d", origin="d", prov=("d",))
    ret = EvidenceAtom("rel", "ret_1", origin="ret_1", prov=("d", "ret_1"))
    rule = RowImplicationRule(
        (diag, ret),
        EvidenceAtom("floor", "f", origin="ret_1", prov=("d", "ret_1")),
        origin="ret_1",
        prov_path=("d", "ret_1"),
    )
    spec = _base_spec(read_coordinates=("legacy_coord",))
    spec = ExecutableBandSpec(
        name=spec.name,
        frame=spec.frame,
        row_schemas=spec.row_schemas,
        records=spec.records,
        candidates=(),
        rules=(rule,),
        mode_matrix={
            ("diag", "floor"): ModeDecision(True, requires_retyping=True),
            ("rel", "floor"): ModeDecision(True),
        },
        read_coordinates=("legacy_coord",),
    )
    normal = spec.validate_report()
    strict = spec.validate_report(strict=True)
    assert normal.ok
    assert not strict.ok
    assert any("legacy bare read coordinate" in problem for problem in strict.problems)
    assert any("legacy atom-name heuristic" in problem for problem in strict.problems)


def test_validate_report_exposes_wf_failure_witnesses():
    problematic = Row(
        "needs",
        "need",
        "needs",
        verdict="bad-verdict",
        retention="bad-retention",
        refs=("missing", "target"),
        payload={
            "derives": [
                {"kind": "broken"},
                {
                    "rid": "derived",
                    "kind": "unknown",
                    "sem": "derived",
                    "verdict": "bad",
                    "retention": "bad",
                },
            ]
        },
    )
    duplicate = Row("needs", "need", "dup")
    target = Row("target", "other", "target")
    outside = Row("outside", "outside", "outside")
    bad_rule = RowImplicationRule(
        (),
        EvidenceAtom("floor", "free"),
        origin="",
        prov_path=(),
        non_synthetic=False,
    )
    release = ReleaseCertificate("rel_bad", "missing_source", "H", footprint=("ghost",))
    spec = ExecutableBandSpec(
        name="invalid-wf",
        frame=Frame(systems=("H",), row_kinds=("need", "other")),
        row_schemas={
            "need": RowSchema("need", required_fields=("must",), allowed_refs=("need",)),
            "other": RowSchema("other"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "same", rows=(problematic, duplicate, target, outside))},
        candidates=("c",),
        cand_enum={
            "c": CandidateSpec(
                "c",
                rows=(Row("c1", "need", "c1"), Row("c2", "need", "c2")),
            ),
            "ghost": CandidateSpec("ghost"),
        },
        rules=(bad_rule,),
        components=(
            ComponentFunctional(
                "Cap",
                polarity="capability",
                upper=1,
                carrier=(0, 1),
                bottom=2,
                default=3,
                preorder=frozenset({(0, 2)}),
                support_atoms=("atom:notmode:x",),
            ),
            ComponentFunctional("Obs", polarity="obstruction", lower=0),
            ComponentFunctional("Diag", polarity="diagnostic", read_modes=("floor",)),
        ),
        releases=(release,),
        release_check_table=ReleaseCheckTable(
            required_predicates=("noNewRow",),
            footprint_predicates={"rel_bad": {"noNewRow": False}},
        ),
        read_coordinates=("bare",),
        work_bounds=WorkBounds(candidate_rows=1, closure_steps=0),
        audit_scope=AuditUniverseScope(whole_domain=False),
        exact_support_limit=2,
    )
    report = spec.validate_report(strict=True)
    problems = "\n".join(report.problems)
    assert not report.ok
    assert "schema violation" in problems
    assert "duplicate row id needs" in problems
    assert "candidate c: candidate row bound exceeded" in problems
    assert "synthetic rule rejected" in problems
    assert "component Cap: bottom is outside finite carrier" in problems
    assert "release rel_bad: declared footprint predicate noNewRow fails" in problems
    assert "audit universe scope" in problems
    assert "declared work bounds must be positive" in problems
    assert any(issue.witness_rows for issue in report.issues if issue.condition == "WF01")


def test_strict_evidence_audit_preserves_provenance_variants():
    rule = RowImplicationRule(
        (EvidenceAtom("floor", "a"),),
        EvidenceAtom("floor", "c", origin="r_rule", prov=("r_rule",)),
        origin="r_rule",
        prov_path=("r_rule",),
    )
    spec = _base_spec()
    spec = ExecutableBandSpec(
        name=spec.name,
        frame=spec.frame,
        row_schemas=spec.row_schemas,
        records=spec.records,
        candidates=(),
        rules=(rule,),
    )
    atom_r1 = EvidenceAtom("floor", "a", origin="r1", prov=("r1",))
    atom_r2 = EvidenceAtom("floor", "a", origin="r2", prov=("r2",))
    assert (
        EvidenceAtom("floor", "c", origin="r_rule", prov=("r_rule",))
        in evidence_closure(spec, {atom_r1}).atoms
    )
    assert (
        EvidenceAtom("floor", "c", origin="r_rule", prov=("r_rule",))
        not in evidence_closure(spec, {atom_r1}, strict=True).atoms
    )
    audit = evidence_audit(spec, {atom_r1, atom_r2}, strict=True)
    assert not audit.ok
    assert audit.provenance_collisions
    assert audit.to_dict()["provenance_collisions"][0]["mode"] == "floor"


def test_closure_certificate_records_checker_ids_and_provenance():
    root = Row(
        "r1",
        "k",
        "r1",
        payload={"derives": [{"rid": "r2", "kind": "k", "sem": "r2"}]},
    )
    cert = close_store_with_certificate(_base_spec((root,)), "H")
    assert cert.row_results[0].checker_id == "row-schema-totality"
    assert cert.row_results[0].enabled_step_id
    assert cert.row_results[0].provenance["source"] == "H"
    assert cert.steps[0].emitted_rows == ("r2",)
    assert cert.to_dict()["steps"][0]["checker_id"] == "row-schema-totality"


def test_rule_table_driven_closure_emits_rows_deterministically():
    root = Row(
        "r1",
        "k",
        "r1",
        payload={"atoms": [{"mode": "floor", "name": "seed", "origin": "r1", "prov": ["r1"]}]},
    )
    emitted = Row("r_rule", "k", "r_rule", payload={"value": 1})
    spec = ExecutableBandSpec(
        name="store-rule",
        frame=Frame(systems=("H",)),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "same", rows=(root,))},
        candidates=(),
        store_step_rules=(
            StoreStepRule(
                "derive_from_seed",
                premise_rows=("r1",),
                premise_atoms=(EvidenceAtom("floor", "seed"),),
                emits=(emitted,),
                origin="r1",
                prov_path=("r1",),
            ),
        ),
        read_coordinates=("row:r1", "row:r_rule"),
    )
    cert = close_store_with_certificate(spec, "H")
    assert set(cert.store.by_id()) == {"r1", "r_rule"}
    assert cert.rule_table.rule_count == 1
    assert cert.rule_table.certificates[0].applied is True
    assert cert.rule_table.certificates[0].emitted_rows == ("r_rule",)


def test_closure_certificates_retain_boundary_duplicate_and_blocked_rule_paths():
    first = Row("r1", "k", "r1")
    duplicate = Row("r1", "k", "dup")
    missing = Row("missing", "unknown", "missing")
    candidate_rows = (Row("c1", "k", "c1"), Row("c2", "k", "c2"))
    blocked_rule = StoreStepRule(
        "blocked",
        premise_rows=("ghost",),
        premise_atoms=(EvidenceAtom("floor", "ghost"),),
        emits=(Row("never", "k", "never"),),
        non_synthetic=False,
    )
    spec = ExecutableBandSpec(
        name="closure-branches",
        frame=Frame(systems=("H",)),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "same", rows=(first, duplicate, missing))},
        candidates=("c",),
        cand_enum={"c": CandidateSpec("c", rows=candidate_rows)},
        store_step_rules=(blocked_rule,),
        work_bounds=WorkBounds(candidate_rows=1, closure_steps=12),
        read_coordinates=("row:r1",),
    )
    cert = close_store_with_certificate(spec, "H")
    problems = "\n".join(row.rid for row in cert.store.failures)
    assert "duplicate_row_id" in problems
    assert "missing_schema" in problems
    assert "boundary::H::candidate_rows" in cert.boundary_rows
    blocked = cert.rule_table.certificates[-1]
    assert blocked.enabled is False
    assert "synthetic-store-step" in blocked.blocked_reasons
    assert "missing-row:ghost" in blocked.blocked_reasons


def test_strict_closure_rejects_legacy_payload_derives():
    root = Row(
        "r1",
        "k",
        "r1",
        payload={"derives": [{"rid": "legacy", "kind": "k", "sem": "legacy"}]},
    )
    spec = _base_spec((root,))
    report = spec.validate_report(strict=True)
    assert not report.ok
    assert any("payload.derives is legacy compatibility input" in p for p in report.problems)
    cert = close_store_with_certificate(spec, "H", strict=True)
    assert cert.accepted_rows == ()
    assert "fail::r1::legacy_derives_forbidden" in cert.failure_rows
    assert cert.fixed_point_reason == "pending-empty"


def test_rech_certificate_exposes_mode_and_preservation_audit():
    retained = Row(
        "retained",
        "k",
        "retained",
        retention="retained",
        payload={"source": "root", "atoms": [{"mode": "diag", "name": "d"}]},
    )
    cert = build_rech_certificate(_base_spec((retained,)), "H")
    assert cert.ok
    assert cert.retention_paths == (("retained", "root"),)
    assert "diag" in cert.mode_separation
    assert cert.store_transformation_audit["dangling_references"] == []
    assert {result.clause for result in cert.clause_results} >= {
        "RCH01.unique-row-ids-and-typed-references",
        "RCH07.floor-diagnostic-separation",
        "RCH09.lower-bound-successor-preservation",
    }


def test_rech_clause_table_detects_floor_diag_and_missing_successor():
    mixed = Row(
        "mixed",
        "k",
        "mixed",
        payload={
            "source": "mixed",
            "atoms": [{"mode": "diag", "name": "d"}, {"mode": "floor", "name": "f"}],
        },
    )
    lb = Row(
        "lb",
        "k",
        "lb",
        retention="discharged",
        payload={
            "successor": "missing",
            "source": "lb",
            "atoms": [{"mode": "diag", "name": "lb_1"}],
        },
    )
    cert = build_rech_certificate(_base_spec((mixed, lb)), "H")
    failed = {result.clause: result.problems for result in cert.clause_results if not result.passed}
    assert "RCH07.floor-diagnostic-separation" in failed
    assert "RCH09.lower-bound-successor-preservation" in failed


def test_graph_component_and_support_table_are_finite_data():
    graph_row = Row(
        "g",
        "graph",
        "g",
        payload={
            "atoms": [{"mode": "prov", "name": "g"}],
            "graph_edges": [["a", "b"], ["b", "c"]],
        },
    )
    component = ComponentFunctional(
        "Graph",
        aggregator="graph_count",
        input_kinds=("graph",),
        read_modes=("prov",),
        carrier=(0, 2),
        bottom=0,
        default=0,
        preorder=frozenset({(0, 0), (2, 2), (0, 2)}),
        low_debt_table={"0": (), "2": ()},
        up_debt_table={"0": (), "2": ()},
        support_table={"0": ("row:g",), "2": ("row:g",)},
    )
    spec = ExecutableBandSpec(
        name="graph-component",
        frame=Frame(systems=("H",)),
        row_schemas={
            "graph": RowSchema("graph"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "same", rows=(graph_row,))},
        candidates=(),
        components=(component,),
        read_coordinates=("row:g",),
    )
    assert evaluate_component("Graph", spec, "H") == 2
    assert component_support_coordinates(spec, "Graph") == ("row:g",)
    assert component_law_certificate(component, strict=True).passed


def test_graph_component_variants_and_law_failures_are_table_driven():
    graph_row = Row(
        "g",
        "graph",
        "g",
        payload={
            "atoms": [{"mode": "prov", "name": "g"}],
            "graph_edges": [["a", "b"], ["b", "c"]],
            "graph_cut": ["b", "c"],
        },
    )
    count_only = Row(
        "nodes",
        "graph",
        "nodes",
        payload={
            "atoms": [{"mode": "prov", "name": "g"}],
            "graph_nodes": ["x", "y", "z"],
        },
    )
    reach = ComponentFunctional(
        "Reach",
        aggregator="graph_reachability",
        input_kinds=("graph",),
        read_modes=("prov",),
        eval_table={"source": "a", "target": "c"},
    )
    cut = ComponentFunctional(
        "Cut",
        aggregator="graph_cut",
        input_kinds=("graph",),
        read_modes=("prov",),
    )
    node_count = ComponentFunctional(
        "NodeCount",
        aggregator="graph_count",
        input_kinds=("graph",),
        read_modes=("prov",),
    )
    spec = ExecutableBandSpec(
        name="graph-component-variants",
        frame=Frame(systems=("H", "N")),
        row_schemas={
            "graph": RowSchema("graph"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={
            "H": FiniteRecord("H", "same", rows=(graph_row,)),
            "N": FiniteRecord("N", "same", rows=(count_only,)),
        },
        candidates=(),
        components=(reach, cut, node_count),
        read_coordinates=("row:g", "row:nodes"),
    )
    assert evaluate_component("Reach", spec, "H") is True
    assert evaluate_component("Cut", spec, "H") == 2
    assert evaluate_component("NodeCount", spec, "N") == 3

    empty_graph = ComponentFunctional("EmptyGraph", aggregator="graph_count")
    bad_carrier = ComponentFunctional(
        "BadCarrier",
        polarity="capability",
        upper=1,
        carrier=(0, 1),
        bottom=2,
        default=3,
        preorder=frozenset({(0, 1), (1, 2)}),
        congruence={2: 0},
        support_atoms=("atom:notmode:x",),
    )
    assert (
        "graph-evaluator-has-empty-read-domain"
        in component_law_certificate(empty_graph, strict=True).problems
    )
    audit = audit_component_functional(bad_carrier, strict=True)
    assert "bottom-outside-carrier" in audit.problems
    assert "default-outside-carrier" in audit.problems
    assert "capability-has-upper-obstruction-debt" in audit.problems
    assert any(problem.startswith("invalid-support-coordinate") for problem in audit.problems)
    assert {component.name for component in default_component_specs()} >= {"ObsRank", "NonRed"}


def test_strict_retyping_requires_declared_same_path_certificate():
    diag = EvidenceAtom("diag", "d", origin="x", prov=("x",))
    rel_wrong = EvidenceAtom("rel", "ret", origin="y", prov=("y",))
    rel_right = EvidenceAtom("rel", "ret", origin="x", prov=("x",))
    floor = EvidenceAtom("floor", "f", origin="x", prov=("x",))
    wrong_rule = RowImplicationRule((diag, rel_wrong), floor, origin="x", prov_path=("x",))
    right_rule = RowImplicationRule((diag, rel_right), floor, origin="x", prov_path=("x",))
    decision = ModeDecision(True, requires_retyping=True, retyping_atoms=("ret",))
    wrong_spec = ExecutableBandSpec(
        name="wrong-retype",
        frame=Frame(systems=("H",)),
        row_schemas={"failure": RowSchema("failure"), "boundary": RowSchema("boundary")},
        records={"H": FiniteRecord("H", "r", rows=())},
        candidates=(),
        rules=(wrong_rule,),
        mode_matrix={("diag", "floor"): decision, ("rel", "floor"): ModeDecision(True)},
    )
    right_spec = ExecutableBandSpec(
        name="right-retype",
        frame=wrong_spec.frame,
        row_schemas=wrong_spec.row_schemas,
        records=wrong_spec.records,
        candidates=(),
        rules=(right_rule,),
        mode_matrix=wrong_spec.mode_matrix,
    )
    assert floor not in evidence_closure(wrong_spec, {diag, rel_wrong}, strict=True).atoms
    assert floor in evidence_closure(right_spec, {diag, rel_right}, strict=True).atoms
    assert evidence_audit(right_spec, {diag, rel_right}, strict=True).to_dict()["mode_traces"]


def test_component_audit_reports_law_results():
    component = ComponentFunctional(
        "Lookup",
        aggregator="lookup",
        carrier=(0, 1, 2),
        bottom=0,
        default=0,
        preorder=frozenset({(0, 0), (1, 1), (2, 2), (0, 1), (1, 2)}),
        eval_table={"x": 3},
        support_atoms=("atom:diag:x",),
    )
    result = audit_component_functional(component, strict=True)
    assert not result.ok
    assert result.law_results["preorder_transitive"] is False
    assert result.law_results["eval_total"] is False
    assert "preorder-not-transitive" in result.problems
    law = audit_component_functional(component, strict=True).to_dict()["law_results"]
    assert law["support_procedure_total"] is False


def test_component_law_certificate_reports_strict_table_problems():
    component = ComponentFunctional(
        "Broken",
        polarity="obstruction",
        lower=0,
        aggregator="lookup",
        carrier=(0,),
        bottom=0,
        default=1,
        preorder=frozenset({(0, 0)}),
        congruence={2: 0},
        support_atoms=("atom:not-a-mode:x",),
    )
    cert = component_law_certificate(component, strict=True)
    payload = cert.to_dict()
    assert not cert.passed
    assert payload["law_results"]["eval_total"] is False
    assert payload["law_results"]["support_procedure_total"] is False
    assert "lookup-evaluator-missing-eval-table" in payload["problems"]
    assert "obstruction-has-lower-capability-debt" in payload["problems"]
    assert payload["warnings"] == []


def test_new_certificate_record_shapes_and_strict_map_totality():
    diag = EvidenceAtom("diag", "d", origin="ob", prov=("ob",))
    rel = EvidenceAtom("rel", "ret", origin="ret", prov=("ob", "ret"))
    retyping = RetypingCertificate("rt_1", diag, rel, ("ob", "ret"))
    assert retyping.to_dict()["target_atom"]["mode"] == "rel"

    path = ReleaseEvidencePath("path_1", "rel", rel, ("ob", "ret"), certificate_id="rc")
    assert path.to_dict()["certificate_id"] == "rc"
    with pytest.raises(ValueError):
        ReleaseEvidencePath("bad", "not-a-mode", diag, ())

    mode_trace = ModeTrace(
        "rule",
        ("diag", "floor", "diag"),
        "floor",
        False,
        required_release=True,
        required_retyping=True,
        evidence_path_ids=("path_1",),
        problems=("missing-retyping",),
    )
    assert mode_trace.to_dict()["premise_modes"] == ["diag", "floor"]

    with pytest.raises(TypeError):
        StoreStepRule.from_obj(1)
    rule = StoreStepRule.from_obj(
        {
            "id": "rule",
            "premise_kinds": ["k"],
            "emits": [{"rid": "out", "kind": "k", "sem": "out"}],
            "max_applications": 2,
        }
    )
    enabled, problems = rule.enabled_by({})
    assert not enabled
    assert problems == ("missing-kind:k",)
    assert rule.to_dict()["max_applications"] == 2

    with pytest.raises(ValueError):
        ReleaseCertificate.strict(
            "rc_bad",
            "H",
            "H",
            footprint=("ob", "p", "ret"),
            discharges=("ob",),
            preserves=("p",),
            diagnostic_retyping=("ret",),
        )
    strict = ReleaseCertificate.strict(
        "rc",
        "H",
        "H",
        footprint=("ob", "p", "ret"),
        discharges=("ob",),
        preserves=("p",),
        diagnostic_retyping=("ret",),
        discharge_map={"ob": "rc"},
        preservation_map={"p": "p"},
        retyping_map={"ret": "ret"},
    )
    assert strict.local_stability["OneStepReleaseBisim"]
    table = ReleaseCheckTable(
        footprint_coordinates={"rc": ("ob", "ret")},
        predicate_coordinates={"rc": {"diagnosticRetyping": ("ret",)}},
    )
    assert table.declared_predicate_coordinates_for("rc", "diagnosticRetyping") == ("ret",)
    assert table.to_dict()["predicate_coordinates"]["rc"]["diagnosticRetyping"] == ["ret"]


def test_support_and_completion_certificates_include_witness_sections():
    spec = build_microframe_spec()
    lens = ReportLens("report")
    support = support_exact_certificate(spec, lens)
    completion = completion_certificate(spec, lens)
    completion_law = completion_law_certificate(spec, lens)
    assert support.pairwise_witnesses
    assert "pairwise_witnesses" in support.to_dict()
    support_table = support_table_certificate(spec, lens, exact=True)
    assert support_table.passed
    assert support_table.to_dict()["results"]
    assert completion.universal_property_checks["kernel_pair_partition"]
    assert completion.universal_property_checks["idempotent"]
    assert completion.universal_property_witnesses["observable_table"]
    assert completion_law.passed
    assert completion_law.to_dict()["law_witnesses"]["completion_classes"]
    assert completion_law.to_dict()["operator_laws"]["report_refinement"]


def test_strict_release_uses_footprint_predicate_table():
    row = Row("r", "k", "r")
    release = ReleaseCertificate.strict("rel_1", "H", "H", footprint=("r",))
    spec = _base_spec((row,), releases=(release,))
    spec = ExecutableBandSpec(
        name=spec.name,
        frame=spec.frame,
        row_schemas=spec.row_schemas,
        records=spec.records,
        candidates=(),
        releases=spec.releases,
        release_check_table=ReleaseCheckTable(
            footprint_predicates={
                "rel_1": {
                    "obstructionCoverage": True,
                    "lowerBoundSuccessor": True,
                    "noNewRow": False,
                    "noninterference": True,
                    "diagnosticRetyping": True,
                }
            },
            footprint_coordinates={"rel_1": ("r",)},
            predicate_coordinates={
                "rel_1": {
                    "obstructionCoverage": ("r",),
                    "lowerBoundSuccessor": ("r",),
                    "noNewRow": ("r",),
                    "noninterference": ("r",),
                    "diagnosticRetyping": ("r",),
                }
            },
        ),
        read_coordinates=("row:r",),
    )
    result = check_release(spec, release, strict=True)
    assert not result.passed
    assert result.predicate_results["declaredPredicate:noNewRow"] is False
    assert any("declared-predicate-failed:noNewRow" in item for item in result.errors)
    assert ambient_store_enumerator(spec, "H").passed


def test_strict_release_requires_total_proof_maps_and_ambient_rows():
    source = FiniteRecord(
        "H0",
        "same",
        rows=(
            Row("ob", "k", "ob", payload={"debt": True, "atoms": [{"mode": "diag", "name": "ob"}]}),
        ),
    )
    target = FiniteRecord(
        "H1",
        "same",
        rows=(Row("ob", "k", "ob"), Row("outside", "k", "outside")),
    )
    release = ReleaseCertificate(
        "rel",
        "H0",
        "H1",
        discharges=("ob",),
        preserves=("p",),
        footprint=("ob",),
        diagnostic_retyping=("ret",),
        checker_trace=(),
        local_stability={
            "FootprintDet": True,
            "ComponentDebtPres": True,
            "StageStab": True,
            "SelKerStab": True,
            "OneStepReleaseBisim": True,
        },
    )
    spec = ExecutableBandSpec(
        name="strict-release-proof",
        frame=Frame(systems=("H0", "H1")),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H0": source, "H1": target},
        candidates=(),
        releases=(release,),
        release_check_table=ReleaseCheckTable(
            obstruction_rows=("ob",),
            lower_bound_rows=("p",),
            allowed_new_rows=(),
            footprint_predicates={
                "rel": {
                    "obstructionCoverage": True,
                    "lowerBoundSuccessor": True,
                    "noNewRow": True,
                    "noninterference": True,
                    "diagnosticRetyping": True,
                }
            },
            footprint_coordinates={"rel": ("ob",)},
            predicate_coordinates={
                "rel": {
                    "obstructionCoverage": ("ob",),
                    "lowerBoundSuccessor": ("ob",),
                    "noNewRow": ("ob",),
                    "noninterference": ("ob",),
                    "diagnosticRetyping": ("ob",),
                }
            },
        ),
        read_coordinates=("row:ob",),
    )
    result = check_release(spec, release, strict=True)
    assert not result.passed
    assert result.predicate_results["strictDischargeMapTotal"] is False
    assert result.predicate_results["strictPreservationMapTotal"] is False
    assert result.predicate_results["strictRetypingMapTotal"] is False
    assert result.predicate_results["strictCheckerTracePresent"] is False
    assert any(error.startswith("new-row:outside") for error in result.errors)


def test_release_descent_certificate_records_support_and_bisim_witnesses():
    row = Row("r", "k", "r")
    release = ReleaseCertificate.strict(
        "rel_1",
        "H",
        "H",
        footprint=("r",),
        signature={"kind": "identity"},
    )
    spec = _base_spec((row,), read_coordinates=("row:r",), releases=(release,))
    spec = ExecutableBandSpec(
        name=spec.name,
        frame=spec.frame,
        row_schemas=spec.row_schemas,
        records=spec.records,
        candidates=(),
        releases=spec.releases,
        release_check_table=ReleaseCheckTable(
            footprint_predicates={
                "rel_1": {
                    "obstructionCoverage": True,
                    "lowerBoundSuccessor": True,
                    "noNewRow": True,
                    "noninterference": True,
                    "diagnosticRetyping": True,
                }
            },
            footprint_coordinates={"rel_1": ("r",)},
            predicate_coordinates={
                "rel_1": {
                    "obstructionCoverage": ("r",),
                    "lowerBoundSuccessor": ("r",),
                    "noNewRow": ("r",),
                    "noninterference": ("r",),
                    "diagnosticRetyping": ("r",),
                }
            },
        ),
        read_coordinates=("row:r",),
    )
    cert = release_action_certificate(spec, ReportLens("report"), strict=True)
    descent = cert.descent_certificates["rel_1"]
    assert descent.certificate_congruence
    assert descent.one_step_witness
    assert cert.descent_proofs["rel_1"].passed
    assert cert.to_dict()["descent_proofs"]["rel_1"]["predicate_witnesses"]
    assert descent.to_dict()["passed"] is True


def test_cli_close_certificate_path(capsys):
    assert main(["close", "examples/minimal_spec.json", "H0", "--certificate"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "row_results" in payload
    assert "steps" in payload


def test_strict_minimal_example_validates_under_strict_mode(capsys):
    assert main(["validate", "examples/strict_minimal_spec.json", "--report", "--strict"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is True
    assert set(report["condition_status"].values()) == {"pass"}


def test_io_loaders_and_spec_parser_cover_portable_shapes(tmp_path):
    json_path = tmp_path / "data.json"
    yaml_path = tmp_path / "data.yaml"
    json_path.write_text('{"x": 1}', encoding="utf-8")
    yaml_path.write_text("x: 2\n", encoding="utf-8")
    assert load_data(json_path) == {"x": 1}
    assert load_data(yaml_path) == {"x": 2}
    assert json.loads(dump_json({"b": 2, "a": 1})) == {"a": 1, "b": 2}
    assert report_lens_from_name("effects:a,b").coordinates == ("a", "b")
    assert report_lens_from_name("custom").name == "custom"

    spec = spec_from_dict(
        {
            "name": "parsed",
            "frame": {"systems": ["H"], "effect_dimensions": ["obs"]},
            "row_schemas": {"k": {"required_fields": ["v"]}},
            "candidates": ["c"],
            "cand_enum": {
                "c": {
                    "id": "c",
                    "semantic_class": "C",
                    "rows": [{"rid": "cr", "kind": "k", "sem": "cr", "payload": {"v": 1}}],
                    "evidence": [{"mode": "avail", "name": "c"}],
                }
            },
            "candidate_evidence": {"c": [{"mode": "avail", "name": "c"}]},
            "stage_checks": {"c": {"presentable": {"reads": [{"mode": "avail", "name": "c"}]}}},
            "rules": [
                {
                    "premises": [{"mode": "avail", "name": "c"}],
                    "conclusion": {"mode": "floor", "name": "c"},
                    "origin": "cr",
                    "prov_path": ["cr"],
                }
            ],
            "components": [
                {
                    "name": "Lookup",
                    "aggregator": "lookup",
                    "eval_table": {"key": 1},
                    "eval_key": ["k"],
                }
            ],
            "records": [
                {
                    "id": "H",
                    "report": "r",
                    "rows": [{"rid": "r", "kind": "k", "sem": "r", "payload": {"v": 1}}],
                }
            ],
            "releases": [{"id": "rel", "source": "H", "target": "H", "footprint": ["r"]}],
            "release_check_table": {
                "allowed_new_rows": ["n"],
                "footprint_predicates": {"rel": {"noNewRow": True}},
                "footprint_coordinates": {"rel": ["r"]},
            },
            "mode_matrix": {"avail->floor": True},
            "read_coordinates": ["row:r"],
            "work_bounds": {"closure_steps": 3},
            "audit_scope": {"whole_domain": True},
            "exact_support_limit": 4,
        }
    )
    assert spec.name == "parsed"
    assert spec.cand_enum["c"].semantic_class == "C"
    assert spec.release_check_table.allowed_new_rows == ("n",)
    assert spec.mode_matrix[("avail", "floor")].allowed
