from dataclasses import replace

from cgt_bandwidth.closure import close_store, close_store_with_certificate
from cgt_bandwidth.core import (
    EvidenceAtom,
    ExecutableBandSpec,
    FiniteRecord,
    Frame,
    ModeDecision,
    ReleaseCertificate,
    Row,
    RowImplicationRule,
    RowSchema,
    StageCheck,
    WorkBounds,
)
from cgt_bandwidth.evidence import (
    evidence_closure,
    mode_isolation_audit,
    no_free_row_closure_audit,
    stage_implication,
)
from cgt_bandwidth.io import spec_from_dict
from cgt_bandwidth.microframe import build_microframe_spec
from cgt_bandwidth.pipeline import applicability_support
from cgt_bandwidth.rech import build_rech, build_rech_certificate, well_formed_rech
from cgt_bandwidth.release import check_release


def _simple_spec():
    rows = (
        Row("r1", "base", "a", payload={"atoms": [{"mode": "floor", "name": "a"}]}),
        Row("r2", "base", "b", payload={"atoms": [{"mode": "floor", "name": "b"}]}),
    )
    rule = RowImplicationRule(
        (EvidenceAtom("floor", "a", prov=("r1",)),),
        EvidenceAtom("floor", "c"),
        origin="r1",
        prov_path=("r1",),
    )
    return ExecutableBandSpec(
        name="simple",
        frame=Frame(systems=("H",)),
        row_schemas={
            "base": RowSchema("base"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "r", rows=rows)},
        candidates=("x", "y"),
        rules=(rule,),
    )


def test_closure_retains_schema_failures():
    spec = _simple_spec()
    bad = FiniteRecord("B", "r", rows=(Row("bad", "missing", "bad"),))
    spec = ExecutableBandSpec(
        name=spec.name,
        frame=spec.frame,
        row_schemas=spec.row_schemas,
        records={"B": bad},
        candidates=spec.candidates,
    )
    store = close_store(spec, "B")
    assert not store.rows
    assert store.failures
    assert store.failures[0].retention == "retained"


def test_rech_well_formed_for_simple_store():
    spec = _simple_spec()
    store = close_store(spec, "H")
    ok, problems = well_formed_rech(store)
    assert ok, problems
    rech = build_rech(store)
    assert "row:r1" in rech.nodes
    assert any(kind == "evidence:floor" for kind, _src, _target in rech.hyperarcs)
    cert = build_rech_certificate(store)
    assert cert.ok
    assert cert.incidence


def test_evidence_closure_operator_properties():
    spec = _simple_spec()
    atoms = frozenset({EvidenceAtom("floor", "a", prov=("r1",))})
    closure = evidence_closure(spec, atoms).atoms
    assert EvidenceAtom("floor", "a", prov=("r1",)) in closure
    assert EvidenceAtom("floor", "c") in closure
    closure_again = evidence_closure(spec, closure).atoms
    assert closure_again == closure
    larger = evidence_closure(spec, atoms | {EvidenceAtom("floor", "b")}).atoms
    assert closure <= larger


def test_stage_implication_defaults_to_provenance_sensitive_matching():
    spec = _simple_spec()
    left = frozenset({EvidenceAtom("floor", "a", origin="r1", prov=("r1",))})
    right_same_key_other_origin = frozenset({EvidenceAtom("floor", "a", origin="r2", prov=("r2",))})
    assert not stage_implication(spec, left, right_same_key_other_origin)
    assert stage_implication(spec, left, right_same_key_other_origin, quotient=True)


def test_applicability_support_ignores_metadata_override():
    spec = _simple_spec()
    rec = FiniteRecord("H", "r", rows=(), metadata={"app_supp_pairs": [["y", "y"]]})
    spec = ExecutableBandSpec(
        name=spec.name,
        frame=spec.frame,
        row_schemas=spec.row_schemas,
        records={"H": rec},
        candidates=("x", "y"),
    )
    preorder = applicability_support(spec, "H")
    assert preorder.pairs == frozenset({("x", "x"), ("x", "y"), ("y", "x"), ("y", "y")})


def test_closure_reaches_derived_row_fixed_point_and_retains_boundary():
    root = Row(
        "r1",
        "base",
        "a",
        payload={
            "derives": [
                {
                    "rid": "r2",
                    "kind": "base",
                    "sem": "b",
                    "payload": {"atoms": [{"mode": "floor", "name": "b"}]},
                }
            ]
        },
    )
    spec = ExecutableBandSpec(
        name="derived",
        frame=Frame(systems=("H",)),
        row_schemas={
            "base": RowSchema("base"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "r", rows=(root,))},
        candidates=(),
    )
    store = close_store(spec, "H")
    assert set(store.by_id()) == {"r1", "r2"}
    certificate = close_store_with_certificate(spec, "H")
    assert certificate.store == store
    assert any(step.emitted_rows == ("r2",) for step in certificate.steps)

    bounded = replace(spec, work_bounds=WorkBounds(closure_steps=1))
    bounded_store = close_store(bounded, "H")
    assert "r1" in bounded_store.by_id()
    assert any(row.kind == "boundary" for row in bounded_store.failures)


def test_stage_first_failure_uses_row_order_key():
    rows = (
        Row(
            "z_row",
            "z_kind",
            "z_sem",
            payload={"atoms": [{"mode": "diag", "name": "a", "origin": "z_row"}]},
        ),
        Row(
            "a_row",
            "a_kind",
            "a_sem",
            payload={"atoms": [{"mode": "diag", "name": "b", "origin": "a_row"}]},
        ),
    )
    empty = StageCheck()
    spec = ExecutableBandSpec(
        name="first-failure",
        frame=Frame(systems=("H",)),
        row_schemas={
            "a_kind": RowSchema("a_kind"),
            "z_kind": RowSchema("z_kind"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "r", rows=rows)},
        candidates=("x",),
        stage_checks={
            "x": {
                "presentable": empty,
                "well_formed": empty,
                "observable": empty,
                "comparable": empty,
                "available": empty,
                "floor_safe": empty,
                "release_safe": StageCheck(
                    blockers=(EvidenceAtom("diag", "a"), EvidenceAtom("diag", "b"))
                ),
                "selected": empty,
            }
        },
    )
    from cgt_bandwidth.pipeline import stage_evidence

    assert stage_evidence(spec, "H", "x").first_failure == "release_safe:blocked:diag:b"


def test_loader_reads_work_bounds_and_audit_scope():
    spec = spec_from_dict(
        {
            "name": "loader",
            "frame": {"systems": ["H"]},
            "row_schemas": {},
            "candidates": [],
            "records": [{"id": "H", "report": "r", "rows": []}],
            "work_bounds": {"closure_steps": 3, "support_subsets": 8},
            "audit_scope": {
                "whole_domain": False,
                "abstraction_map_declared": True,
                "preservation_checks": ["rows"],
            },
        }
    )
    assert spec.work_bounds.closure_steps == 3
    assert spec.work_bounds.support_subsets == 8
    assert not spec.audit_scope.whole_domain
    assert spec.audit_scope.preservation_checks == ("rows",)


def test_microframe_validates_and_release_trace_colon_is_not_failure():
    spec = build_microframe_spec()
    assert spec.validate() == []
    strict_report = spec.validate_report(strict=True)
    assert not strict_report.ok
    assert any("aggregate evaluator" in problem for problem in strict_report.problems)
    assert set(strict_report.condition_status()) == {f"WF{index:02d}" for index in range(1, 14)}
    cert = replace(
        next(cert for cert in spec.releases if cert.id == "id_H0"),
        checker_trace=("trace:footprint-ok",),
    )
    assert check_release(spec, cert).passed


def test_stage_reads_do_not_synthesize_passing_evidence():
    empty = StageCheck()
    spec = ExecutableBandSpec(
        name="reads-are-footprint-only",
        frame=Frame(systems=("H",)),
        row_schemas={"failure": RowSchema("failure"), "boundary": RowSchema("boundary")},
        records={"H": FiniteRecord("H", "r", rows=())},
        candidates=("x",),
        stage_checks={
            "x": {
                "presentable": StageCheck(
                    required=(EvidenceAtom("avail", "ghost"),),
                    reads=(EvidenceAtom("avail", "ghost"),),
                ),
                "well_formed": empty,
                "observable": empty,
                "comparable": empty,
                "available": empty,
                "floor_safe": empty,
                "release_safe": empty,
                "selected": empty,
            }
        },
    )
    from cgt_bandwidth.pipeline import stage_evidence

    evidence = stage_evidence(spec, "H", "x")
    assert evidence.first_failure == "presentable:missing:avail:ghost"
    assert evidence.failure is not None
    assert evidence.failure.key == ("presentable", "", "ghost", "")


def test_structured_mode_decision_requires_release_evidence():
    diag = EvidenceAtom("diag", "d", prov=("d",))
    floor = EvidenceAtom("floor", "f")
    rule = RowImplicationRule((diag,), floor, origin="d", prov_path=("d",))
    spec = ExecutableBandSpec(
        name="mode-decision",
        frame=Frame(systems=("H",)),
        row_schemas={"failure": RowSchema("failure"), "boundary": RowSchema("boundary")},
        records={"H": FiniteRecord("H", "r", rows=())},
        candidates=(),
        rules=(rule,),
        mode_matrix={("diag", "floor"): ModeDecision(True, requires_release=True)},
    )
    assert any("diag->floor rejected" in problem for problem in spec.validate())
    assert mode_isolation_audit(spec)

    free_rule = RowImplicationRule(
        (), EvidenceAtom("floor", "free"), origin="", prov_path=(), non_synthetic=False
    )
    free_spec = replace(spec, rules=(free_rule,))
    assert no_free_row_closure_audit(free_spec)


def test_release_check_result_reports_predicates_and_noninterference():
    source = FiniteRecord(
        "H0",
        "same",
        rows=(Row("stable", "k", "stable", payload={"value": 1}),),
    )
    target = FiniteRecord(
        "H1",
        "same",
        rows=(Row("stable", "k", "stable", payload={"value": 2}),),
    )
    spec = ExecutableBandSpec(
        name="release-check",
        frame=Frame(systems=("H0", "H1")),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H0": source, "H1": target},
        candidates=(),
        releases=(ReleaseCertificate("bad", "H0", "H1", footprint=("missing",)),),
    )
    result = check_release(spec, spec.releases[0])
    assert not result.passed
    assert result.predicate_results
    assert result.predicate_results["noninterference"] is False
    assert any(error.startswith("footprint-outside-ambient") for error in result.errors)


def test_validate_report_strict_requires_declared_local_stability():
    row = Row("r", "k", "r")
    spec = ExecutableBandSpec(
        name="strict-release",
        frame=Frame(systems=("H0", "H1")),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={
            "H0": FiniteRecord("H0", "same", rows=(row,)),
            "H1": FiniteRecord("H1", "same", rows=(row,)),
        },
        candidates=(),
        releases=(ReleaseCertificate("r1", "H0", "H1", footprint=("r",)),),
    )
    assert spec.validate_report().ok
    strict = spec.validate_report(strict=True)
    assert not strict.ok
    assert any("local stability predicate FootprintDet is defaulted" in p for p in strict.problems)
