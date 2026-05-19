import json
import subprocess
import sys
from pathlib import Path

import jsonschema

from cgt_bandwidth.bandwidth import compute_debt, compute_debt_certificate
from cgt_bandwidth.cli import main
from cgt_bandwidth.completion import completion_certificate
from cgt_bandwidth.complexity import greedy_release_cover, solve_release_cover_exact
from cgt_bandwidth.components import audit_component_functional, component_profile
from cgt_bandwidth.core import (
    ComponentFunctional,
    ExecutableBandSpec,
    FiniteRecord,
    Frame,
    ReleaseCheckTable,
    ReportLens,
    Row,
    RowSchema,
)
from cgt_bandwidth.microframe import build_microframe_spec
from cgt_bandwidth.release import raw_release_closure, release_action_certificate
from cgt_bandwidth.support import (
    exact_support_enum,
    support_checker_result,
    support_exact_certificate,
    support_product,
    support_signature_certificate,
)


def test_support_product_is_sound_and_exact_terminates_for_microframe():
    spec = build_microframe_spec()
    lens = ReportLens("report")
    product = support_product(spec, lens)
    assert product
    exact = exact_support_enum(spec, lens)
    assert exact
    cert = support_exact_certificate(spec, lens)
    assert cert.product == product
    assert cert.exact == exact
    assert isinstance(cert.exact_match, bool)
    sig = support_signature_certificate(spec, lens, "H0", exact=True)
    assert sig.record_id == "H0"
    assert sig.entries
    assert cert.separating_pairs


def test_exact_support_enum_on_small_audit_universe():
    row_a = Row("rig_1", "k", "rig_1", payload={"atoms": [{"mode": "diag", "name": "rig_1"}]})
    spec = ExecutableBandSpec(
        name="small-support",
        frame=Frame(systems=("H0", "H1")),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={
            "H0": FiniteRecord("H0", "same", rows=()),
            "H1": FiniteRecord("H1", "same", rows=(row_a,)),
        },
        candidates=(),
        components=(ComponentFunctional("Rig", polarity="obstruction", upper=0),),
        read_coordinates=("row:rig_1",),
        exact_support_limit=4,
    )
    exact = exact_support_enum(spec, ReportLens("report"))
    assert frozenset({"row:rig_1"}) in exact
    assert all(isinstance(edge, frozenset) for edge in exact)
    result = support_checker_result(spec, ReportLens("report"), frozenset({"row:rig_1"}), "base")
    assert result.accepted
    assert result.to_dict()["support"] == ["row:rig_1"]


def test_typed_support_coordinates_separate_row_and_atom_names():
    row_a = Row("x", "k", "x", payload={"atoms": [{"mode": "diag", "name": "x"}]})
    spec = ExecutableBandSpec(
        name="typed-support",
        frame=Frame(systems=("H0", "H1")),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={
            "H0": FiniteRecord("H0", "same", rows=()),
            "H1": FiniteRecord("H1", "same", rows=(row_a,)),
        },
        candidates=(),
        components=(ComponentFunctional("Rig", polarity="obstruction", upper=0),),
        read_coordinates=("row:x", "atom:diag:x"),
        exact_support_limit=4,
    )
    coords = {coord for edge in exact_support_enum(spec, ReportLens("report")) for coord in edge}
    assert coords <= {"row:x", "atom:diag:x"}
    assert any(coord.startswith(("row:", "atom:")) for coord in coords)


def test_debt_unions_explicit_and_component_bound_morphisms():
    row_a = Row(
        "rig_1",
        "k",
        "rig_1",
        payload={
            "debt": True,
            "debt_atoms": ["explicit"],
            "component_values": {"Rig": 2},
            "atoms": [{"mode": "diag", "name": "explicit"}],
        },
    )
    spec = ExecutableBandSpec(
        name="debt-union",
        frame=Frame(systems=("H",)),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "same", rows=(row_a,))},
        candidates=(),
        components=(
            ComponentFunctional(
                "Rig", polarity="obstruction", upper=0, upper_debt_label="rig-bound"
            ),
        ),
    )
    assert compute_debt(spec, "H").debts == ("explicit", "rig-bound")
    cert = compute_debt_certificate(spec, "H")
    assert ("explicit", "rig_1") in cert.explicit
    assert any(item[0] == "rig-bound" for item in cert.component_bounds)
    audit = audit_component_functional(spec.components[0], strict=True)
    assert "aggregate-evaluator-is-convenience-only" in audit.warnings


def test_component_aggregate_and_lookup_evaluators():
    row_a = Row(
        "r1",
        "k",
        "r1",
        payload={
            "atoms": [{"mode": "floor", "name": "x"}],
            "component_values": {
                "Sum": 2,
                "Min": 2,
                "Set": "a",
                "Last": 2,
                "Count": 2,
            },
            "component_lookup": {"Lookup": "key"},
        },
    )
    row_b = Row(
        "r2",
        "k",
        "r2",
        payload={
            "atoms": [{"mode": "floor", "name": "x"}],
            "component_values": {
                "Sum": 3,
                "Min": 1,
                "Set": "b",
                "Last": 3,
                "Count": 3,
            },
        },
    )
    spec = ExecutableBandSpec(
        name="components",
        frame=Frame(systems=("H",)),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "same", rows=(row_a, row_b))},
        candidates=(),
        components=(
            ComponentFunctional("Sum", aggregator="sum"),
            ComponentFunctional("Min", aggregator="min"),
            ComponentFunctional("Set", aggregator="set", default=()),
            ComponentFunctional("Last", aggregator="last"),
            ComponentFunctional("Count", aggregator="count"),
            ComponentFunctional("Lookup", aggregator="lookup", eval_table={"key": 7}),
            ComponentFunctional("Default", aggregator="max", default=4),
        ),
    )
    profile = component_profile(spec, "H")
    assert profile["Sum"] == 5
    assert profile["Min"] == 1
    assert profile["Set"] == ("a", "b")
    assert profile["Last"] == 3
    assert profile["Count"] == 2
    assert profile["Lookup"] == 7
    assert profile["Default"] == 4


def test_release_cover_exact_and_greedy():
    universe = {"ob_1", "lb_1", "rig_1"}
    sets = {"a": {"ob_1"}, "b": {"lb_1"}, "c": {"rig_1"}, "ab": {"ob_1", "lb_1"}}
    assert solve_release_cover_exact(universe, sets, 2) == (True, ("ab", "c"))
    ok, chosen = greedy_release_cover(universe, sets, 2)
    assert ok
    assert set(chosen) <= set(sets)


def test_raw_release_closure_keeps_distinct_path_signatures_to_same_target():
    row = Row("r", "k", "r")
    local_stability = {
        "FootprintDet": True,
        "ComponentDebtPres": True,
        "StageStab": True,
        "SelKerStab": True,
        "OneStepReleaseBisim": True,
    }
    spec = ExecutableBandSpec(
        name="path-sensitive-release",
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
        releases=(
            cgt_release("r1", local_stability),
            cgt_release("r2", local_stability),
        ),
        release_check_table=ReleaseCheckTable(
            footprint_predicates={
                "r1": {
                    "obstructionCoverage": True,
                    "lowerBoundSuccessor": True,
                    "noNewRow": True,
                    "noninterference": True,
                    "diagnosticRetyping": True,
                },
                "r2": {
                    "obstructionCoverage": True,
                    "lowerBoundSuccessor": True,
                    "noNewRow": True,
                    "noninterference": True,
                    "diagnosticRetyping": True,
                },
            },
            footprint_coordinates={"r1": ("r",), "r2": ("r",)},
            predicate_coordinates={
                "r1": {
                    "obstructionCoverage": ("r",),
                    "lowerBoundSuccessor": ("r",),
                    "noNewRow": ("r",),
                    "noninterference": ("r",),
                    "diagnosticRetyping": ("r",),
                },
                "r2": {
                    "obstructionCoverage": ("r",),
                    "lowerBoundSuccessor": ("r",),
                    "noNewRow": ("r",),
                    "noninterference": ("r",),
                    "diagnosticRetyping": ("r",),
                },
            },
        ),
        band_rows=("r",),
    )
    closure = raw_release_closure(spec, "H0", ReportLens("report"))
    paths = {item[2] for item in closure}
    assert ("r1",) in paths
    assert ("r2",) in paths
    certificate = release_action_certificate(spec, ReportLens("report"), strict=True)
    assert certificate.accepted_certificates == ("r1", "r2")
    assert set(certificate.descent_certificates or {}) == {"r1", "r2"}


def test_completion_certificate_reports_report_fiber_split():
    row_a = Row(
        "rig_1",
        "k",
        "rig_1",
        payload={"atoms": [{"mode": "diag", "name": "rig_1"}], "debt": True},
    )
    spec = ExecutableBandSpec(
        name="completion-cert",
        frame=Frame(systems=("H0", "H1")),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={
            "H0": FiniteRecord("H0", "same", rows=()),
            "H1": FiniteRecord("H1", "same", rows=(row_a,)),
        },
        candidates=(),
        read_coordinates=("row:rig_1",),
        exact_support_limit=4,
    )
    cert = completion_certificate(spec, ReportLens("report"))
    assert not cert.factorization_ok
    assert cert.report_fiber_splits


def cgt_release(cert_id: str, local_stability: dict[str, bool]):
    from cgt_bandwidth.core import ReleaseCertificate

    return ReleaseCertificate.strict(
        cert_id,
        "H0",
        "H1",
        footprint=("r",),
        signature={"kind": "release", "row": cert_id},
        checker_trace=("declared-pass",),
    )


def test_cli_microframe_runs():
    result = subprocess.run(
        [sys.executable, "-m", "cgt_bandwidth.cli", "microframe", "run"],
        check=True,
        capture_output=True,
        text=True,
    )
    data = json.loads(result.stdout)
    assert ["H0", "H4"] in data["completion"]

    validate = subprocess.run(
        [
            sys.executable,
            "-m",
            "cgt_bandwidth.cli",
            "validate",
            "examples/minimal_spec.json",
            "--report",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(validate.stdout)
    assert "condition_status" in report


def test_cli_main_paths_and_schema_validation(capsys):
    assert main(["validate", "examples/minimal_spec.json", "--report"]) == 0
    report = json.loads(capsys.readouterr().out)
    schema = json.loads(Path("schemas/wellformedness-report.schema.json").read_text())
    jsonschema.validate(report, schema)

    assert main(["audit", "examples/minimal_spec.json", "--lens", "report", "--exact-support"]) == 0
    audit = json.loads(capsys.readouterr().out)
    assert "completion_certificate" in audit
    assert "release_action_certificate" in audit

    assert main(["release-cover", "examples/release_cover.json", "--exact"]) == 0
    cover = json.loads(capsys.readouterr().out)
    assert cover["covered"] is True

    assert main(["release-cover", "examples/release_cover.json", "--greedy"]) == 0
    assert json.loads(capsys.readouterr().out)["covered"] is True

    assert main(["close", "examples/minimal_spec.json", "H0"]) == 0
    closed = json.loads(capsys.readouterr().out)
    assert closed["record_id"] == "H0"

    assert main(["microframe", "spec"]) == 0
    micro_spec = json.loads(capsys.readouterr().out)
    assert micro_spec["name"] == "deterministic-microframe"

    assert main(["validate", "missing-file.json"]) == 2
    assert "error:" in capsys.readouterr().err

    spec_schema = json.loads(Path("schemas/executable-band-spec.schema.json").read_text())
    for example in Path("examples").glob("*.json"):
        if example.name == "release_cover.json":
            continue
        jsonschema.validate(json.loads(example.read_text()), spec_schema)
