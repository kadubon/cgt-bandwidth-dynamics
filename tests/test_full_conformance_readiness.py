import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from cgt_bandwidth.bandwidth import bandwidth_object, compute_debt_certificate
from cgt_bandwidth.cli import main
from cgt_bandwidth.completion import (
    completion_certificate,
    completion_universal_property_certificate,
)
from cgt_bandwidth.components import component_law_certificate
from cgt_bandwidth.core import (
    ComponentFunctional,
    ExecutableBandSpec,
    FiniteRecord,
    Frame,
    ModeDecision,
    ReleaseCertificate,
    ReleaseCheckTable,
    ReportLens,
    Row,
    RowSchema,
    WorkBounds,
)
from cgt_bandwidth.evidence import evidence_audit
from cgt_bandwidth.io import load_data, load_spec
from cgt_bandwidth.rech import build_rech_certificate
from cgt_bandwidth.release import (
    AmbientRowUniverse,
    ambient_store_enumerator,
    certified_exact_release_certificate,
    raw_release_closure_exact,
    release_checker_exact,
    release_closure_fixed_point,
    release_graph,
    release_transformation_certificate,
)
from cgt_bandwidth.support import (
    SepCoord,
    exact_support_enum,
    read_coordinate_universe,
    read_coordinate_universe_certificate,
    separation_coordinate_objects,
    support_signature_certificate,
    support_table_certificate,
)


def _mode_matrix() -> dict[tuple[str, str], ModeDecision]:
    modes = ("floor", "diag", "rel", "cmp", "avail", "prov")
    return {(left, right): ModeDecision(left == right) for left in modes for right in modes}


def _release_table(cert_id: str, coords=("r",)) -> ReleaseCheckTable:
    predicates = {
        "obstructionCoverage": True,
        "lowerBoundSuccessor": True,
        "noNewRow": True,
        "noninterference": True,
        "diagnosticRetyping": True,
    }
    return ReleaseCheckTable(
        footprint_predicates={cert_id: predicates},
        footprint_coordinates={cert_id: tuple(coords)},
        predicate_coordinates={cert_id: {name: tuple(coords) for name in predicates}},
    )


def test_strict_mode_table_certificate_and_normalizer(capsys):
    spec = ExecutableBandSpec(
        name="implicit-mode-table",
        frame=Frame(systems=("H",)),
        row_schemas={"failure": RowSchema("failure"), "boundary": RowSchema("boundary")},
        records={"H": FiniteRecord("H", "same", rows=())},
        candidates=(),
        mode_matrix={("floor", "floor"): ModeDecision(True)},
        read_coordinates=("row:r",),
    )
    cert = spec.mode_table_certificate()
    assert not cert.explicit_total
    assert "diag->floor" in cert.to_dict()["missing_pairs"]
    report = spec.validate_report(strict=True)
    assert not report.ok
    assert any("mode matrix must explicitly declare" in problem for problem in report.problems)
    assert report.to_dict()["checker_results"][2]["condition"] == "WF03"

    assert main(["normalize-strict", "examples/minimal_spec.json"]) == 0
    normalized = json.loads(capsys.readouterr().out)
    assert len(normalized["mode_matrix"]) == 36
    assert normalized["mode_matrix"]["floor->floor"]["allowed"] is True


def test_rech_typed_incidence_and_store_preservation_certificate():
    source = Row(
        "r",
        "k",
        "r",
        payload={
            "source": "seed",
            "witness": True,
            "mcv": True,
            "polarity": "diagnostic",
            "successor": "s",
            "atoms": [{"mode": "diag", "name": "d", "origin": "r", "prov": ["r"]}],
        },
    )
    successor = Row("s", "k", "s", payload={"source": "r"})
    spec = ExecutableBandSpec(
        name="rech-typed",
        frame=Frame(systems=("H",)),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "same", rows=(source, successor))},
        candidates=(),
        read_coordinates=("row:r", "row:s"),
    )
    cert = build_rech_certificate(spec, "H")
    payload = cert.to_dict()
    assert payload["typed_nodes"]
    assert payload["typed_arcs"]
    assert payload["store_preservation"]["passed"] is True
    assert "r" in payload["store_preservation"]["witness_rows"]
    assert cert.store_preservation is not None
    assert cert.store_preservation.successor_rows == (("r", "s", True),)


def test_support_completion_component_and_schema_certificates_validate():
    row = Row(
        "r",
        "k",
        "r",
        payload={
            "atoms": [{"mode": "diag", "name": "d", "origin": "r", "prov": ["r"]}],
            "component_lookup": {"Rig": "key"},
        },
    )
    component = ComponentFunctional(
        "Rig",
        polarity="obstruction",
        aggregator="lookup",
        carrier=(0, 1),
        bottom=0,
        default=0,
        preorder=frozenset({(0, 0), (1, 1)}),
        eval_table={"key": 1},
        low_debt_table={"0": (), "1": ()},
        up_debt_table={"0": (), "1": ("rig",)},
        support_table={"0": ("row:r",), "1": ("row:r",)},
        upper=1,
    )
    spec = ExecutableBandSpec(
        name="schema-certs",
        frame=Frame(systems=("H0", "H1")),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={
            "H0": FiniteRecord("H0", "same", rows=()),
            "H1": FiniteRecord("H1", "same", rows=(row,)),
        },
        candidates=(),
        components=(component,),
        read_coordinates=("row:r",),
        exact_support_limit=4,
    )
    lens = ReportLens("report")
    support = support_table_certificate(spec, lens, exact=True).to_dict()
    universe = read_coordinate_universe_certificate(spec, lens).to_dict()
    completion = completion_universal_property_certificate(spec, lens).to_dict()
    component_payload = component_law_certificate(component, strict=True).to_dict()

    assert universe["declared_coordinates"] == ["row:r"]
    assert completion["passed"] is True
    jsonschema.validate(
        support, json.loads(Path("schemas/support-certificate.schema.json").read_text())
    )
    jsonschema.validate(
        component_payload,
        json.loads(Path("schemas/component-law-certificate.schema.json").read_text()),
    )
    jsonschema.validate(
        completion_universal_property_certificate(spec, lens).to_dict()["checks"],
        {"type": "object"},
    )
    jsonschema.validate(
        completion_certificate(spec, lens).to_dict(),
        json.loads(Path("schemas/completion-certificate.schema.json").read_text()),
    )


def test_certified_exact_release_and_exact_raw_closure():
    row = Row("r", "k", "r")
    release = ReleaseCertificate.strict(
        "rel",
        "H0",
        "H1",
        footprint=("r",),
        discharges=("r",),
        discharge_map={"r": "r"},
        signature={"kind": "release", "row": "rel"},
    )
    spec = ExecutableBandSpec(
        name="exact-release",
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
        releases=(release,),
        release_check_table=_release_table("rel"),
        band_rows=("r",),
        read_coordinates=("row:r",),
        work_bounds=WorkBounds(release_checks=16),
    )
    transformation = release_transformation_certificate(spec, release)
    exact = certified_exact_release_certificate(spec, release)
    assert transformation.passed
    assert exact.passed
    exact_payload = exact.to_dict()
    assert exact_payload["transformation"]["passed"] is True
    assert ambient_store_enumerator(spec, "H0").to_dict()["passed"] is True
    assert release_graph(spec).to_dict()["edges"][0]["certificate"] == "rel"
    assert release_closure_fixed_point(spec, "H0") == ("H0", "H1")
    assert release_checker_exact(release) is True
    assert AmbientRowUniverse.for_record(spec, "H0").record_id == "H0"
    assert ("rel",) in {
        item[2] for item in raw_release_closure_exact(spec, "H0", ReportLens("report"))
    }
    jsonschema.validate(
        exact.check_result.to_dict(),
        json.loads(Path("schemas/release-check.schema.json").read_text()),
    )


def test_new_schemas_and_publication_audit_smoke():
    spec = load_spec("examples/strict_minimal_spec.json")
    assert spec.validate_report(strict=True).ok
    report = spec.validate_report(strict=True).to_dict()
    jsonschema.validate(
        report, json.loads(Path("schemas/wellformedness-report.schema.json").read_text())
    )

    evidence = evidence_audit(spec, set(), strict=True).to_dict()
    jsonschema.validate(
        evidence, json.loads(Path("schemas/evidence-audit.schema.json").read_text())
    )

    rech = build_rech_certificate(spec, "H0").to_dict()
    jsonschema.validate(rech, json.loads(Path("schemas/rech-certificate.schema.json").read_text()))

    completion = load_data("schemas/completion-certificate.schema.json")
    assert completion["title"] == "CompletionCertificate"

    result = subprocess.run(
        [sys.executable, "scripts/publication_audit.py", "--skip-worktree-artifacts"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "publication audit passed" in result.stdout


def test_debt_certificate_and_coordinate_certificates_cover_portable_outputs():
    row = Row(
        "r",
        "k",
        "r",
        payload={
            "atoms": [{"mode": "diag", "name": "explicit", "origin": "r", "prov": ["r"]}],
            "debt": True,
            "component_lookup": {"High": "hi", "Low": "lo"},
        },
    )
    high = ComponentFunctional(
        "High",
        aggregator="lookup",
        input_kinds=("k",),
        read_modes=("diag",),
        carrier=(0, 2),
        default=0,
        eval_table={"hi": 2},
        up_debt_table={"0": (), "2": ("high-table",)},
        support_table={"0": ("row:r",), "2": ("atom:diag:explicit",)},
        upper=1,
        upper_debt_label="high-bound",
    )
    low = ComponentFunctional(
        "Low",
        aggregator="lookup",
        input_kinds=("k",),
        read_modes=("diag",),
        carrier=(-1, 0),
        default=0,
        eval_table={"lo": -1},
        low_debt_table={"-1": ("low-table",), "0": ()},
        support_table={"-1": ("row:r",), "0": ("row:r",)},
        lower=0,
        lower_debt_label="low-bound",
    )
    spec = ExecutableBandSpec(
        name="debt-output",
        frame=Frame(systems=("H",)),
        row_schemas={
            "k": RowSchema("k"),
            "failure": RowSchema("failure"),
            "boundary": RowSchema("boundary"),
        },
        records={"H": FiniteRecord("H", "same", rows=(row,))},
        candidates=(),
        components=(high, low),
        exact_support_limit=6,
    )

    debt = compute_debt_certificate(spec, "H")
    payload = debt.to_dict()
    assert {"explicit", "high-table", "high-bound", "low-table", "low-bound"} <= set(
        payload["debts"]
    )
    assert bandwidth_object(spec, "H").to_dict()["debt"]["bottom"] is False

    lens = ReportLens("report")
    coords = read_coordinate_universe(spec, lens)
    assert "row:r" in coords
    assert "atom:diag:explicit" in coords
    signature_payload = support_signature_certificate(spec, lens, "H", exact=True).to_dict()
    assert signature_payload["record_id"] == "H"
    assert all(
        item.to_dict()["kind"] in {"row", "atom"}
        for item in separation_coordinate_objects(spec, lens)
    )

    atom_coord = SepCoord("atom:diag:explicit")
    assert atom_coord.label == "atom:diag:explicit"
    assert atom_coord.to_dict()["mode"] == "diag"

    atom_only_spec = ExecutableBandSpec(
        name="atom-coordinate",
        frame=spec.frame,
        row_schemas=spec.row_schemas,
        records=spec.records,
        candidates=(),
        components=spec.components,
        read_coordinates=("atom:diag:explicit",),
        exact_support_limit=1,
    )
    assert support_signature_certificate(atom_only_spec, lens, "H").to_dict()["entries"]
    too_many_coords = ExecutableBandSpec(
        name="support-bound",
        frame=spec.frame,
        row_schemas=spec.row_schemas,
        records=spec.records,
        candidates=(),
        read_coordinates=("row:r", "atom:diag:explicit"),
        exact_support_limit=1,
    )
    with pytest.raises(ValueError, match="exact support enumeration"):
        exact_support_enum(too_many_coords, lens)
