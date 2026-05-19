from cgt_bandwidth.bandwidth import compute_debt, compute_raw_bandwidth
from cgt_bandwidth.completion import completion_classes
from cgt_bandwidth.core import ReportLens
from cgt_bandwidth.microframe import build_microframe_spec
from cgt_bandwidth.pipeline import applicability_support, selected_kernel, stage_evidence
from cgt_bandwidth.release import release_action, release_closure_fixed_point


def test_microframe_band_vectors_and_debt():
    spec = build_microframe_spec()
    expected = {
        "H0": (
            {
                "ObsRank": 1,
                "CmpInv": 1,
                "PreProbe": 2,
                "PostProbe": 2,
                "RelCap": 1,
                "RepSlack": 1,
                "Rig": 0,
            },
            (),
        ),
        "H1": (
            {
                "ObsRank": 1,
                "CmpInv": 1,
                "PreProbe": 2,
                "PostProbe": 1,
                "RelCap": 0,
                "RepSlack": 0,
                "Rig": 1,
            },
            ("ob_1",),
        ),
        "H2": (
            {
                "ObsRank": 2,
                "CmpInv": 2,
                "PreProbe": 3,
                "PostProbe": 2,
                "RelCap": 1,
                "RepSlack": 1,
                "Rig": 0,
            },
            (),
        ),
        "H3": (
            {
                "ObsRank": 1,
                "CmpInv": 1,
                "PreProbe": 2,
                "PostProbe": 0,
                "RelCap": 0,
                "RepSlack": 0,
                "Rig": 1,
            },
            ("lb_1", "ob_1"),
        ),
        "H4": (
            {
                "ObsRank": 1,
                "CmpInv": 1,
                "PreProbe": 2,
                "PostProbe": 2,
                "RelCap": 1,
                "RepSlack": 1,
                "Rig": 0,
            },
            (),
        ),
        "H5": (
            {
                "ObsRank": 1,
                "CmpInv": 1,
                "PreProbe": 2,
                "PostProbe": 2,
                "RelCap": 1,
                "RepSlack": 1,
                "Rig": 2,
            },
            ("rig_1",),
        ),
    }
    for record_id, (vector, debt) in expected.items():
        assert compute_raw_bandwidth(spec, record_id).to_dict() == dict(sorted(vector.items()))
        assert compute_debt(spec, record_id).debts == debt


def test_microframe_applicability_support():
    spec = build_microframe_spec()
    assert applicability_support(spec, "H0").pairs == frozenset(
        {("a", "a"), ("a", "b"), ("b", "b")}
    )
    assert applicability_support(spec, "H1").pairs == frozenset({("b", "b")})
    assert applicability_support(spec, "H2").pairs == frozenset({("a", "a"), ("b", "b")})
    assert applicability_support(spec, "H3").pairs == frozenset()


def test_microframe_stage_and_kernel():
    spec = build_microframe_spec()
    assert stage_evidence(spec, "H1", "a").first_failure.startswith("floor_safe:")
    assert stage_evidence(spec, "H1", "b").first_failure is None
    assert selected_kernel(spec, "H1") == ("B",)
    assert selected_kernel(spec, "H3") == ()


def test_microframe_completion_and_release():
    spec = build_microframe_spec()
    lens = ReportLens("report")
    completion = completion_classes(spec, lens)
    assert ("H0", "H4") in completion.classes
    assert completion.class_of("H0") == completion.class_of("H4")
    assert release_closure_fixed_point(spec, "H1") == ("H1", "H4")
    action = release_action(spec, lens)
    assert completion.class_of("H4") in action[completion.class_of("H1")]
