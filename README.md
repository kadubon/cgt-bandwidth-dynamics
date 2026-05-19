# cgt-bandwidth

`cgt-bandwidth` is a v0.1.0 finite executable reference implementation of
**Constraint Bandwidth Dynamics in Constraint Generative Theory (CGT)**.

CGT treats constraints as typed effect transformations, not merely predicates to
satisfy. A constraint may generate observation, comparison, availability,
diagnostic, repair, release, and applicability-support evidence while the
visible report stays unchanged. The central intuition is that **a report is a
projection, not the effect profile**.

This is what makes constraint bandwidth different from ordinary constraint
solvers, diagnosis tools, database update systems, and view-update lenses. Those
tools usually ask whether a state satisfies a predicate, which fault explains an
observation, how to mutate stored facts, or how to round-trip a view. This
package asks a continuation-sensitive CGT question: after accumulated typed
constraint effects have been checked and retained, what can still be observed,
compared, made available, repaired, released, or selected by later constraints?

The implementation answers that question only on an explicitly declared finite
`AuditUniv`. It produces executable certificates for the finite row semantics;
it does not prove that an unstated infinite system is represented by that finite
universe.

## What This Repository Provides

- A Python library for finite CGT bandwidth audits.
- A CLI for validation, closure, audit reports, deterministic microframe replay,
  and release-cover synthesis.
- JSON/YAML data formats with no arbitrary code execution.
- Typed residual rows, mode-stratified evidence closure, stage evidence,
  component profiles, debt, support antichains, completion classes, release
  certificates, ambient row-universe checks, and release actions.
- A deterministic microframe fixture for `H0..H5`.
- Certificate-shaped audit output for closure, support, completion, and release
  descent.
- GitHub Actions CI for linting, type checking, tests, coverage, schema checks,
  package build validation, and artifact cleanliness.

The runtime core uses only the Python standard library. Development and CI use
`uv`, `pytest`, `ruff`, `mypy`, and `twine`.

## Names At A Glance

| Surface | Name |
| --- | --- |
| GitHub repository | `kadubon/cgt-bandwidth-dynamics` |
| Python package distribution | `cgt-bandwidth` |
| Python import package | `cgt_bandwidth` |
| CLI command | `cgt-bw` |
| Main library object | `ExecutableBandSpec` |
| Scientific conformance path | strict finite package + certificate APIs |

## What To Expect

Use this project when you want to answer finite questions such as:

- Which residual coordinates force a report-fiber split?
- Which candidates remain available, floor-safe, release-safe, or selectable?
- Which component/debt profile is induced by checked rows?
- Which release certificates are exact under the declared checker table?
- Which completion class does a record belong to under a report lens?

This is not a solver for arbitrary infinite CGT domains. Every theorem-level
claim is relative to the declared finite `AuditUniv`. Larger domains require an
external abstraction proof preserving row schemas, mode projections, stage
evidence, component evaluation, support coordinates, release footprints, and raw
release edges.

## Quick Start

```powershell
uv sync --all-extras --dev
uv run cgt-bw microframe run
```

Validate and audit the minimal example:

```powershell
uv run cgt-bw validate examples/minimal_spec.json
uv run cgt-bw validate examples/minimal_spec.json --report
uv run cgt-bw normalize-strict examples/minimal_spec.json
uv run cgt-bw validate examples/strict_minimal_spec.json --report --strict
uv run cgt-bw close examples/minimal_spec.json H0 --certificate
uv run cgt-bw close examples/strict_minimal_spec.json H0 --certificate --strict
uv run cgt-bw audit examples/minimal_spec.json --lens report --exact-support
uv run cgt-bw audit examples/minimal_spec.json --lens report --exact-support --compat-release
```

Run the release-cover core:

```powershell
uv run cgt-bw release-cover examples/release_cover.json --exact
uv run cgt-bw release-cover examples/release_cover.json --greedy
```

## Python API

```python
from cgt_bandwidth import ReportLens, completion_classes, compute_debt, compute_raw_bandwidth
from cgt_bandwidth.microframe import build_microframe_spec

spec = build_microframe_spec()
lens = ReportLens("report")

print(compute_raw_bandwidth(spec, "H1").to_dict())
print(compute_debt(spec, "H1").to_dict())
print(completion_classes(spec, lens).classes)
```

## Pipeline

1. Validate the finite executable specification.
2. Build the bounded closure store and retained failure/boundary rows.
3. Build the residual effect certificate hypergraph.
4. Compute eight-coordinate stage evidence and applicability support.
5. Evaluate component profiles, debt, band membership, and selected kernels.
6. Compute the bandwidth observable and completion classes.
7. Compute product support, exact support, support signatures, and separation coordinates.
8. Check release certificates and descend release actions to completion classes.
9. Solve the pure release-cover synthesis fragment when needed.

For conformance work, `validate --report` returns a machine-readable
`WF01..WF13` executable well-formedness report. `validate --strict` additionally
turns portability and certificate-explicitness issues into failures: legacy bare
read coordinates, implicit coordinate universes, aggregate component evaluators,
defaulted release local-stability predicates, incomplete release predicate
tables, heuristic retyping requirements, legacy `payload.derives`, incomplete
component eval/debt/support tables, and undeclared release proof traces.
Strict specs must either declare every finite `mode_matrix` pair explicitly or
be expanded with `cgt-bw normalize-strict`; compact defaults are a compatibility
feature, not the theorem-aligned path.
Strict mode is default for scientific conformance. Compatibility mode remains
available for legacy examples and migration, and release compatibility is
available in the audit CLI only through `--compat-release`.

## Data Format Notes

Rows are data, not code. Evidence atoms are mode-stratified (`floor`, `diag`,
`rel`, `cmp`, `avail`, `prov`). Support/read coordinates are typed:

- `row:o_1`
- `atom:diag:rig_1`

Legacy bare coordinate strings are accepted as row coordinates, but new specs
should use the typed labels to avoid row/atom name collisions.

See:

- `docs/spec-format.md`
- `docs/pipeline.md`
- `docs/theory-map.md`
- `docs/security.md`
- `docs/porting.md`
- `docs/api-stability.md`
- `docs/conformance-matrix.json`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CHANGELOG.md`

Machine-readable schemas are published under `schemas/`:

- `schemas/executable-band-spec.schema.json` for portable spec shape.
- `schemas/strict-executable-band-spec.schema.json` for strict finite package
  shape.
- `schemas/wellformedness-report.schema.json` for `validate --report`.
- `schemas/audit-report.schema.json` for `audit --exact-support`.
- `schemas/closure-certificate.schema.json` for `close --certificate`.
- `schemas/rech-certificate.schema.json` for typed residual hypergraph
  certificates.
- `schemas/evidence-audit.schema.json` for provenance-sensitive evidence audit.
- `schemas/component-law-certificate.schema.json` for finite component law
  checks.
- `schemas/support-certificate.schema.json` for support table certificates.
- `schemas/completion-certificate.schema.json` for completion certificates.
- `schemas/release-check.schema.json` for release checker output.
- `schemas/release-descent-certificate.schema.json` for the
  `release_action_certificate` section of audit output.
- `schemas/conformance-matrix.schema.json` for
  `docs/conformance-matrix.json`.
- `docs/conformance-matrix.json` for a machine-readable map from theory
  obligations to implementation surfaces and schemas.

Before publishing a local tree, run:

```powershell
uv run python scripts/publication_audit.py
uv build
uv run twine check dist/*
uv run python scripts/publication_audit.py --package dist --skip-worktree-artifacts
```

## Limitations

- The implementation is finite and certificate-relative.
- It does not prove that an external infinite system is represented by a finite
  audit universe.
- Proof assistant integration is not included.
- Component evaluators are pure finite data readers. Strict conformance accepts
  lookup/table evaluators and finite graph readers; Python callbacks are not
  accepted in specs.
- Exact support enumeration is exponential and bounded by `exact_support_limit`.
- The strict validation report is an executable audit artifact, not a formal
  proof assistant certificate.
- v0.1.0 is suitable as a finite executable reference and commercial-use OSS
  foundation under Apache-2.0; it is still marked alpha because theorem
  conformance is executable/certificate-relative rather than mechanically
  verified.

## Citation

Takahashi, K. (2026). *Constraint Generative Theory: Typed Constraint Effects
and Scientific Availability*. Zenodo. https://doi.org/10.5281/zenodo.20278525

## License

Apache-2.0. This project intentionally does not include a NOTICE file.
