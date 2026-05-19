# Pipeline

The practical pipeline is deliberately staged so that small claims can run cheaply and exact audits can be requested only when needed.

## Level 0: Validate

`cgt-bw validate spec.json`

Checks the finite executable package: row schema totality, row ids, row references, mode-table totality, rule admissibility, full stage extraction tables, component polarity/debt consistency, release checker predicates, audit-universe scope, and declared work bounds.

`cgt-bw validate spec.json --report` emits a `WF01..WF13` report suitable for
CI and cross-language conformance fixtures. `--strict` additionally requires
portable, certificate-explicit declarations: typed read coordinates, declared
support coordinate universe, lookup/table component evaluators for strict
component conformance, explicit release predicate tables, explicit footprint
coordinate sets, explicit release local-stability predicates, total component
debt/support tables, and non-heuristic retyping evidence paths.
It also requires a complete explicit finite `mode_matrix`. To expand compact
identity-default specs without mutating the input, run:

`cgt-bw normalize-strict spec.json`

Expected output is either a compact `ok`/problem list or a schema-versioned JSON
report. A strict failure should be interpreted as an undeclared finite-theory
assumption, not as a Python runtime error.

## Level 1: Closure And RECH

`cgt-bw close spec.json H0`

Builds a bounded inflationary closure store. Passing rows may emit finite
derived rows through declared `StoreStepRule` entries; `payload.derives` remains
accepted for legacy fixtures. Failed checks are retained as diagnostic rows
instead of being omitted. Bound exhaustion creates retained boundary rows.

Library users can call `close_store_with_certificate()` to get row-checker
results, emitted derived rows, retained failures, and store-step traces.
The returned certificate includes `RuleTableCertificate`, so ports can check
which finite store-step rules were enabled, applied, or blocked.
The CLI equivalent is:

`cgt-bw close spec.json H0 --certificate`

Use `--strict` with strict finite packages:

`cgt-bw close spec.json H0 --certificate --strict`

`build_rech(store)` constructs a residual effect certificate hypergraph with row, semantic, atom, reference, verdict, and retention incidences.
`build_rech_certificate()` adds provenance paths, well-formedness problems, a
nine-clause RECH result table, mode separation, successor preservation, and
store-transformation audit data.

Expected certificate output includes row-checker results, retained failures,
boundary rows, candidate rows, and rule-table traces. If a row is retained as a
failure, downstream stages should treat it as diagnostic evidence rather than as
an absent row.

## Level 2: Bandwidth Object

Computes:

- stage evidence for each candidate;
- applicability-support preorder;
- raw component bandwidth;
- debt profile;
- selected kernel.

## Level 3: Completion And Support

`cgt-bw audit spec.json --lens report`

Computes the finite bandwidth observable and its kernel-pair completion. `support_product` returns a sound coordinate-wise product certificate. `exact_support_enum` returns the joint inclusion-minimal supports for small coordinate universes, and `support_exact` compares the two antichains.

For portable audit output, use `support_exact_certificate` and
`support_signature_certificate`; the CLI includes these when `--exact-support`
is requested.
`completion_certificate()` records report-fiber splits and the separating
support coordinates that witness report incompleteness. v0.1.0 certificate
output also includes pairwise support witnesses, minimality witnesses, and
executable universal-property checks for the completion partition. Use
`support_table_certificate()` and `completion_law_certificate()` when a
cross-language conformance runner needs table-level evidence.

Support coordinates are typed labels such as `row:o_1` and `atom:diag:rig_1`.

Expected exact-support output may be exponential. If the coordinate universe
exceeds `exact_support_limit`, use product support or raise the bound
deliberately in the spec.

## Level 4: Release

Release certificates are finite records, not cancellation commands. The checker reads declared footprints and verifies obstruction coverage, lower-bound successors, no-new-row, noninterference, no-new-obstruction, diagnostic retyping, and the five local stability predicates. Release action is introduced only after completion classes are computed.

`release_action_certificate` records accepted certificates, skipped
certificates, checker traces, descent certificates, support signatures, and the
descended completion-class relation.
Use `cgt-bw audit spec.json --strict-release` when release descent should fail
unless the finite footprint predicate table and local-stability declarations are
explicit.
Strict release certificates also include ambient row-universe checks and
`ReleaseDescentProof`, which enumerates predicate witnesses and same-source-class
congruent release-pair checks before descending to completion classes. Missing
strict proof maps or missing checker traces fail the release checker before
descent.
`certified_exact_release_certificate()` and `raw_release_closure_exact()` use
the strict checker, ambient row-universe membership, transformation
certificate, and bounded ambient-store enumerator. Exact release may fail with a
bound-exhaustion certificate when `work_bounds.release_checks` is too small.
The compatibility `raw_release_closure()` remains path-sensitive for
non-identity certificate signatures; identity self-release is normalized to the
empty path.

## Level 5: Exact/Hard Fragments

`cgt-bw release-cover examples/release_cover.json --exact`

Solves the pure release-cover core exactly for small inputs. `--greedy` exposes the standard set-cover heuristic boundary.

Expected exact output is deterministic for a fixed instance. Greedy output is
useful for large planning, but it is not a proof of minimum cover size.
