# Theory Map

This table maps the paper-level objects to the v0.1.0 executable
implementation. Status values are finite-audit scoped: `implemented` means the
finite executable semantics are present with machine-checkable certificate data;
`partial` is reserved for places where the remaining gap is a formal proof
assistant artifact or an infinite-domain abstraction proof.

| Paper object / claim | Status | Implementation |
| --- | --- | --- |
| finite typed-row frame | implemented | `Frame`, `Row`, `RowSchema`, `FiniteRecord` |
| effect profile and report lens | implemented | `EffectProfile`, `ReportLens`, `ActivePresentationLens` |
| MCV requirement contract | implemented | `MCVContract` data model |
| executable band specification | implemented | `ExecutableBandSpec`, `CandidateSpec`, `ModeDecision`, `ReleaseCheckTable`, `WorkBounds`, `AuditUniverseScope` |
| executable well-formedness | implemented | `ExecutableBandSpec.validate_report(strict=...)` emits a schema-versioned `WF01..WF13` report with evidence, witness rows, severity, repair hints, checker results, and `ModeTableCertificate`; strict mode rejects implicit/legacy/heuristic conformance shortcuts, including partial mode tables unless expanded by `cgt-bw normalize-strict` |
| bounded closure store | implemented | `close_store()` with retained failures, candidate-row bounds, boundary rows, compatibility `payload.derives`, and typed `StoreStepRule` closure; `close_store_with_certificate(strict=True)` treats `StoreStepRule` as the theorem-aligned derived-row source and exposes row-checker traces, accepted/failure/boundary/candidate/derived row ids, fixed-point reason, and `RuleTableCertificate` |
| residual effect certificate hypergraph | implemented | `build_rech_certificate()` emits typed incidence, provenance paths, retention/discharge paths, mode separation, successor preservation, store-transformation audit, and a nine-clause `RECHClauseResult` table |
| stage evidence vector | implemented | `StageEvidence(s,q,phi,gamma,ell,delta,omega,alpha)` and typed `StageFailure` |
| mode-stratified row closure | implemented | `evidence_closure(strict=...)` with structured mode decisions, `AtomKey` quotient identity, `AtomInstance` provenance identity, and `EvidenceAudit` for provenance collisions |
| mode isolation / no-free-row audits | implemented | `mode_isolation_audit()` checks rule and derivation traces; `no_free_row_closure_audit()` rejects synthetic usable conclusions |
| applicability support preorder | implemented | `applicability_support()` from candidate-visible evidence implication |
| executable component functional | implemented | strict theorem-aligned evaluators are finite lookup/table readers and pure finite graph readers (`graph_count`, `graph_reachability`, `graph_cut`); `ComponentLawCertificate` reports carrier, preorder, eval-totality, congruence, debt-table, and support-table checks |
| raw profile, debt, and band | implemented | `compute_raw_bandwidth()`, `compute_debt()`, `compute_debt_certificate()`, `is_in_band()` |
| product support algebra | implemented | `support_product()` over typed `ReadCoord` labels; `support_product_certificate()` and `SupportTableCertificate` expose when a sound full-coordinate fallback was used because exact coordinate minimization exceeded declared bounds |
| exact support enumeration | implemented | `exact_support_enum()` under `exact_support_limit` |
| support exactness / signatures / separation coordinates | implemented | `ReadCoordUniverseCertificate`, `SupportCheckerResult`, `SupportTableCertificate`, `support_exact_certificate()`, `support_signature_certificate()`, `separation_coordinate_objects()` expose portable certificate-shaped data, pairwise witnesses, minimality witnesses, and separating record pairs |
| bandwidth completion | implemented | `completion_classes()` as the kernel pair of `BWObservable`; `completion_certificate()`, `CompletionLawCertificate`, and `CompletionUniversalPropertyCertificate` record report-fiber splits, separation coordinates, and executable universal-property checks |
| completion operator laws | implemented | finite idempotence/report-refinement checks are emitted by `completion_law_certificate()` |
| report factorization obstruction | implemented | `report_factorization_obstruction()` and `completion_certificate()` return separating classes, report-fiber splits, separation coordinates, and universal-property witness tables |
| finite audit algorithm | implemented | CLI `audit` computes observable, completion, support, release graph, and release action in strict release mode by default; compatibility release checking is available only through `--compat-release` |
| release schema completeness | implemented | `check_release(strict=True)` checks declared finite predicates, predicate coordinate declarations, ambient row-universe membership, strict proof-map totality, checker trace presence, noninterference, no-new-row, no-new-obstruction, and diagnostic retyping; `certified_exact_release_certificate()` adds store-transformation and bounded ambient-store certificates |
| release certificate | implemented | `ReleaseCertificate` with discharge, preservation, no-new-obstruction, retyping, checker trace, local stability fields, and strict constructor |
| certificate congruence / one-step bisimulation | implemented | `ReleaseDescentCertificate` and `ReleaseDescentProof` record support signatures, all same-source-class certified release-pair checks, local-stability witnesses, predicate witnesses, and one-step bisimulation witnesses before descending to completion classes |
| release closure fixed point | implemented | `release_closure_fixed_point()` and strict `raw_release_closure_exact()` over certified exact release edges |
| release/deletion non-commutation | implemented | semantics and deterministic examples are present; release closure remains path-sensitive for non-identity signatures |
| pure release-cover synthesis | implemented | exact and greedy solvers in `complexity` and CLI `release-cover` |
| infinite domains / external abstraction `pi: Sys -> AuditUniv` | out of scope | documented future extension |
| proof assistant integration | out of scope | documented future extension |

The implementation is finite-audit scoped. A result computed by this package is a
claim about the declared `ExecutableBandSpec.audit_universe`, not about an
unstated larger system.

For v0.1.0, strict mode is default for scientific conformance. Non-strict
validation and `audit --compat-release` remain useful for migration fixtures,
but CI and downstream ports should use strict finite packages for
theorem-aligned executable audit data.

Citation: Takahashi, K. (2026). *Constraint Generative Theory: Typed Constraint Effects and Scientific Availability*. Zenodo. https://doi.org/10.5281/zenodo.20278525
