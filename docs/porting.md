# Porting Guide

The core algorithms are finite data transformations and can be ported to other languages directly. The Python package keeps portable data definitions in focused modules (`finite`, `rows`, `contracts`, `orders`, `spec`) and keeps algorithms in separate modules.

## Data Model

Represent these as immutable records:

- `Row`
- `RowSchema`
- `EvidenceAtom`
- `AtomKey`
- `AtomInstance`
- `ClosureStore`
- `StageCheck`
- `StageEvidence`
- `RowImplicationRule`
- `StoreStepRule`
- `StoreStepCertificate`
- `RuleTableCertificate`
- `CandidateSpec`
- `ComponentFunctional`
- `ComponentLawCertificate`
- `ReleaseCertificate`
- `ReleaseCheckTable`
- `RetypingCertificate`
- `ReleaseEvidencePath`
- `ModeTrace`
- `WorkBounds`
- `AuditUniverseScope`
- `StrictConformanceOptions`
- `ModeTableCertificate`
- `WellFormednessChecker`
- `WellFormednessCheckerResult`
- `WellFormednessReport`
- `ClosureCertificate`
- `RECHCertificate`
- `RECHClauseResult`
- `StorePreservationCertificate`
- `DebtCertificate`
- `SupportExact`
- `SupportCheckerResult`
- `SupportTableCertificate`
- `ReadCoordUniverseCertificate`
- `SuppSig`
- `CompletionCertificate`
- `CompletionLawCertificate`
- `CompletionUniversalPropertyCertificate`
- `ReleasePredicateWitness`
- `ReleaseCongruencePair`
- `ReleaseDescentProof`
- `ReleaseDescentCertificate`
- `ReleaseActionCertificate`
- `AmbientRowUniverse`
- `AmbientStoreEnumerator`
- `ReleaseTransformationCertificate`
- `CertifiedExactReleaseCertificate`
- `ExecutableBandSpec`

Use a deterministic normal form for maps and sets. Python uses sorted tuples through `freeze_value`; another language should use canonical JSON, ordered maps, or explicit structural hashes.

## Algorithms

1. Validate rows against schemas.
2. Apply all enabled `StoreStepRule` entries in deterministic order until the bounded fixed point; retain invalid rows and bound exhaustion as typed rows, and preserve row-checker and store-step traces. `payload.derives` is a compatibility input, not the preferred portable rule table.
3. Extract evidence atoms from closed rows.
4. Run finite forward closure over row-implication rules with mode admissibility, provenance, and non-synthetic checks.
5. Scan candidate stages in fixed order and choose first failure by `(stage,rowKind,semanticId,rowId)`.
6. Build applicability support from candidate-visible evidence implication.
7. Evaluate finite component functions from declared row payload values. Strict
   theorem-aligned evaluators are lookup/table readers and finite graph readers
   (`graph_count`, `graph_reachability`, `graph_cut`).
8. Compute debt from explicit residual debt rows or component bounds.
9. Build the bandwidth observable before quotienting.
10. Compute product support and, when bounded, exact joint support.
11. Partition records by observable equality to get completion classes.
12. Enumerate release edges from accepted certificates and checker-table pass
    results. In strict mode, each predicate must declare the coordinates it
    reads, every emitted target row must be in the ambient row universe, proof
    maps must be total, and checker traces must be present.
13. For exact finite release, compute `CertifiedExactReleaseCertificate` from
    the strict checker, store-transformation certificate, and bounded ambient
    store enumeration. Reject bound exhaustion explicitly instead of guessing.
14. Descend release action to completion classes only after support-signature
    checks, local stability, certificate congruence, and one-step bisimulation
    witnesses pass.

No step requires Python-specific reflection, dynamic import, or code execution.

## v0.1.0 Conformance Defaults

Ports should implement both compatibility mode and strict mode. Compatibility
mode may accept legacy bare read coordinates and aggregate component evaluators.
Strict mode should reject implicit coordinate universes, undeclared rule tables,
defaulted release stability predicates, incomplete footprint predicate tables,
heuristic retyping, and component evaluators that cannot be represented as
finite lookup/table or finite graph data.
Strict mode should also reject compact mode tables unless the implementation
emits a `ModeTableCertificate` showing that a normalizer expanded every ordered
mode pair.

Release checking should treat `ReleaseCheckTable.footprint_predicates` and
`ReleaseCheckTable.footprint_coordinates` as first-class data. Predicate-level
read sets should be represented through
`ReleaseCheckTable.predicate_coordinates`. A checker must not read outside the
declared footprint coordinate set.

For conformance tests in another language, compare canonical JSON output from
`validate --report`, `close_store_with_certificate`,
`support_exact_certificate`, `support_signature_certificate`,
`support_table_certificate`, `completion_certificate`,
`completion_law_certificate`, `completion_universal_property_certificate`,
`close_store_with_certificate`, `certified_exact_release_certificate`, and
`release_action_certificate` before optimizing internal representations.

Strict evidence closure should match premises by full provenance identity. A
diagnostic atom may be promoted into floor/availability/selection-relevant
evidence only when the same trace contains an explicitly declared typed
retyping or release evidence path.
