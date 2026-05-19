# API Stability

`cgt-bandwidth` is currently alpha software. The preferred extension strategy is
additive:

- keep existing public imports from `cgt_bandwidth` and `cgt_bandwidth.core`;
- add certificate APIs beside compact APIs rather than replacing them;
- keep CLI JSON keys stable once documented in `schemas/`;
- mark compatibility behavior that is weaker than strict conformance as a
  warning in `validate --report`, and as a failure under `validate --strict`.

Breaking changes are allowed before `1.0` only when needed to preserve the
finite executable semantics or eliminate a security risk.

## v0.1.0 Public Surface

The compact APIs remain stable for v0.x: `close_store`, `evidence_closure`,
`stage_evidence`, `compute_raw_bandwidth`, `compute_debt`,
`completion_classes`, `support_product`, `exact_support_enum`,
`release_graph`, and `release_action`.

The certificate APIs are the preferred integration surface for ports and audit
dashboards: `validate_report`, `close_store_with_certificate`,
`build_rech_certificate`, `evidence_audit`, `compute_debt_certificate`,
`support_exact_certificate`, `support_table_certificate`,
`read_coordinate_universe_certificate`, `completion_certificate`,
`completion_law_certificate`, `completion_universal_property_certificate`,
`check_release`, `certified_exact_release_certificate`,
`raw_release_closure_exact`, and `release_action_certificate`.

v0.1.0 also exposes finite-theory certificate records used by those APIs:
`StoreStepRule`, `StoreStepCertificate`, `RuleTableCertificate`,
`ModeTableCertificate`, `WellFormednessCheckerResult`,
`RetypingCertificate`, `ReleaseEvidencePath`, `ModeTrace`,
`ComponentLawCertificate`, `SupportTableCertificate`,
`ReadCoordUniverseCertificate`, `CompletionLawCertificate`,
`CompletionUniversalPropertyCertificate`, `RECHClauseResult`,
`StorePreservationCertificate`, `AmbientRowUniverse`, `AmbientStoreEnumerator`,
`ReleaseTransformationCertificate`, `CertifiedExactReleaseCertificate`,
`ReleasePredicateWitness`, `ReleaseCongruencePair`, and `ReleaseDescentProof`.
These records are pure data containers intended to
serialize cleanly to JSON-shaped dictionaries.

Schemas under `schemas/` are versioned by their `schema_version` or `$id`.
New fields may be added in v0.x, but documented fields will not be removed
without a changelog entry.
