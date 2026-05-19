"""Executable band specification and validation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from .contracts import (
    AuditUniverseScope,
    CandidateSpec,
    ComponentFunctional,
    MCVContract,
    ModeDecision,
    ModeTableCertificate,
    ReadCoord,
    ReleaseCertificate,
    ReleaseCheckTable,
    RowImplicationRule,
    StageCheck,
    StoreStepRule,
    StrictConformanceOptions,
    WellFormednessChecker,
    WellFormednessCheckerResult,
    WellFormednessIssue,
    WellFormednessReport,
    WorkBounds,
)
from .finite import MODES, STAGE_ORDER, sorted_unique
from .rows import EvidenceAtom, FiniteRecord, Frame, Row, RowSchema

WELLFORMEDNESS_CHECKERS: tuple[WellFormednessChecker, ...] = (
    WellFormednessChecker("WF01", "row-schema-totality", "row schemas, refs, verdicts, retentions"),
    WellFormednessChecker("WF02", "candidate-enumeration", "candidate rows under declared bounds"),
    WellFormednessChecker("WF03", "mode-matrix-totality", "finite mode decision table"),
    WellFormednessChecker("WF04", "rule-admissibility", "row rules accepted by ModeMat"),
    WellFormednessChecker("WF05", "stage-extraction", "total deterministic stage extraction"),
    WellFormednessChecker("WF06", "component-registry", "component carrier/eval/debt consistency"),
    WellFormednessChecker("WF07", "support-checker", "typed support coordinate universe"),
    WellFormednessChecker("WF08", "exact-support-enumerator", "bounded exhaustive support search"),
    WellFormednessChecker("WF09", "audit-universe-scope", "finite theorem domain declaration"),
    WellFormednessChecker("WF10", "release-check-table", "finite release predicate table"),
    WellFormednessChecker("WF11", "release-footprint-congruence", "release footprint universe"),
    WellFormednessChecker("WF12", "release-local-stability", "local release descent predicates"),
    WellFormednessChecker("WF13", "work-bounds", "positive finite work bounds"),
)


@dataclass(frozen=True)
class ExecutableBandSpec:
    name: str
    frame: Frame
    row_schemas: Mapping[str, RowSchema]
    records: Mapping[str, FiniteRecord]
    candidates: tuple[str, ...]
    cand_enum: Mapping[str, CandidateSpec] = field(default_factory=dict)
    candidate_semantics: Mapping[str, str] = field(default_factory=dict)
    candidate_evidence: Mapping[str, tuple[EvidenceAtom, ...]] = field(default_factory=dict)
    stage_checks: Mapping[str, Mapping[str, StageCheck]] = field(default_factory=dict)
    rules: tuple[RowImplicationRule, ...] = ()
    store_step_rules: tuple[StoreStepRule, ...] = ()
    rule_table_declared: bool = True
    components: tuple[ComponentFunctional, ...] = ()
    releases: tuple[ReleaseCertificate, ...] = ()
    release_check_table: ReleaseCheckTable = field(default_factory=ReleaseCheckTable)
    band_rows: tuple[str, ...] = ()
    mode_matrix: Mapping[tuple[str, str], ModeDecision | bool | Mapping[str, object]] = field(
        default_factory=dict
    )
    read_coordinates: tuple[str, ...] = ()
    work_bounds: WorkBounds = field(default_factory=WorkBounds)
    audit_scope: AuditUniverseScope = field(default_factory=AuditUniverseScope)
    exact_support_limit: int = 12
    legacy_read_coordinates: tuple[str, ...] = field(
        default=(), init=False, repr=False, compare=False
    )
    declared_mode_pairs: tuple[tuple[str, str], ...] = field(
        default=(), init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", str(self.name))
        object.__setattr__(self, "row_schemas", dict(self.row_schemas))
        object.__setattr__(self, "records", dict(self.records))
        object.__setattr__(self, "candidates", sorted_unique(self.candidates))
        cand_enum = dict(self.cand_enum)
        for candidate in self.candidates:
            cand_enum.setdefault(
                candidate,
                CandidateSpec(
                    id=candidate,
                    semantic_class=self.candidate_semantics.get(candidate, candidate),
                    evidence=tuple(self.candidate_evidence.get(candidate, ())),
                ),
            )
        object.__setattr__(self, "cand_enum", cand_enum)
        object.__setattr__(
            self,
            "candidate_semantics",
            {
                str(k): str(v)
                for k, v in {
                    **{k: v.semantic_class for k, v in cand_enum.items()},
                    **self.candidate_semantics,
                }.items()
            },
        )
        object.__setattr__(
            self,
            "candidate_evidence",
            {
                str(k): tuple(EvidenceAtom.from_obj(a) for a in (v or ()))
                for k, v in {
                    **{k: cand.evidence for k, cand in cand_enum.items()},
                    **self.candidate_evidence,
                }.items()
            },
        )
        object.__setattr__(self, "stage_checks", dict(self.stage_checks))
        object.__setattr__(self, "rules", tuple(self.rules))
        object.__setattr__(
            self,
            "store_step_rules",
            tuple(StoreStepRule.from_obj(rule) for rule in self.store_step_rules),
        )
        object.__setattr__(self, "rule_table_declared", bool(self.rule_table_declared))
        object.__setattr__(self, "components", tuple(self.components))
        object.__setattr__(self, "releases", tuple(self.releases))
        object.__setattr__(self, "release_check_table", self.release_check_table)
        object.__setattr__(self, "band_rows", sorted_unique(self.band_rows))
        declared_pairs = tuple(sorted((str(k[0]), str(k[1])) for k in self.mode_matrix))
        object.__setattr__(self, "declared_mode_pairs", declared_pairs)
        mode_matrix = {
            (left, right): ModeDecision(left == right) for left in MODES for right in MODES
        }
        mode_matrix.update(
            {(str(k[0]), str(k[1])): ModeDecision.from_obj(v) for k, v in self.mode_matrix.items()}
        )
        object.__setattr__(self, "mode_matrix", mode_matrix)
        object.__setattr__(
            self,
            "legacy_read_coordinates",
            tuple(
                sorted(
                    str(coord)
                    for coord in self.read_coordinates
                    if isinstance(coord, str) and ":" not in coord
                )
            ),
        )
        object.__setattr__(
            self,
            "read_coordinates",
            tuple(sorted({ReadCoord.from_obj(coord).label for coord in self.read_coordinates})),
        )
        object.__setattr__(self, "work_bounds", self.work_bounds)
        object.__setattr__(self, "audit_scope", self.audit_scope)
        object.__setattr__(self, "exact_support_limit", int(self.exact_support_limit))

    @property
    def audit_universe(self) -> tuple[FiniteRecord, ...]:
        return tuple(self.records[rid] for rid in sorted(self.records))

    def record(self, record_or_id: str | FiniteRecord) -> FiniteRecord:
        if isinstance(record_or_id, FiniteRecord):
            return record_or_id
        return self.records[str(record_or_id)]

    def validate(self) -> list[str]:
        return list(self.validate_report().problems)

    @staticmethod
    def wellformedness_checkers() -> tuple[WellFormednessChecker, ...]:
        return WELLFORMEDNESS_CHECKERS

    def mode_table_certificate(self) -> ModeTableCertificate:
        expected = tuple((left, right) for left in MODES for right in MODES)
        declared = tuple(sorted(self.declared_mode_pairs))
        normalized = tuple(sorted(self.mode_matrix))
        declared_set = set(declared)
        missing = tuple(pair for pair in expected if pair not in declared_set)
        return ModeTableCertificate(
            declared_pairs=declared,
            normalized_pairs=normalized,
            missing_pairs=missing,
            implicit_default_pairs=missing,
        )

    def validate_report(
        self,
        strict: bool = False,
        options: StrictConformanceOptions | None = None,
    ) -> WellFormednessReport:
        """Return a condition-indexed executable well-formedness audit.

        The condition labels correspond to the finite executable package
        requirements in the paper.  `strict=True` turns conservative portability
        and certificate-explicitness warnings into hard failures.
        """

        opts = options or StrictConformanceOptions.from_bool(strict)
        if strict and not opts.strict:
            opts = StrictConformanceOptions.from_bool(True)
        issues: list[WellFormednessIssue] = []
        all_conditions = tuple(f"WF{index:02d}" for index in range(1, 14))

        def add(
            condition: str,
            status: str,
            message: str,
            subject: str = "",
            *,
            evidence: Mapping[str, object] | None = None,
            witness_rows: tuple[str, ...] = (),
            repair_hint: str = "",
        ) -> None:
            issues.append(
                WellFormednessIssue(
                    condition,
                    status,
                    message,
                    subject,
                    evidence=evidence,
                    witness_rows=witness_rows,
                    repair_hint=repair_hint,
                )
            )

        def fail(
            condition: str,
            message: str,
            subject: str = "",
            *,
            evidence: Mapping[str, object] | None = None,
            witness_rows: tuple[str, ...] = (),
            repair_hint: str = "",
        ) -> None:
            add(
                condition,
                "fail",
                message,
                subject,
                evidence=evidence,
                witness_rows=witness_rows,
                repair_hint=repair_hint,
            )

        def warn(
            condition: str,
            message: str,
            subject: str = "",
            *,
            evidence: Mapping[str, object] | None = None,
            witness_rows: tuple[str, ...] = (),
            repair_hint: str = "",
        ) -> None:
            add(
                condition,
                "fail" if opts.strict else "warning",
                message,
                subject,
                evidence=evidence,
                witness_rows=witness_rows,
                repair_hint=repair_hint,
            )

        if not self.records:
            fail("WF09", "audit universe must contain at least one finite record")

        def validate_row(row: Row, context: str, row_map: Mapping[str, Row]) -> None:
            if (
                self.frame.row_kinds
                and row.kind not in self.frame.row_kinds
                and row.kind not in {"failure", "boundary"}
            ):
                fail(
                    "WF01",
                    f"{context}:{row.rid}: row kind outside frame carrier {row.kind}",
                    row.rid,
                    evidence={"kind": row.kind, "frame_row_kinds": list(self.frame.row_kinds)},
                    witness_rows=(row.rid,),
                    repair_hint="Add the row kind to the frame carrier or correct the row kind.",
                )
            if row.verdict not in self.frame.verdicts:
                fail(
                    "WF01",
                    f"{context}:{row.rid}: verdict outside frame carrier {row.verdict}",
                    row.rid,
                )
            if row.retention not in self.frame.retentions:
                fail(
                    "WF01",
                    f"{context}:{row.rid}: retention outside frame carrier {row.retention}",
                    row.rid,
                )
            schema = self.row_schemas.get(row.kind)
            if schema is None:
                fail(
                    "WF01",
                    f"{context}:{row.rid}: missing schema for kind {row.kind}",
                    row.rid,
                    evidence={"kind": row.kind},
                    witness_rows=(row.rid,),
                    repair_hint="Declare a RowSchema for this row kind.",
                )
                return
            ok, missing = schema.validate(row)
            if not ok:
                fail("WF01", f"{context}:{row.rid}: schema violation {missing}", row.rid)
            for ref in row.refs:
                target = row_map.get(ref)
                if target is None:
                    fail("WF01", f"{context}:{row.rid}: unknown ref {ref}", row.rid)
                elif schema.allowed_refs and target.kind not in schema.allowed_refs:
                    fail(
                        "WF01",
                        f"{context}:{row.rid}: ref {ref} kind {target.kind} not allowed",
                        row.rid,
                    )
            for raw in row.payload.get("derives", ()):
                warn(
                    "WF04",
                    f"{context}:{row.rid}: payload.derives is legacy compatibility input",
                    row.rid,
                    witness_rows=(row.rid,),
                    repair_hint="Move finite derived rows into store_step_rules for strict conformance.",
                )
                try:
                    derived = Row.from_obj(raw)
                except Exception as exc:
                    fail("WF01", f"{context}:{row.rid}: invalid derived row {exc}", row.rid)
                    continue
                if derived.kind not in self.row_schemas:
                    fail(
                        "WF01",
                        f"{context}:{row.rid}: derived row {derived.rid} missing schema {derived.kind}",
                        derived.rid,
                    )
                if derived.verdict not in self.frame.verdicts:
                    fail(
                        "WF01",
                        f"{context}:{row.rid}: derived row {derived.rid} invalid verdict {derived.verdict}",
                        derived.rid,
                    )
                if derived.retention not in self.frame.retentions:
                    fail(
                        "WF01",
                        f"{context}:{row.rid}: derived row {derived.rid} invalid retention {derived.retention}",
                        derived.rid,
                    )

        row_kinds_used = {row.kind for record in self.records.values() for row in record.rows}
        row_kinds_used.update(
            row.kind for candidate in self.cand_enum.values() for row in candidate.rows
        )
        row_kinds_used.update(row.kind for rule in self.store_step_rules for row in rule.emits)
        row_kinds_used.update({"failure", "boundary"})
        row_kinds_used.update(
            kind for component in self.components for kind in component.input_kinds
        )
        missing_schema = sorted(kind for kind in row_kinds_used if kind not in self.row_schemas)
        for kind in missing_schema:
            fail("WF01", f"executable well-formedness(i): missing schema for row kind {kind}", kind)
        mode_table = self.mode_table_certificate()
        if set(self.mode_matrix) != {(left, right) for left in MODES for right in MODES}:
            fail(
                "WF03",
                "executable well-formedness(iii): mode matrix is not total",
                evidence={"entries": len(self.mode_matrix), "expected": len(MODES) * len(MODES)},
                repair_hint="Declare or normalize every premise-mode/conclusion-mode pair.",
            )
        if opts.strict and not mode_table.explicit_total:
            fail(
                "WF03",
                "strict mode matrix must explicitly declare every premise/conclusion pair",
                evidence=mode_table.to_dict(),
                repair_hint="Run `cgt-bw normalize-strict spec.json` or declare every mode pair.",
            )
        required_release_predicates = {
            "obstructionCoverage",
            "lowerBoundSuccessor",
            "noNewRow",
            "noninterference",
            "diagnosticRetyping",
        }
        if set(self.release_check_table.required_predicates) != required_release_predicates:
            fail(
                "WF10",
                "executable well-formedness(x): release check table predicates are not total",
            )
        for record in self.records.values():
            seen: set[str] = set()
            record_rows = record.row_by_id()
            for row in record.rows:
                if row.rid in seen:
                    fail("WF01", f"{record.id}: duplicate row id {row.rid}", row.rid)
                seen.add(row.rid)
                validate_row(row, record.id, record_rows)
        for candidate_spec in self.cand_enum.values():
            row_map = {row.rid: row for row in candidate_spec.rows}
            if len(candidate_spec.rows) > self.work_bounds.candidate_rows:
                fail(
                    "WF02",
                    f"candidate {candidate_spec.id}: candidate row bound exceeded",
                    candidate_spec.id,
                )
            for row in candidate_spec.rows:
                validate_row(row, f"candidate:{candidate_spec.id}", row_map)
        if opts.strict and not self.rule_table_declared:
            fail(
                "WF04",
                "RuleTab is not explicitly declared",
                repair_hint="Declare rules or store_step_rules, even when the table is empty.",
            )
        for store_rule in self.store_step_rules:
            if not store_rule.id:
                fail("WF04", "store-step rule has empty id")
            if not store_rule.non_synthetic:
                fail("WF04", f"store-step rule {store_rule.id}: synthetic rule rejected")
            if store_rule.max_applications <= 0:
                fail("WF04", f"store-step rule {store_rule.id}: max_applications must be positive")
            if not store_rule.emits:
                fail("WF04", f"store-step rule {store_rule.id}: emits no rows")
            for emitted in store_rule.emits:
                validate_row(emitted, f"store-rule:{store_rule.id}", {emitted.rid: emitted})
        for rule in self.rules:
            if not rule.origin:
                fail(
                    "WF04",
                    f"rule {rule.conclusion.mode}:{rule.conclusion.name}: missing non-bottom origin",
                    rule.conclusion.name,
                )
            if not rule.prov_path and not rule.premises:
                fail(
                    "WF04",
                    f"rule {rule.conclusion.mode}:{rule.conclusion.name}: missing provenance path",
                    rule.conclusion.name,
                )
            if not rule.non_synthetic:
                fail(
                    "WF04",
                    f"rule {rule.conclusion.mode}:{rule.conclusion.name}: synthetic rule rejected",
                    rule.conclusion.name,
                )
            for prem in rule.premises:
                decision = ModeDecision.from_obj(
                    self.mode_matrix.get((prem.mode, rule.conclusion.mode), ModeDecision(False))
                )
                if not decision.permits(rule.premises, strict=opts.strict):
                    fail(
                        "WF04",
                        f"rule {rule.conclusion.mode}:{rule.conclusion.name}: "
                        f"mode pair {prem.mode}->{rule.conclusion.mode} rejected",
                        rule.conclusion.name,
                        evidence={"premise": prem.to_dict(), "rule": rule.to_dict()},
                        repair_hint="Add required release/retyping premises or reject the rule.",
                    )
                if decision.requires_retyping:
                    if not decision.retyping_evidence_present(rule.premises, strict=opts.strict):
                        fail(
                            "WF04",
                            f"rule {rule.conclusion.mode}:{rule.conclusion.name}: "
                            "required retyping evidence is absent",
                            rule.conclusion.name,
                        )
                    if decision.uses_heuristic_retyping:
                        warn(
                            "WF04",
                            f"rule {rule.conclusion.mode}:{rule.conclusion.name}: "
                            "retyping requirement uses legacy atom-name heuristic",
                            rule.conclusion.name,
                            evidence={"mode_pair": f"{prem.mode}->{rule.conclusion.mode}"},
                            repair_hint="Declare ModeDecision.retyping_atoms for strict conformance.",
                        )
                if decision.requires_release and not decision.release_evidence_present(
                    rule.premises, strict=opts.strict
                ):
                    fail(
                        "WF04",
                        f"rule {rule.conclusion.mode}:{rule.conclusion.name}: "
                        "required release evidence is absent",
                        rule.conclusion.name,
                    )
        for candidate in self.candidates:
            if candidate not in self.stage_checks:
                fail(
                    "WF05",
                    f"executable well-formedness(v): missing StageExtract checks for {candidate}",
                    candidate,
                )
            else:
                missing_stages = set(STAGE_ORDER) - set(self.stage_checks[candidate])
                if missing_stages:
                    fail(
                        "WF05",
                        f"executable well-formedness(v): StageExtract for {candidate} missing stages "
                        f"{sorted(missing_stages)}",
                        candidate,
                    )
            if candidate not in self.cand_enum:
                fail(
                    "WF02",
                    f"executable well-formedness: missing CandEnum entry for {candidate}",
                    candidate,
                )
        for candidate in self.cand_enum:
            if candidate not in self.candidates:
                warn("WF02", f"CandEnum entry is outside candidate list: {candidate}", candidate)
        for component in self.components:
            theorem_aligned_component = (
                component.aggregator == "lookup" or component.aggregator.startswith("graph_")
            )
            if component.aggregator != "lookup":
                if opts.active("reject_aggregate_components"):
                    fail(
                        "WF06",
                        f"component {component.name}: aggregate evaluator is convenience-only",
                        component.name,
                        evidence={"aggregator": component.aggregator},
                        repair_hint="Use a total lookup/table evaluator for strict conformance.",
                    )
            if opts.strict and not theorem_aligned_component:
                fail(
                    "WF06",
                    f"component {component.name}: evaluator is not finite table/graph aligned",
                    component.name,
                    evidence={"aggregator": component.aggregator},
                    repair_hint="Use lookup or graph_* component evaluators for strict conformance.",
                )
            if (
                component.aggregator == "lookup"
                and not component.eval_table
                and opts.active("require_lookup_eval_table")
            ):
                fail(
                    "WF06",
                    f"component {component.name}: lookup evaluator has no eval table",
                    component.name,
                    repair_hint="Declare eval_table entries covering the finite carrier inputs.",
                )
            if component.carrier and component.bottom not in component.carrier:
                fail(
                    "WF06",
                    f"component {component.name}: bottom is outside finite carrier",
                    component.name,
                )
            if component.carrier and component.default not in component.carrier:
                fail(
                    "WF06",
                    f"component {component.name}: default is outside finite carrier",
                    component.name,
                )
            if component.carrier:
                carrier = set(component.carrier)
                bad_preorder = [
                    (left, right)
                    for left, right in component.preorder
                    if left not in carrier or right not in carrier
                ]
                if bad_preorder:
                    fail(
                        "WF06",
                        f"component {component.name}: preorder references outside carrier",
                        component.name,
                    )
                missing_reflexive = [
                    value for value in component.carrier if (value, value) not in component.preorder
                ]
                if component.preorder and missing_reflexive:
                    fail(
                        "WF06",
                        f"component {component.name}: preorder is not reflexive",
                        component.name,
                    )
                if component.preorder:
                    for left, middle in component.preorder:
                        for mid2, right in component.preorder:
                            if middle == mid2 and (left, right) not in component.preorder:
                                fail(
                                    "WF06",
                                    f"component {component.name}: preorder is not transitive",
                                    component.name,
                                )
                                break
                        else:
                            continue
                        break
                for value, cls in component.congruence.items():
                    if value not in carrier:
                        fail(
                            "WF06",
                            f"component {component.name}: congruence references outside carrier",
                            component.name,
                            evidence={"value": repr(value), "class": repr(cls)},
                        )
                for value in component.eval_table.values():
                    if value not in carrier:
                        fail(
                            "WF06",
                            f"component {component.name}: eval table emits outside carrier",
                            component.name,
                        )
                if opts.strict:
                    for table_name, table in (
                        ("low-debt", component.low_debt_table),
                        ("up-debt", component.up_debt_table),
                        ("support", component.support_table),
                    ):
                        missing = [
                            value
                            for value in component.carrier
                            if value not in table and str(value) not in table
                        ]
                        if missing:
                            fail(
                                "WF06",
                                f"component {component.name}: {table_name} table is not total",
                                component.name,
                                evidence={
                                    "missing_values": [repr(value) for value in missing],
                                    "table": table_name,
                                },
                                repair_hint="Declare table entries for every finite carrier value.",
                            )
            if component.polarity == "capability" and component.upper is not None:
                fail(
                    "WF06",
                    f"component {component.name}: capability component has upper-obstruction debt",
                    component.name,
                )
            if component.polarity == "obstruction" and component.lower is not None:
                fail(
                    "WF06",
                    f"component {component.name}: obstruction component has lower-capability debt",
                    component.name,
                )
            if (
                component.polarity == "diagnostic"
                and "floor" in component.read_modes
                and not {"rel"} & set(component.read_modes)
            ):
                fail(
                    "WF06",
                    f"component {component.name}: diagnostic component feeds floor without release path",
                    component.name,
                )
            for coord in component.support_atoms:
                try:
                    ReadCoord.from_obj(coord)
                except Exception as exc:
                    fail("WF07", f"component {component.name}: invalid support coordinate {exc}")
        for coord in self.read_coordinates:
            try:
                ReadCoord.from_obj(coord)
            except Exception as exc:
                fail("WF07", f"invalid read coordinate {coord!r}: {exc}", coord)
        for coord in self.legacy_read_coordinates:
            message = f"legacy bare read coordinate {coord!r} is accepted only as a row coordinate"
            if opts.active("reject_legacy_read_coordinates"):
                fail(
                    "WF07",
                    message,
                    coord,
                    evidence={"interpreted_as": f"row:{coord}"},
                    repair_hint="Use row:<row-id> or atom:<mode>:<atom-name> labels.",
                )
            else:
                warn(
                    "WF07",
                    message,
                    coord,
                    evidence={"interpreted_as": f"row:{coord}"},
                    repair_hint="Use row:<row-id> or atom:<mode>:<atom-name> labels.",
                )
        if not self.read_coordinates:
            if opts.active("require_declared_read_coordinates"):
                fail(
                    "WF07",
                    "read coordinate universe is implicit",
                    repair_hint="Declare read_coordinates for reproducible support and release audits.",
                )
            else:
                warn(
                    "WF07",
                    "read coordinate universe is implicit",
                    repair_hint="Declare read_coordinates for reproducible support and release audits.",
                )
        if self.exact_support_limit <= 0:
            fail("WF08", "exact support limit must be positive")
        if self.exact_support_limit > self.work_bounds.support_subsets:
            warn(
                "WF08",
                "exact support limit exceeds declared support subset work bound",
                str(self.exact_support_limit),
            )
        record_ids = set(self.records)
        ambient_rows = {row.rid for record in self.records.values() for row in record.rows}
        ambient_rows.update(self.release_check_table.allowed_new_rows)
        for cert in self.releases:
            declared_predicates = self.release_check_table.declared_predicates_for(cert.id)
            missing_table_preds = sorted(required_release_predicates - set(declared_predicates))
            if opts.strict and missing_table_preds:
                fail(
                    "WF10",
                    f"release {cert.id}: footprint predicate table is incomplete {missing_table_preds}",
                    cert.id,
                    evidence={"declared": sorted(declared_predicates)},
                    repair_hint="Declare release_check_table.footprint_predicates for every release.",
                )
            for pred_name, pred_ok in declared_predicates.items():
                if not pred_ok:
                    fail(
                        "WF10",
                        f"release {cert.id}: declared footprint predicate {pred_name} fails",
                        cert.id,
                    )
                pred_coords = self.release_check_table.declared_predicate_coordinates_for(
                    cert.id, pred_name
                )
                if opts.strict and not pred_coords:
                    fail(
                        "WF10",
                        f"release {cert.id}: predicate {pred_name} has no coordinate witness",
                        cert.id,
                    )
                if pred_coords and set(pred_coords) - set(cert.footprint):
                    fail(
                        "WF10",
                        f"release {cert.id}: predicate {pred_name} reads outside footprint "
                        f"{sorted(set(pred_coords) - set(cert.footprint))}",
                        cert.id,
                    )
            declared_coords = self.release_check_table.declared_coordinates_for(cert.id)
            if opts.strict and not declared_coords:
                fail(
                    "WF11",
                    f"release {cert.id}: missing declared footprint coordinate set",
                    cert.id,
                    repair_hint="Declare release_check_table.footprint_coordinates for this certificate.",
                )
            if declared_coords:
                outside_declared_coords = set(cert.footprint) - set(declared_coords)
                if outside_declared_coords:
                    fail(
                        "WF11",
                        f"release {cert.id}: checker reads outside declared footprint coordinates "
                        f"{sorted(outside_declared_coords)}",
                        cert.id,
                    )
            if cert.source not in record_ids or cert.target not in record_ids:
                fail("WF11", f"release {cert.id}: source or target outside audit universe", cert.id)
            if not cert.footprint:
                fail("WF11", f"release {cert.id}: missing declared footprint", cert.id)
            outside = set(cert.footprint) - ambient_rows
            if outside:
                fail(
                    "WF11",
                    f"release {cert.id}: footprint reads outside declared row universe {sorted(outside)}",
                    cert.id,
                )
            for pred in (
                "FootprintDet",
                "ComponentDebtPres",
                "StageStab",
                "SelKerStab",
                "OneStepReleaseBisim",
            ):
                if pred not in cert.local_stability:
                    fail(
                        "WF12",
                        f"release {cert.id}: missing local stability predicate {pred}",
                        cert.id,
                    )
                if (
                    opts.active("require_explicit_local_stability")
                    and pred not in cert.local_stability_declared
                ):
                    fail(
                        "WF12",
                        f"release {cert.id}: local stability predicate {pred} is defaulted",
                        cert.id,
                    )
        if not self.audit_scope.whole_domain and not self.audit_scope.abstraction_map_declared:
            fail("WF09", "audit universe scope: non-whole domain requires abstraction map")
        if (
            min(
                self.work_bounds.closure_steps,
                self.work_bounds.candidate_rows,
                self.work_bounds.trace_depth,
                self.work_bounds.branch_depth,
                self.work_bounds.snapshot_depth,
                self.work_bounds.component_evals,
                self.work_bounds.support_subsets,
                self.work_bounds.release_checks,
                self.work_bounds.quotient_classes,
            )
            <= 0
        ):
            fail("WF13", "declared work bounds must be positive")

        touched = {issue.condition for issue in issues}
        for condition in all_conditions:
            if condition not in touched:
                add(condition, "pass", f"{condition} passed")
        by_condition: dict[str, list[WellFormednessIssue]] = {
            condition: [issue for issue in issues if issue.condition == condition]
            for condition in all_conditions
        }
        checker_name = {checker.condition: checker.name for checker in WELLFORMEDNESS_CHECKERS}
        rank = {"pass": 0, "warning": 1, "fail": 2}
        checker_results: list[WellFormednessCheckerResult] = []
        for condition in all_conditions:
            condition_issues = by_condition[condition]
            severity = max((issue.status for issue in condition_issues), key=lambda s: rank[s])
            checker_results.append(
                WellFormednessCheckerResult(
                    condition=condition,
                    checker=checker_name.get(condition, condition),
                    passed=severity != "fail",
                    issue_count=sum(1 for issue in condition_issues if issue.status != "pass"),
                    severity=severity,
                    witnesses=tuple(
                        row for issue in condition_issues for row in issue.witness_rows
                    ),
                )
            )
        return WellFormednessReport(tuple(issues), tuple(checker_results))


@dataclass(frozen=True)
class BandSpec:
    dimensions: tuple[str, ...]
    mcv_contract: MCVContract
    exec_spec: ExecutableBandSpec


def as_exec_spec(spec: ExecutableBandSpec | BandSpec) -> ExecutableBandSpec:
    if isinstance(spec, BandSpec):
        return spec.exec_spec
    return spec
