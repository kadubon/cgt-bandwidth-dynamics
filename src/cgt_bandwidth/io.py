"""JSON/YAML loading and safe serialization helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .core import (
    AuditUniverseScope,
    CandidateSpec,
    ComponentFunctional,
    EvidenceAtom,
    ExecutableBandSpec,
    FiniteRecord,
    Frame,
    ReleaseCertificate,
    ReleaseCheckTable,
    ReportLens,
    Row,
    RowImplicationRule,
    RowSchema,
    StageCheck,
    StoreStepRule,
    WorkBounds,
    thaw_value,
)


def load_data(path: str | Path) -> Any:
    path = Path(path)
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8")
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("YAML support requires the optional 'yaml' extra") from exc
        return yaml.safe_load(text)
    return json.loads(text)


def dump_json(data: Any) -> str:
    return json.dumps(thaw_value(data), ensure_ascii=False, indent=2, sort_keys=True)


def _schemas(data: dict[str, Any]) -> dict[str, RowSchema]:
    schemas = {}
    for kind, raw in data.get("row_schemas", {}).items():
        if isinstance(raw, dict):
            schemas[str(kind)] = RowSchema(kind=str(kind), **raw)
        else:
            schemas[str(kind)] = RowSchema(kind=str(kind))
    for builtin in ("failure", "boundary"):
        schemas.setdefault(builtin, RowSchema(kind=builtin))
    return schemas


def _stage_checks(raw: dict[str, Any]) -> dict[str, dict[str, StageCheck]]:
    result: dict[str, dict[str, StageCheck]] = {}
    for candidate, stages in raw.items():
        result[str(candidate)] = {}
        for stage, check in stages.items():
            result[str(candidate)][str(stage)] = StageCheck(
                required=tuple(EvidenceAtom.from_obj(atom) for atom in check.get("required", ())),
                blockers=tuple(EvidenceAtom.from_obj(atom) for atom in check.get("blockers", ())),
                reads=tuple(EvidenceAtom.from_obj(atom) for atom in check.get("reads", ())),
            )
    return result


def spec_from_dict(data: dict[str, Any]) -> ExecutableBandSpec:
    frame_data = data.get("frame", {})
    frame = Frame(
        systems=tuple(frame_data.get("systems", ())),
        effect_dimensions=tuple(frame_data.get("effect_dimensions", ())),
        occurrences=tuple(frame_data.get("occurrences", ())),
        row_kinds=tuple(frame_data.get("row_kinds", ())),
        semantic_ids=tuple(frame_data.get("semantic_ids", ())),
        laws=dict(frame_data.get("laws", {})),
    )
    rules = tuple(
        RowImplicationRule(
            premises=tuple(EvidenceAtom.from_obj(atom) for atom in raw.get("premises", ())),
            conclusion=EvidenceAtom.from_obj(raw["conclusion"]),
            origin=str(raw.get("origin", "")),
            prov_path=tuple(str(p) for p in raw.get("prov_path", ())),
            non_synthetic=bool(raw.get("non_synthetic", True)),
            cost=int(raw.get("cost", 0)),
            locality=tuple(str(x) for x in raw.get("locality", ())),
        )
        for raw in data.get("rules", ())
    )
    store_step_rules = tuple(
        StoreStepRule.from_obj(raw) for raw in data.get("store_step_rules", ())
    )
    mode_matrix = {}
    for key, value in data.get("mode_matrix", {}).items():
        if "->" in key:
            left, right = key.split("->", 1)
            mode_matrix[(left, right)] = value
    components = tuple(ComponentFunctional(**raw) for raw in data.get("components", ()))
    releases = tuple(ReleaseCertificate(**raw) for raw in data.get("releases", ()))
    cand_enum = {
        str(raw.get("id", candidate)): CandidateSpec(
            id=str(raw.get("id", candidate)),
            semantic_class=raw.get("semantic_class"),
            rows=tuple(Row.from_obj(row) for row in raw.get("rows", ())),
            evidence=tuple(EvidenceAtom.from_obj(atom) for atom in raw.get("evidence", ())),
        )
        for candidate, raw in data.get("cand_enum", {}).items()
    }
    candidate_evidence = {
        str(candidate): tuple(EvidenceAtom.from_obj(atom) for atom in atoms)
        for candidate, atoms in data.get("candidate_evidence", {}).items()
    }
    records = {str(raw["id"]): FiniteRecord.from_obj(raw) for raw in data.get("records", ())}
    return ExecutableBandSpec(
        name=str(data.get("name", "cgt-bandwidth-spec")),
        frame=frame,
        row_schemas=_schemas(data),
        records=records,
        candidates=tuple(str(c) for c in data.get("candidates", ())),
        cand_enum=cand_enum,
        candidate_semantics={
            str(k): str(v) for k, v in data.get("candidate_semantics", {}).items()
        },
        candidate_evidence=candidate_evidence,
        stage_checks=_stage_checks(data.get("stage_checks", {})),
        rules=rules,
        store_step_rules=store_step_rules,
        rule_table_declared=bool(
            data.get("rule_table_declared", "rules" in data or "store_step_rules" in data)
        ),
        components=components,
        releases=releases,
        release_check_table=ReleaseCheckTable(**data.get("release_check_table", {})),
        band_rows=tuple(str(x) for x in data.get("band_rows", ())),
        mode_matrix=mode_matrix,
        read_coordinates=tuple(data.get("read_coordinates", ())),
        work_bounds=WorkBounds(**data.get("work_bounds", {})),
        audit_scope=AuditUniverseScope(**data.get("audit_scope", {})),
        exact_support_limit=int(data.get("exact_support_limit", 12)),
    )


def load_spec(path: str | Path) -> ExecutableBandSpec:
    return spec_from_dict(load_data(path))


def report_lens_from_name(name: str) -> ReportLens:
    if name == "report":
        return ReportLens("report")
    if name.startswith("effects:"):
        return ReportLens(
            name=name,
            coordinates=tuple(part for part in name.removeprefix("effects:").split(",") if part),
        )
    return ReportLens(name=name)
