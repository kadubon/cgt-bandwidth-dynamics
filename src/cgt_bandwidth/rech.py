"""Residual effect certificate hypergraph construction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .closure import close_store
from .core import RECH, ClosureStore, ExecutableBandSpec, FiniteRecord, as_exec_spec


@dataclass(frozen=True)
class RECHClauseResult:
    clause: str
    passed: bool
    witnesses: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "clause": self.clause,
            "passed": self.passed,
            "witnesses": list(self.witnesses),
            "problems": list(self.problems),
        }


@dataclass(frozen=True)
class RECHNode:
    node_id: str
    kind: str
    label: str

    @classmethod
    def from_label(cls, label: str) -> RECHNode:
        if ":" in label:
            kind, rest = label.split(":", 1)
            return cls(node_id=label, kind=kind, label=rest)
        return cls(node_id=label, kind="record", label=label)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.node_id, "kind": self.kind, "label": self.label}


@dataclass(frozen=True)
class RECHArc:
    kind: str
    sources: tuple[str, ...]
    target: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "sources": list(self.sources), "target": self.target}


@dataclass(frozen=True)
class StorePreservationCertificate:
    record_id: str
    outside_footprint_preserved: bool
    footprint: tuple[str, ...] = ()
    loss_rows: tuple[str, ...] = ()
    witness_rows: tuple[str, ...] = ()
    mcv_rows: tuple[str, ...] = ()
    polarity_rows: tuple[str, ...] = ()
    provenance_rows: tuple[str, ...] = ()
    successor_rows: tuple[tuple[str, str, bool], ...] = ()
    problems: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.outside_footprint_preserved and not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "passed": self.passed,
            "outside_footprint_preserved": self.outside_footprint_preserved,
            "footprint": list(self.footprint),
            "loss_rows": list(self.loss_rows),
            "witness_rows": list(self.witness_rows),
            "mcv_rows": list(self.mcv_rows),
            "polarity_rows": list(self.polarity_rows),
            "provenance_rows": list(self.provenance_rows),
            "successor_rows": [
                {"source": source, "successor": successor, "preserved": preserved}
                for source, successor, preserved in self.successor_rows
            ],
            "problems": list(self.problems),
        }


@dataclass(frozen=True)
class RECHCertificate:
    rech: RECH
    incidence: tuple[tuple[str, tuple[str, ...], str], ...]
    typed_nodes: tuple[RECHNode, ...] = ()
    typed_arcs: tuple[RECHArc, ...] = ()
    preservation_problems: tuple[str, ...] = ()
    provenance_paths: tuple[tuple[str, str], ...] = ()
    retention_paths: tuple[tuple[str, str], ...] = ()
    discharge_paths: tuple[tuple[str, str], ...] = ()
    successor_preservation: tuple[tuple[str, str, bool], ...] = ()
    clause_results: tuple[RECHClauseResult, ...] = ()
    preservation_witnesses: tuple[dict[str, object], ...] = ()
    store_preservation: StorePreservationCertificate | None = None
    mode_separation: dict[str, tuple[str, ...]] | None = None
    store_transformation_audit: dict[str, object] | None = None

    @property
    def ok(self) -> bool:
        return not self.preservation_problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "rech": self.rech.to_dict(),
            "incidence": [
                {"kind": kind, "sources": list(sources), "target": target}
                for kind, sources, target in self.incidence
            ],
            "typed_nodes": [node.to_dict() for node in self.typed_nodes],
            "typed_arcs": [arc.to_dict() for arc in self.typed_arcs],
            "preservation_problems": list(self.preservation_problems),
            "provenance_paths": [
                {"atom": atom, "path": path} for atom, path in self.provenance_paths
            ],
            "retention_paths": [
                {"row": row_id, "path": path} for row_id, path in self.retention_paths
            ],
            "discharge_paths": [
                {"row": row_id, "path": path} for row_id, path in self.discharge_paths
            ],
            "successor_preservation": [
                {"source": source, "successor": successor, "preserved": preserved}
                for source, successor, preserved in self.successor_preservation
            ],
            "clause_results": [result.to_dict() for result in self.clause_results],
            "preservation_witnesses": list(self.preservation_witnesses),
            "store_preservation": self.store_preservation.to_dict()
            if self.store_preservation
            else None,
            "mode_separation": {
                mode: list(items) for mode, items in sorted((self.mode_separation or {}).items())
            },
            "store_transformation_audit": dict(self.store_transformation_audit or {}),
        }


def build_rech(
    store_or_spec: ClosureStore | ExecutableBandSpec, record: str | FiniteRecord | None = None
) -> RECH:
    """Build the external incidence presentation of a closure store."""

    if isinstance(store_or_spec, ClosureStore):
        store = store_or_spec
    else:
        if record is None:
            raise TypeError("record is required when building RECH from a spec")
        store = close_store(as_exec_spec(store_or_spec), record)

    nodes: set[str] = {store.record_id}
    arcs: list[tuple[str, tuple[str, ...], str]] = []
    for row in store.all_rows:
        row_node = f"row:{row.rid}"
        sem_node = f"sem:{row.sem}"
        kind_node = f"kind:{row.kind}"
        verdict_node = f"verdict:{row.verdict}:{row.rid}"
        retention_node = f"retention:{row.retention}:{row.rid}"
        nodes.update({row_node, sem_node, kind_node, verdict_node, retention_node})
        arcs.append(("semantic", (row_node,), sem_node))
        arcs.append(("row-kind", (row_node,), kind_node))
        arcs.append(("verdict", (row_node,), verdict_node))
        arcs.append(("retention", (row_node,), retention_node))
        arcs.append(("generated-by-record", (store.record_id,), row_node))
        for ref in row.refs:
            ref_node = f"row:{ref}"
            nodes.add(ref_node)
            arcs.append(("reference", (row_node,), ref_node))
        for atom in row.atoms():
            atom_node = f"atom:{atom.mode}:{atom.name}"
            mode_node = f"mode:{atom.mode}"
            nodes.update({atom_node, mode_node})
            arcs.append((f"evidence:{atom.mode}", (row_node,), atom_node))
            arcs.append(("mode-incidence", (atom_node,), mode_node))
            if atom.origin:
                origin_node = f"origin:{atom.origin}"
                nodes.add(origin_node)
                arcs.append(("provenance-origin", (atom_node,), origin_node))
            for index, prov in enumerate(atom.prov):
                prov_node = f"prov:{index}:{prov}"
                nodes.add(prov_node)
                arcs.append(("provenance-path", (atom_node,), prov_node))

    return RECH(nodes=frozenset(nodes), hyperarcs=tuple(sorted(arcs)))


def store_preservation_certificate(
    store: ClosureStore, footprint: tuple[str, ...] = ()
) -> StorePreservationCertificate:
    footprint_set = set(footprint)
    row_ids = set(store.by_id())
    successor_rows: list[tuple[str, str, bool]] = []
    problems: list[str] = []
    loss_rows: list[str] = []
    witness_rows: list[str] = []
    mcv_rows: list[str] = []
    polarity_rows: list[str] = []
    provenance_rows: list[str] = []
    for row in store.all_rows:
        if row.payload.get("loss") or row.kind == "failure":
            loss_rows.append(row.rid)
        if row.kind == "witness" or row.payload.get("witness"):
            witness_rows.append(row.rid)
        if row.payload.get("mcv") or row.kind in {"mcv", "kernel"}:
            mcv_rows.append(row.rid)
        if row.payload.get("polarity") or any(atom.mode == "diag" for atom in row.atoms()):
            polarity_rows.append(row.rid)
        if row.payload.get("source") or any(atom.origin or atom.prov for atom in row.atoms()):
            provenance_rows.append(row.rid)
        successor = row.payload.get("successor")
        if successor is not None:
            preserved = str(successor) in row_ids
            successor_rows.append((row.rid, str(successor), preserved))
            if not preserved:
                problems.append(f"{row.rid}: successor {successor} missing")
        if footprint_set and row.rid not in footprint_set and row.retention in {"deleted"}:
            problems.append(f"{row.rid}: outside-footprint row not preserved")
    return StorePreservationCertificate(
        record_id=store.record_id,
        outside_footprint_preserved=not any("outside-footprint" in item for item in problems),
        footprint=tuple(sorted(footprint_set)),
        loss_rows=tuple(sorted(loss_rows)),
        witness_rows=tuple(sorted(witness_rows)),
        mcv_rows=tuple(sorted(mcv_rows)),
        polarity_rows=tuple(sorted(polarity_rows)),
        provenance_rows=tuple(sorted(provenance_rows)),
        successor_rows=tuple(sorted(successor_rows)),
        problems=tuple(sorted(problems)),
    )


def _clause_result(
    clause: str, problems: list[str], witnesses: list[str] | None = None
) -> RECHClauseResult:
    return RECHClauseResult(
        clause=clause,
        passed=not problems,
        witnesses=tuple(sorted(witnesses or ())),
        problems=tuple(sorted(problems)),
    )


def _rech_clause_results(
    store: ClosureStore, spec: ExecutableBandSpec | None = None
) -> tuple[RECHClauseResult, ...]:
    row_ids = [row.rid for row in store.all_rows]
    row_id_set = set(row_ids)
    schema_kinds = (
        set(spec.row_schemas) if spec is not None else {row.kind for row in store.all_rows}
    )
    by_id = store.by_id()
    clauses: list[RECHClauseResult] = []

    unique_problems = [rid for rid in sorted(row_id_set) if row_ids.count(rid) > 1]
    typed_ref_problems = [
        f"{row.rid}->{ref}" for row in store.all_rows for ref in row.refs if ref not in row_id_set
    ]
    clauses.append(
        _clause_result(
            "RCH01.unique-row-ids-and-typed-references",
            [*unique_problems, *typed_ref_problems],
            row_ids,
        )
    )

    sem_problems = [row.rid for row in store.all_rows if not row.sem or row.sem == row.rid == ""]
    clauses.append(
        _clause_result(
            "RCH02.semantic-effect-ids-preserved",
            sem_problems,
            [f"{row.rid}:{row.sem}" for row in store.all_rows],
        )
    )

    schema_problems = [row.rid for row in store.all_rows if row.kind not in schema_kinds]
    clauses.append(
        _clause_result("RCH03.declared-row-kind-schema", schema_problems, list(schema_kinds))
    )

    verdicts = {"pass", "fail", "inconclusive"}
    retentions = {"active", "retained", "discharged", "boundary", "deleted"}
    carrier_problems = [
        row.rid
        for row in store.all_rows
        if row.verdict not in verdicts or row.retention not in retentions
    ]
    clauses.append(
        _clause_result(
            "RCH04.single-verdict-and-retention-state",
            carrier_problems,
            [f"{row.rid}:{row.verdict}:{row.retention}" for row in store.all_rows],
        )
    )

    provenance_problems = [
        row.rid
        for row in store.all_rows
        if (
            row.retention in {"retained", "boundary"}
            or row.kind == "failure"
            or any(atom.mode == "diag" for atom in row.atoms())
        )
        and not (
            row.refs
            or row.payload.get("source")
            or any(atom.origin or atom.prov for atom in row.atoms())
        )
    ]
    clauses.append(
        _clause_result("RCH05.retained-failure-boundary-provenance", provenance_problems)
    )

    snapshot_problems = [
        row.rid
        for row in store.all_rows
        if row.kind == "witness"
        for ref in row.refs
        if by_id.get(ref) is not None
        and by_id[ref].kind == "snapshot"
        and not by_id[ref].payload.get("frozen", True)
    ]
    clauses.append(_clause_result("RCH06.snapshot-before-witness-read", snapshot_problems))

    separation_problems = [
        row.rid
        for row in store.all_rows
        if any(atom.mode == "diag" for atom in row.atoms())
        and any(atom.mode == "floor" for atom in row.atoms())
        and not row.payload.get("retyped", False)
    ]
    clauses.append(_clause_result("RCH07.floor-diagnostic-separation", separation_problems))

    kernel_problems = [
        row.rid
        for row in store.all_rows
        if (row.kind == "kernel" or row.payload.get("kernel", False))
        for ref in row.refs
        if by_id.get(ref) is not None
        and not any(atom.mode == "floor" for atom in by_id[ref].atoms())
    ]
    clauses.append(_clause_result("RCH08.kernel-reads-floor-witness-paths", kernel_problems))

    lower_bound_problems = [
        row.rid
        for row in store.all_rows
        if (
            row.retention in {"discharged", "deleted"}
            and any(atom.mode == "diag" and atom.name.startswith("lb") for atom in row.atoms())
            and str(row.payload.get("successor", "")) not in row_id_set
        )
    ]
    clauses.append(_clause_result("RCH09.lower-bound-successor-preservation", lower_bound_problems))
    return tuple(clauses)


def build_rech_certificate(
    store_or_spec: ClosureStore | ExecutableBandSpec, record: str | FiniteRecord | None = None
) -> RECHCertificate:
    if isinstance(store_or_spec, ClosureStore):
        store = store_or_spec
        spec: ExecutableBandSpec | None = None
    else:
        if record is None:
            raise TypeError("record is required when building RECH from a spec")
        spec = as_exec_spec(store_or_spec)
        store = close_store(spec, record)
    rech = build_rech(store)
    ok, problems = well_formed_rech(store)
    provenance_paths: list[tuple[str, str]] = []
    retention_paths: list[tuple[str, str]] = []
    discharge_paths: list[tuple[str, str]] = []
    mode_separation: dict[str, set[str]] = {}
    successor_preservation: list[tuple[str, str, bool]] = []
    preservation_witnesses: list[dict[str, object]] = []
    for row in store.all_rows:
        if row.retention in {"retained", "boundary"}:
            retention_paths.append((row.rid, str(row.payload.get("source", row.rid))))
        if row.retention == "discharged":
            discharge_paths.append((row.rid, str(row.payload.get("source", row.rid))))
        successor = row.payload.get("successor")
        if successor is not None:
            successor_preservation.append(
                (row.rid, str(successor), str(successor) in store.by_id())
            )
            preservation_witnesses.append(
                {
                    "row": row.rid,
                    "successor": str(successor),
                    "preserved": str(successor) in store.by_id(),
                }
            )
        for atom in row.atoms():
            atom_id = f"atom:{atom.mode}:{atom.name}"
            path = "->".join(atom.prov or ((atom.origin or row.rid),))
            provenance_paths.append((atom_id, path))
            mode_separation.setdefault(atom.mode, set()).add(atom_id)
    return RECHCertificate(
        rech=rech,
        incidence=rech.hyperarcs,
        typed_nodes=tuple(
            sorted((RECHNode.from_label(node) for node in rech.nodes), key=lambda n: n.node_id)
        ),
        typed_arcs=tuple(
            RECHArc(kind, sources, target) for kind, sources, target in rech.hyperarcs
        ),
        preservation_problems=() if ok else problems,
        provenance_paths=tuple(sorted(provenance_paths)),
        retention_paths=tuple(sorted(retention_paths)),
        discharge_paths=tuple(sorted(discharge_paths)),
        successor_preservation=tuple(sorted(successor_preservation)),
        clause_results=_rech_clause_results(store, spec),
        preservation_witnesses=tuple(preservation_witnesses),
        store_preservation=store_preservation_certificate(store),
        mode_separation={mode: tuple(sorted(items)) for mode, items in mode_separation.items()},
        store_transformation_audit={
            "record_id": store.record_id,
            "rows": len(store.rows),
            "failures": len(store.failures),
            "dangling_references": [
                problem for problem in problems if "dangling reference" in problem
            ],
        },
    )


def well_formed_rech(store: ClosureStore) -> tuple[bool, tuple[str, ...]]:
    problems: list[str] = []
    seen: set[str] = set()
    row_ids = {row.rid for row in store.all_rows}
    for row in store.all_rows:
        if row.rid in seen:
            problems.append(f"duplicate row id {row.rid}")
        seen.add(row.rid)
        if not row.sem:
            problems.append(f"{row.rid}: missing semantic id")
        if row.verdict not in {"pass", "fail", "inconclusive"}:
            problems.append(f"{row.rid}: invalid verdict {row.verdict}")
        if not row.retention:
            problems.append(f"{row.rid}: missing retention state")
        for ref in row.refs:
            if ref not in row_ids:
                problems.append(f"{row.rid}: dangling reference {ref}")
        if row.retention in {"retained", "boundary"} and not (
            row.refs or row.payload.get("source")
        ):
            problems.append(f"{row.rid}: retained row lacks provenance")
    return not problems, tuple(problems)
