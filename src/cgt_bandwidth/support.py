"""Support antichains and exact finite support enumeration."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Any

from .bandwidth import bandwidth_observable
from .closure import close_store
from .core import ExecutableBandSpec, ReadCoord, ReportLens, as_exec_spec, freeze_value, thaw_value

SupportAntichain = tuple[frozenset[str], ...]


@dataclass(frozen=True)
class SepCoord:
    """A typed coordinate that separates at least one report fiber."""

    label: str

    def __post_init__(self) -> None:
        coord = ReadCoord.from_obj(self.label)
        object.__setattr__(self, "label", coord.label)

    def to_dict(self) -> dict[str, object]:
        return ReadCoord.from_obj(self.label).to_dict()


@dataclass(frozen=True)
class SuppSig:
    """Support signature for one record over a support antichain."""

    record_id: str
    exact: bool
    entries: tuple[tuple[tuple[str, ...], Any], ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "exact": self.exact,
            "entries": [
                {"support": list(edge), "value": thaw_value(freeze_value(value))}
                for edge, value in self.entries
            ],
        }


@dataclass(frozen=True)
class SupportExact:
    """Audit certificate comparing product support with exact joint support."""

    product: SupportAntichain
    exact: SupportAntichain
    exact_match: bool
    coordinate_universe: tuple[str, ...]
    product_only: SupportAntichain = ()
    exact_only: SupportAntichain = ()
    separating_pairs: tuple[tuple[str, str], ...] = ()
    pairwise_witnesses: tuple[dict[str, object], ...] = ()
    minimality_witnesses: tuple[dict[str, object], ...] = ()
    failed_pairs: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "exact_match": self.exact_match,
            "coordinate_universe": list(self.coordinate_universe),
            "product": [sorted(edge) for edge in self.product],
            "exact": [sorted(edge) for edge in self.exact],
            "product_only": [sorted(edge) for edge in self.product_only],
            "exact_only": [sorted(edge) for edge in self.exact_only],
            "separating_pairs": [list(pair) for pair in self.separating_pairs],
            "pairwise_witnesses": list(self.pairwise_witnesses),
            "minimality_witnesses": list(self.minimality_witnesses),
            "failed_pairs": [list(pair) for pair in self.failed_pairs],
        }


@dataclass(frozen=True)
class SupportCheckerResult:
    support: frozenset[str]
    coordinate: str
    accepted: bool
    failed_pairs: tuple[tuple[str, str], ...] = ()
    witness_pairs: tuple[tuple[str, str], ...] = ()
    minimality_witness: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "support": sorted(self.support),
            "coordinate": self.coordinate,
            "accepted": self.accepted,
            "failed_pairs": [list(pair) for pair in self.failed_pairs],
            "witness_pairs": [list(pair) for pair in self.witness_pairs],
            "minimality_witness": list(self.minimality_witness),
        }


@dataclass(frozen=True)
class SupportTableCertificate:
    coordinate_universe: tuple[str, ...]
    results: tuple[SupportCheckerResult, ...]
    bound_fallback: bool = False
    fallback_coordinates: tuple[str, ...] = ()
    fallback_reasons: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return all(result.accepted for result in self.results)

    def to_dict(self) -> dict[str, object]:
        return {
            "coordinate_universe": list(self.coordinate_universe),
            "passed": self.passed,
            "results": [result.to_dict() for result in self.results],
            "bound_fallback": self.bound_fallback,
            "fallback_coordinates": list(self.fallback_coordinates),
            "fallback_reasons": list(self.fallback_reasons),
        }


@dataclass(frozen=True)
class SupportProductCertificate:
    product: SupportAntichain
    coordinate_universe: tuple[str, ...]
    bound_fallback: bool = False
    fallback_coordinates: tuple[str, ...] = ()
    fallback_reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "product": [sorted(edge) for edge in self.product],
            "coordinate_universe": list(self.coordinate_universe),
            "bound_fallback": self.bound_fallback,
            "fallback_coordinates": list(self.fallback_coordinates),
            "fallback_reasons": list(self.fallback_reasons),
        }


@dataclass(frozen=True)
class ReadCoordUniverseCertificate:
    lens: str
    effective_coordinates: tuple[str, ...]
    declared_coordinates: tuple[str, ...] = ()
    inferred_row_coordinates: tuple[str, ...] = ()
    inferred_atom_coordinates: tuple[str, ...] = ()
    release_footprint_coordinates: tuple[str, ...] = ()
    band_row_coordinates: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "lens": self.lens,
            "effective_coordinates": list(self.effective_coordinates),
            "declared_coordinates": list(self.declared_coordinates),
            "inferred_row_coordinates": list(self.inferred_row_coordinates),
            "inferred_atom_coordinates": list(self.inferred_atom_coordinates),
            "release_footprint_coordinates": list(self.release_footprint_coordinates),
            "band_row_coordinates": list(self.band_row_coordinates),
        }


def min_supp(sets: set[frozenset[str]]) -> SupportAntichain:
    minimal = set(sets)
    for left in sets:
        for right in sets:
            if left != right and left > right and left in minimal:
                minimal.remove(left)
    return tuple(sorted(minimal, key=lambda item: (len(item), sorted(item))))


def read_coordinate_universe(spec: ExecutableBandSpec, lens: ReportLens) -> tuple[str, ...]:
    exec_spec = as_exec_spec(spec)
    if exec_spec.read_coordinates:
        return exec_spec.read_coordinates
    coords: set[str] = set(exec_spec.read_coordinates)
    for record in exec_spec.audit_universe:
        store = close_store(exec_spec, record)
        coords.update(
            ReadCoord("row", row.rid, row_kind=row.kind, sem=row.sem).label
            for row in store.all_rows
        )
        for row in store.all_rows:
            coords.update(
                ReadCoord("atom", atom.name, mode=atom.mode).label for atom in row.atoms()
            )
    return tuple(sorted(coords))


def read_coordinate_universe_certificate(
    spec: ExecutableBandSpec, lens: ReportLens
) -> ReadCoordUniverseCertificate:
    exec_spec = as_exec_spec(spec)
    row_coords: set[str] = set()
    atom_coords: set[str] = set()
    for record in exec_spec.audit_universe:
        store = close_store(exec_spec, record)
        row_coords.update(
            ReadCoord("row", row.rid, row_kind=row.kind, sem=row.sem).label
            for row in store.all_rows
        )
        atom_coords.update(
            ReadCoord("atom", atom.name, mode=atom.mode).label
            for row in store.all_rows
            for atom in row.atoms()
        )
    release_coords = {
        ReadCoord("row", coord).label for cert in exec_spec.releases for coord in cert.footprint
    }
    band_coords = {ReadCoord("row", coord).label for coord in exec_spec.band_rows}
    return ReadCoordUniverseCertificate(
        lens=lens.name,
        effective_coordinates=read_coordinate_universe(exec_spec, lens),
        declared_coordinates=exec_spec.read_coordinates,
        inferred_row_coordinates=tuple(sorted(row_coords)),
        inferred_atom_coordinates=tuple(sorted(atom_coords)),
        release_footprint_coordinates=tuple(sorted(release_coords)),
        band_row_coordinates=tuple(sorted(band_coords)),
    )


def _restriction(spec: ExecutableBandSpec, record_id: str, coords: frozenset[str]) -> Any:
    record = spec.record(record_id)
    store = close_store(spec, record)
    row_map = store.by_id()
    atom_keys = {atom.key for atom in store.atoms()}
    row_reading = {}
    atom_reading = {}
    for label in coords:
        coord = ReadCoord.from_obj(label)
        if coord.kind == "row":
            row = row_map.get(coord.id)
            row_reading[coord.label] = row.congruence_key() if row else None
        else:
            atom_reading[coord.label] = (coord.mode, coord.id) in atom_keys
    return freeze_value({"rows": row_reading, "atoms": atom_reading})


def _restriction_table(spec: ExecutableBandSpec, lens: ReportLens) -> dict[str, dict[str, Any]]:
    coords = read_coordinate_universe(spec, lens)
    table: dict[str, dict[str, Any]] = {}
    for record in spec.audit_universe:
        store = close_store(spec, record)
        row_map = store.by_id()
        values: dict[str, Any] = {}
        atom_keys = {atom.key for atom in store.atoms()}
        for label in coords:
            coord = ReadCoord.from_obj(label)
            if coord.kind == "row":
                row = row_map.get(coord.id)
                values[label] = row.congruence_key() if row else None
            else:
                values[label] = (coord.mode, coord.id) in atom_keys
        table[record.id] = values
    return table


def _restriction_from_table(
    table: dict[str, dict[str, Any]], record_id: str, coords: frozenset[str]
) -> Any:
    return tuple((coord, table[record_id].get(coord)) for coord in sorted(coords))


def _computes_observable(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    coords: frozenset[str],
    observables: dict[str, Any] | None = None,
    table: dict[str, dict[str, Any]] | None = None,
    strict_release: bool = True,
) -> bool:
    records = spec.audit_universe
    observables = observables or {
        record.id: bandwidth_observable(spec, lens, record, strict_release=strict_release).key()
        for record in records
    }
    table = table or _restriction_table(spec, lens)
    for left in records:
        for right in records:
            if lens.read(left) != lens.read(right):
                continue
            if _restriction_from_table(table, left.id, coords) == _restriction_from_table(
                table, right.id, coords
            ):
                if observables[left.id] != observables[right.id]:
                    return False
    return True


def _observable_coordinates(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> dict[str, dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    for record in spec.audit_universe:
        observable = bandwidth_observable(
            spec, lens, record, strict_release=strict_release
        ).to_dict()
        flat = {
            "base": observable["base"],
            "release_closure": observable["release_closure"],
            "action_signature": observable["action_signature"],
        }
        base = observable.get("base", {})
        if isinstance(base, dict):
            for key, value in base.items():
                flat[f"base.{key}"] = value
        values[record.id] = {key: freeze_value(value) for key, value in flat.items()}
    return values


def _supports_coordinate(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    coords: frozenset[str],
    coordinate: str,
    values: dict[str, dict[str, Any]],
    table: dict[str, dict[str, Any]],
) -> bool:
    records = spec.audit_universe
    for left in records:
        for right in records:
            if lens.read(left) != lens.read(right):
                continue
            if _restriction_from_table(table, left.id, coords) == _restriction_from_table(
                table, right.id, coords
            ):
                if values[left.id][coordinate] != values[right.id][coordinate]:
                    return False
    return True


def support_checker_result(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    coords: frozenset[str],
    coordinate: str,
    *,
    strict_release: bool = True,
) -> SupportCheckerResult:
    exec_spec = as_exec_spec(spec)
    values = _observable_coordinates(exec_spec, lens, strict_release=strict_release)
    table = _restriction_table(exec_spec, lens)
    failed_pairs: list[tuple[str, str]] = []
    witness_pairs: list[tuple[str, str]] = []
    records = exec_spec.audit_universe
    for left in records:
        for right in records:
            if left.id >= right.id or lens.read(left) != lens.read(right):
                continue
            same_support = _restriction_from_table(
                table, left.id, coords
            ) == _restriction_from_table(table, right.id, coords)
            different_coordinate = values[left.id][coordinate] != values[right.id][coordinate]
            if same_support and different_coordinate:
                failed_pairs.append((left.id, right.id))
            if not same_support and different_coordinate:
                witness_pairs.append((left.id, right.id))
    minimality_witness = tuple(
        sorted(
            coord
            for coord in coords
            if not _supports_coordinate(
                exec_spec,
                lens,
                frozenset(item for item in coords if item != coord),
                coordinate,
                values,
                table,
            )
        )
    )
    return SupportCheckerResult(
        support=coords,
        coordinate=coordinate,
        accepted=not failed_pairs,
        failed_pairs=tuple(failed_pairs),
        witness_pairs=tuple(witness_pairs),
        minimality_witness=minimality_witness,
    )


def _minimal_supports_for_coordinate(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    coordinate: str,
    values: dict[str, dict[str, Any]],
    table: dict[str, dict[str, Any]],
) -> tuple[SupportAntichain, tuple[str, ...]]:
    coords = read_coordinate_universe(spec, lens)
    if len(coords) > spec.exact_support_limit:
        return (frozenset(coords),), (
            f"{coordinate}: coordinate universe size {len(coords)} exceeds "
            f"exact_support_limit {spec.exact_support_limit}; using full-coordinate "
            "sound fallback",
        )
    found: set[frozenset[str]] = set()
    for size in range(len(coords) + 1):
        for combo in combinations(coords, size):
            candidate = frozenset(combo)
            if any(existing <= candidate for existing in found):
                continue
            if _supports_coordinate(spec, lens, candidate, coordinate, values, table):
                found.add(candidate)
    return min_supp(found), ()


def exact_support_enum(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> SupportAntichain:
    exec_spec = as_exec_spec(spec)
    coords = read_coordinate_universe(exec_spec, lens)
    if len(coords) > exec_spec.exact_support_limit:
        raise ValueError(
            f"exact support enumeration would inspect 2^{len(coords)} subsets; "
            f"limit is {exec_spec.exact_support_limit}"
        )
    computing: set[frozenset[str]] = set()
    observables = {
        record.id: bandwidth_observable(
            exec_spec, lens, record, strict_release=strict_release
        ).key()
        for record in exec_spec.audit_universe
    }
    table = _restriction_table(exec_spec, lens)
    for size in range(len(coords) + 1):
        for combo in combinations(coords, size):
            candidate = frozenset(combo)
            if any(existing <= candidate for existing in computing):
                continue
            if _computes_observable(
                exec_spec,
                lens,
                candidate,
                observables,
                table,
                strict_release=strict_release,
            ):
                computing.add(candidate)
    return min_supp(computing)


def _support_product_with_fallback(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> tuple[SupportAntichain, tuple[str, ...]]:
    exec_spec = as_exec_spec(spec)
    values = _observable_coordinates(exec_spec, lens, strict_release=strict_release)
    table = _restriction_table(exec_spec, lens)
    coordinates = sorted(next(iter(values.values())).keys()) if values else []
    family: SupportAntichain = (frozenset(),)
    fallback_reasons: list[str] = []
    for coordinate in coordinates:
        coord_supports, reasons = _minimal_supports_for_coordinate(
            exec_spec, lens, coordinate, values, table
        )
        fallback_reasons.extend(reasons)
        unions = {left | right for left in family for right in coord_supports}
        family = min_supp(unions)
    return family, tuple(fallback_reasons)


def support_product(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> SupportAntichain:
    family, _fallback_reasons = _support_product_with_fallback(
        spec, lens, strict_release=strict_release
    )
    return family


def support_product_certificate(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> SupportProductCertificate:
    exec_spec = as_exec_spec(spec)
    product, fallback_reasons = _support_product_with_fallback(
        exec_spec, lens, strict_release=strict_release
    )
    return SupportProductCertificate(
        product=product,
        coordinate_universe=read_coordinate_universe(exec_spec, lens),
        bound_fallback=bool(fallback_reasons),
        fallback_coordinates=tuple(sorted({coord for edge in product for coord in edge}))
        if fallback_reasons
        else (),
        fallback_reasons=fallback_reasons,
    )


def support_exact(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> bool:
    return set(support_product(spec, lens, strict_release=strict_release)) == set(
        exact_support_enum(spec, lens, strict_release=strict_release)
    )


def support_exact_certificate(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> SupportExact:
    exec_spec = as_exec_spec(spec)
    product = support_product(exec_spec, lens, strict_release=strict_release)
    exact = exact_support_enum(exec_spec, lens, strict_release=strict_release)
    product_set = set(product)
    exact_set = set(exact)
    observables = {
        record.id: bandwidth_observable(
            exec_spec, lens, record, strict_release=strict_release
        ).key()
        for record in exec_spec.audit_universe
    }
    separating_pairs: set[tuple[str, str]] = set()
    pairwise_witnesses: list[dict[str, object]] = []
    for left in exec_spec.audit_universe:
        for right in exec_spec.audit_universe:
            if left.id >= right.id or lens.read(left) != lens.read(right):
                continue
            if observables[left.id] != observables[right.id]:
                separating_pairs.add((left.id, right.id))
                pairwise_witnesses.append(
                    {
                        "left": left.id,
                        "right": right.id,
                        "same_report": True,
                        "observable_differs": True,
                    }
                )
    observable_coords = _observable_coordinates(exec_spec, lens, strict_release=strict_release)
    minimality_witnesses: list[dict[str, object]] = []
    failed_pairs: set[tuple[str, str]] = set()
    for edge in exact:
        for coordinate in sorted(next(iter(observable_coords.values())).keys()):
            result = support_checker_result(
                exec_spec, lens, edge, coordinate, strict_release=strict_release
            )
            failed_pairs.update(result.failed_pairs)
            if result.minimality_witness:
                minimality_witnesses.append(
                    {
                        "support": sorted(edge),
                        "coordinate": coordinate,
                        "essential_coordinates": list(result.minimality_witness),
                    }
                )
    return SupportExact(
        product=product,
        exact=exact,
        exact_match=product_set == exact_set,
        coordinate_universe=read_coordinate_universe(exec_spec, lens),
        product_only=tuple(
            sorted(product_set - exact_set, key=lambda item: (len(item), sorted(item)))
        ),
        exact_only=tuple(
            sorted(exact_set - product_set, key=lambda item: (len(item), sorted(item)))
        ),
        separating_pairs=tuple(sorted(separating_pairs)),
        pairwise_witnesses=tuple(pairwise_witnesses),
        minimality_witnesses=tuple(minimality_witnesses),
        failed_pairs=tuple(sorted(failed_pairs)),
    )


def support_table_certificate(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    *,
    exact: bool = False,
    strict_release: bool = True,
) -> SupportTableCertificate:
    exec_spec = as_exec_spec(spec)
    fallback_reasons: tuple[str, ...] = ()
    if exact:
        supports = exact_support_enum(exec_spec, lens, strict_release=strict_release)
    else:
        supports, fallback_reasons = _support_product_with_fallback(
            exec_spec, lens, strict_release=strict_release
        )
    values = _observable_coordinates(exec_spec, lens, strict_release=strict_release)
    coordinates = tuple(sorted(next(iter(values.values())).keys())) if values else ()
    results = tuple(
        support_checker_result(exec_spec, lens, support, coordinate, strict_release=strict_release)
        for support in supports
        for coordinate in coordinates
    )
    return SupportTableCertificate(
        coordinate_universe=read_coordinate_universe(exec_spec, lens),
        results=results,
        bound_fallback=bool(fallback_reasons),
        fallback_coordinates=tuple(sorted({coord for edge in supports for coord in edge}))
        if fallback_reasons
        else (),
        fallback_reasons=fallback_reasons,
    )


def support_signature(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    record_id: str,
    exact: bool = False,
    *,
    strict_release: bool = True,
) -> Any:
    family = (
        exact_support_enum(spec, lens, strict_release=strict_release)
        if exact
        else support_product(spec, lens, strict_release=strict_release)
    )
    return tuple(
        (tuple(sorted(edge)), thaw_value(_restriction(spec, record_id, edge))) for edge in family
    )


def support_signature_certificate(
    spec: ExecutableBandSpec,
    lens: ReportLens,
    record_id: str,
    exact: bool = False,
    *,
    strict_release: bool = True,
) -> SuppSig:
    entries = tuple(
        (tuple(edge), freeze_value(value))
        for edge, value in support_signature(
            spec, lens, record_id, exact=exact, strict_release=strict_release
        )
    )
    return SuppSig(record_id=str(record_id), exact=exact, entries=entries)


def separation_coordinates(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> tuple[str, ...]:
    exec_spec = as_exec_spec(spec)
    exact = exact_support_enum(exec_spec, lens, strict_release=strict_release)
    coords: set[str] = set()
    for edge in exact:
        for coord in edge:
            reduced_edges = {
                frozenset(item for item in candidate if item != coord) for candidate in exact
            }
            observables = {
                record.id: bandwidth_observable(
                    exec_spec, lens, record, strict_release=strict_release
                ).key()
                for record in exec_spec.audit_universe
            }
            table = _restriction_table(exec_spec, lens)
            if not all(
                _computes_observable(
                    exec_spec,
                    lens,
                    reduced,
                    observables,
                    table,
                    strict_release=strict_release,
                )
                for reduced in reduced_edges
            ):
                coords.add(coord)
    return tuple(sorted(coords))


def separation_coordinate_objects(
    spec: ExecutableBandSpec, lens: ReportLens, *, strict_release: bool = True
) -> tuple[SepCoord, ...]:
    return tuple(
        SepCoord(label)
        for label in separation_coordinates(spec, lens, strict_release=strict_release)
    )
