"""Command line interface for the finite CGT bandwidth reference."""

from __future__ import annotations

import argparse
import sys

from .bandwidth import bandwidth_observable
from .closure import close_store, close_store_with_certificate
from .completion import completion_certificate, completion_classes, completion_law_certificate
from .complexity import (
    greedy_release_cover,
    parse_release_cover_instance,
    solve_release_cover_exact,
)
from .core import MODES, ModeDecision
from .io import dump_json, load_data, load_spec, report_lens_from_name
from .microframe import build_microframe_spec, microframe_summary
from .release import release_action_certificate, release_graph
from .support import (
    exact_support_enum,
    separation_coordinates,
    support_exact,
    support_exact_certificate,
    support_product,
    support_product_certificate,
    support_signature,
    support_table_certificate,
)


def _cmd_validate(args: argparse.Namespace) -> int:
    spec = load_spec(args.spec)
    report = spec.validate_report(strict=args.strict)
    if args.report or args.strict:
        print(dump_json(report.to_dict()))
    else:
        print(dump_json({"ok": report.ok, "problems": list(report.problems)}))
    return 0 if report.ok else 1


def _cmd_normalize_strict(args: argparse.Namespace) -> int:
    data = load_data(args.spec)
    spec = load_spec(args.spec)
    data.setdefault("rules", [])
    data.setdefault("store_step_rules", [])
    data.setdefault("components", [])
    data.setdefault("release_check_table", {})
    data.setdefault("read_coordinates", list(spec.read_coordinates))
    data.setdefault("work_bounds", spec.work_bounds.__dict__)
    data.setdefault("audit_scope", {"whole_domain": spec.audit_scope.whole_domain})
    data["mode_matrix"] = {
        f"{left}->{right}": ModeDecision.from_obj(spec.mode_matrix[(left, right)]).to_dict()
        for left in MODES
        for right in MODES
    }
    print(dump_json(data))
    return 0


def _cmd_close(args: argparse.Namespace) -> int:
    spec = load_spec(args.spec)
    record = args.record
    if record not in spec.records:
        data = load_data(record)
        record_obj = spec.record(data["id"]) if data["id"] in spec.records else None
        if record_obj is None:
            from .core import FiniteRecord

            record_obj = FiniteRecord.from_obj(data)
        result = (
            close_store_with_certificate(spec, record_obj, strict=args.strict)
            if args.certificate
            else close_store(spec, record_obj)
        )
    else:
        result = (
            close_store_with_certificate(spec, record, strict=args.strict)
            if args.certificate
            else close_store(spec, record)
        )
    print(dump_json(result.to_dict()))
    return 0


def _cmd_audit(args: argparse.Namespace) -> int:
    spec = load_spec(args.spec)
    lens = report_lens_from_name(args.lens)
    strict_release = not args.compat_release
    records = {
        record.id: bandwidth_observable(spec, lens, record, strict_release=strict_release).to_dict()
        for record in spec.audit_universe
    }
    release_certificate = release_action_certificate(spec, lens, strict=strict_release)
    payload = {
        "schema_version": "cgt-bandwidth.audit.v1",
        "release_mode": "strict" if strict_release else "compatibility",
        "records": records,
        "completion": completion_classes(spec, lens, strict_release=strict_release).to_dict(),
        "completion_certificate": completion_certificate(
            spec, lens, strict_release=strict_release
        ).to_dict(),
        "completion_law_certificate": completion_law_certificate(
            spec, lens, strict_release=strict_release
        ).to_dict(),
        "support_product": [
            sorted(edge) for edge in support_product(spec, lens, strict_release=strict_release)
        ],
        "support_product_certificate": support_product_certificate(
            spec, lens, strict_release=strict_release
        ).to_dict(),
        "support_exact": support_exact(spec, lens, strict_release=strict_release)
        if args.exact_support
        else None,
        "separation_coordinates": separation_coordinates(spec, lens, strict_release=strict_release)
        if args.exact_support
        else None,
        "release_graph": release_graph(spec, strict=strict_release).to_dict(),
        "release_action": {
            str(k): [list(v) for v in vals] for k, vals in release_certificate.relation.items()
        },
        "release_action_certificate": release_certificate.to_dict(),
    }
    if args.exact_support:
        payload["exact_support"] = [
            sorted(edge) for edge in exact_support_enum(spec, lens, strict_release=strict_release)
        ]
        payload["support_exact_certificate"] = support_exact_certificate(
            spec, lens, strict_release=strict_release
        ).to_dict()
        payload["support_table_certificate"] = support_table_certificate(
            spec, lens, exact=True, strict_release=strict_release
        ).to_dict()
        payload["support_signatures"] = {
            record.id: support_signature(
                spec, lens, record.id, exact=True, strict_release=strict_release
            )
            for record in spec.audit_universe
        }
    print(dump_json(payload))
    return 0


def _cmd_microframe(args: argparse.Namespace) -> int:
    if args.micro_command == "run":
        print(dump_json(microframe_summary()))
        return 0
    if args.micro_command == "spec":
        spec = build_microframe_spec()
        print(
            dump_json(
                {"name": spec.name, "records": [record.to_dict() for record in spec.audit_universe]}
            )
        )
        return 0
    return 2


def _cmd_release_cover(args: argparse.Namespace) -> int:
    universe, sets, budget = parse_release_cover_instance(load_data(args.instance))
    if args.exact:
        ok, chosen = solve_release_cover_exact(universe, sets, budget)
    else:
        ok, chosen = greedy_release_cover(universe, sets, budget)
    print(dump_json({"covered": ok, "chosen": list(chosen), "budget": budget}))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cgt-bw")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="validate an executable band spec")
    validate.add_argument("spec")
    validate.add_argument("--strict", action="store_true")
    validate.add_argument("--report", action="store_true")
    validate.set_defaults(func=_cmd_validate)

    normalize = sub.add_parser("normalize-strict", help="emit a strict finite package shape")
    normalize.add_argument("spec")
    normalize.set_defaults(func=_cmd_normalize_strict)

    close = sub.add_parser("close", help="compute a bounded closure store")
    close.add_argument("spec")
    close.add_argument("record")
    close.add_argument("--certificate", action="store_true")
    close.add_argument("--strict", action="store_true")
    close.set_defaults(func=_cmd_close)

    audit = sub.add_parser("audit", help="compute the finite audit pipeline")
    audit.add_argument("spec")
    audit.add_argument("--lens", default="report")
    audit.add_argument("--exact-support", action="store_true")
    audit.add_argument(
        "--compat-release",
        action="store_true",
        help="use legacy compatibility release checks instead of strict release conformance",
    )
    audit.set_defaults(func=_cmd_audit)

    micro = sub.add_parser("microframe", help="run deterministic microframe utilities")
    micro_sub = micro.add_subparsers(dest="micro_command", required=True)
    micro_run = micro_sub.add_parser("run")
    micro_run.set_defaults(func=_cmd_microframe)
    micro_spec = micro_sub.add_parser("spec")
    micro_spec.set_defaults(func=_cmd_microframe)

    cover = sub.add_parser("release-cover", help="solve a pure release-cover instance")
    cover.add_argument("instance")
    group = cover.add_mutually_exclusive_group()
    group.add_argument("--exact", action="store_true")
    group.add_argument("--greedy", action="store_true")
    cover.set_defaults(func=_cmd_release_cover)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
