# Security And Publication Notes

This package is designed for public OSS distribution.

- No spec field is evaluated as Python code.
- JSON loading uses `json.loads`.
- YAML loading is optional and uses `yaml.safe_load`.
- CLI commands read only the explicit paths passed by the caller.
- Release certificates are data objects; they do not delete files or mutate repositories.
- Store-step rules are finite data declarations. They do not import modules,
  evaluate expressions, or call user-provided Python callbacks.
- Strict component evaluators are lookup/table readers or finite graph readers;
  they do not execute user code.
- Exact support enumeration is capped by `exact_support_limit` because it is exponential.
- `work_bounds` caps closure, support, release, and quotient work; oversized exact audits should be rejected by configuration rather than allowed to exhaust local resources.
- `.gitignore` excludes virtual environments, caches, logs, build outputs, and common secret file patterns.
- `.venv` is treated as a local development artifact. `uv.lock` is tracked so CI and local strict checks resolve the same development toolchain.
- The package contains no NOTICE file by design.
- CI runs lint, format checks, type checks, coverage-gated tests at 94%,
  schema validation for official JSON outputs, CLI smoke tests, package build,
  metadata checks, publication audit, and artifact-content checks.
- Strict validation rejects defaulted release local-stability predicates,
  incomplete release footprint predicate tables, legacy bare read coordinates,
  implicit support coordinate universes, aggregate-only component evaluators, and
  heuristic retyping declarations.
- JSON Schema validation is used for published example specs, validate-report
  output, and audit-report output in CI.
- `schemas/strict-executable-band-spec.schema.json` documents the stricter
  portable package shape used by `validate --strict`; executable theory checks
  still happen in Python validation, not inside JSON Schema alone.
- `cgt-bw close --certificate` and strict-first `cgt-bw audit` emit data
  certificates only; they do not mutate inputs, files, repositories, or external
  systems.
- Strict release checking also rejects target rows outside the ambient row
  universe, missing proof-map entries, and missing checker traces before a
  release action is descended to completion classes.
- `scripts/publication_audit.py` scans text files for local absolute paths and
  secret-like tokens, rejects stale local artifacts when run without
  `--skip-worktree-artifacts`, and can scan built `dist/` archives for forbidden
  cache, virtualenv, coverage, build, and local-path entries.

For untrusted large specs, keep `exact_support_limit` low and prefer `support_product` over `exact_support_enum`.
