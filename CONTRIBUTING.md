# Contributing

This repository is a finite executable reference implementation of Constraint
Bandwidth Dynamics in CGT. Contributions should preserve three properties:

- theory conformance on finite `AuditUniv` instances;
- portable, pure-data semantics suitable for other language implementations;
- runtime safety with no arbitrary code execution from specs.

## Development

Use `uv`:

```powershell
uv sync --all-extras --dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy src/cgt_bandwidth
uv run pytest --cov=cgt_bandwidth --cov-report=term-missing --cov-fail-under=90
```

Do not commit generated caches, virtual environments, local logs, or build
artifacts.

## API Stability

The project is `0.x` alpha. Public imports from `cgt_bandwidth` and
`cgt_bandwidth.core` should remain backward compatible where practical. New
theory-facing behavior should be additive unless an existing behavior is
demonstrably unsound against the finite executable semantics.

## Theory Changes

When changing closure, evidence, support, completion, or release semantics,
include tests that identify the corresponding paper definition, proposition, or
audit criterion. Prefer certificate-shaped outputs over opaque strings.
Strict conformance paths should reject implicit or heuristic inputs rather than
silently accepting them as theorem-aligned evidence.
