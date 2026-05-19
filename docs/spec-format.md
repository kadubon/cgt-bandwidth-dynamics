# Spec Format

Specs are JSON by default. YAML is accepted only when the optional `yaml` extra is installed.

The top-level object is an `ExecutableBandSpec` over a finite audit universe:

```json
{
  "name": "example",
  "frame": {
    "systems": ["H0"],
    "effect_dimensions": ["obs", "cmp", "release"]
  },
  "row_schemas": {
    "observation": {},
    "comparison": {},
    "witness": {},
    "release": {},
    "diagnostic": {}
  },
  "candidates": ["a", "b"],
  "cand_enum": {
    "a": {"id": "a", "semantic_class": "A", "rows": [], "evidence": []}
  },
  "candidate_semantics": {"a": "A", "b": "B"},
  "candidate_evidence": {
    "a": [{"mode": "avail", "name": "obs_1"}]
  },
  "stage_checks": {
    "a": {
      "presentable": {"required": [{"mode": "avail", "name": "obs_1"}]},
      "well_formed": {},
      "observable": {},
      "comparable": {},
      "available": {},
      "floor_safe": {},
      "release_safe": {},
      "selected": {}
    }
  },
  "records": [
    {
      "id": "H0",
      "report": "r",
      "rows": [
        {
          "rid": "o_1",
          "kind": "observation",
          "sem": "o_1",
          "payload": {
            "atoms": [{"mode": "avail", "name": "obs_1", "origin": "o_1", "prov": ["o_1"]}],
            "component_values": {"ObsRank": 1}
          }
        }
      ]
    }
  ]
}
```

Rows are never executable code. A row is data:

- `rid`: row identifier.
- `kind`: schema key.
- `sem`: semantic effect id.
- `verdict`: `pass`, `fail`, or `inconclusive`.
- `retention`: `active`, `retained`, `discharged`, `boundary`, or `deleted`.
- `refs`: finite row-id references.
- `payload.atoms`: mode-stratified evidence atoms.
- `payload.component_values`: finite values consumed by component functionals.
- `payload.debt_atoms` / `payload.debt`: explicit residual debt declarations.
- `payload.derives`: legacy compatibility input for finite derived rows. New
  strict specs should use `store_step_rules`; `validate --strict` reports
  `payload.derives` as a conformance failure.

Supported atom modes are `floor`, `diag`, `rel`, `cmp`, `avail`, and `prov`.

`stage_checks` should declare all pipeline stages for each candidate: `presentable`, `well_formed`, `observable`, `comparable`, `available`, `floor_safe`, `release_safe`, and `selected`. Missing stages are allowed for low-level construction, but `validate()` reports them as incomplete executable well-formedness.

`validate --report` returns a condition-indexed report for `WF01..WF13`:
row schemas, candidate enumeration, mode matrix, rule table, stage extraction,
component registry, support checker, exact support bounds, audit-universe scope,
release checker predicates, release footprint congruence, release local
stability, and work bounds. In v0.1.0, `--strict` treats portability and
certificate-explicitness warnings as failures: legacy bare coordinates, implicit
coordinate universes, aggregate component evaluators, lookup evaluators without
tables, incomplete component debt/support tables, heuristic retyping, legacy
`payload.derives`, incomplete release predicate tables, missing release checker
traces, and defaulted local-stability predicates.

Strict portable specs should explicitly include evidence rules, store-step
rules, mode matrix, component registry, release check table, read coordinates,
work bounds, and audit scope, even when some tables are empty:

```json
{
  "rules": [],
  "mode_matrix": {
    "floor->floor": {"allowed": true},
    "floor->diag": {"allowed": false}
  },
  "components": [],
  "release_check_table": {},
  "store_step_rules": [
    {
      "id": "derive_from_seed",
      "premise_rows": ["seed_row"],
      "premise_atoms": [{"mode": "floor", "name": "seed"}],
      "emits": [{"rid": "derived_row", "kind": "witness", "sem": "derived"}],
      "origin": "seed_row",
      "prov_path": ["seed_row"]
    }
  ]
}
```

The snippet above is abbreviated. A strict finite package must declare all
36 ordered mode pairs over `floor`, `diag`, `rel`, `cmp`, `avail`, and `prov`.
Use the non-mutating normalizer to expand compact examples:

```powershell
uv run cgt-bw normalize-strict examples/minimal_spec.json
```

`examples/strict_minimal_spec.json` is the smallest repository fixture with a
complete explicit mode table. `validate --strict` fails partial mode tables so
that downstream ports do not silently rely on identity defaults.

`payload.derives` remains accepted for legacy fixtures, but `StoreStepRule` is
the theorem-aligned finite closure declaration for new strict specs.

The report includes a stable `schema_version` and is covered by
`schemas/wellformedness-report.schema.json`. Specs are covered by the permissive
publication schema in `schemas/executable-band-spec.schema.json`; executable
theory validity is still enforced by `validate --report`.
Each issue can include machine-readable `evidence`, `witness_rows`, `severity`,
and `repair_hint` fields for automated conformance dashboards.

Applicability support is computed from candidate-visible mode evidence and row implication rules. The former `metadata.app_supp_pairs` diagnostic shortcut is no longer part of the normal computation path.

Component declarations are generic finite readers. Strict conformance treats
finite lookup/table evaluators and the built-in finite graph readers
(`graph_count`, `graph_reachability`, `graph_cut`) as theorem-aligned. Aggregate
evaluators remain useful in compatibility examples, but strict validation
reports them as convenience evaluators.

```json
{
  "name": "Rig",
  "polarity": "obstruction",
  "upper": 0,
  "input_kinds": ["rigidity"],
  "read_modes": ["diag"],
  "read_atoms": ["rig_1"],
  "aggregator": "lookup",
  "default": 0,
  "carrier": [0, 2],
  "bottom": 0,
  "preorder": [[0, 0], [2, 2]],
  "eval_table": {"rig-key": 2},
  "low_debt_table": {"0": [], "2": []},
  "up_debt_table": {"0": [], "2": ["rig-bound"]},
  "support_table": {"0": ["row:rig_1"], "2": ["row:rig_1"]},
  "support_atoms": ["row:rig_1"]
}
```

Release checker declarations:

```json
{
  "release_check_table": {
    "obstruction_rows": ["ob_1", "rig_1"],
    "lower_bound_rows": ["lb_1"],
    "allowed_new_rows": ["rc_1", "p_1", "ret_1"],
    "footprint_predicates": {
      "rc_1": {
        "obstructionCoverage": true,
        "lowerBoundSuccessor": true,
        "noNewRow": true,
        "noninterference": true,
        "diagnosticRetyping": true
      }
    },
    "footprint_coordinates": {
      "rc_1": ["ob_1", "w_1", "rc_1", "p_1", "ret_1"]
    },
    "predicate_coordinates": {
      "rc_1": {
        "obstructionCoverage": ["ob_1", "rc_1"],
        "lowerBoundSuccessor": ["w_1", "p_1"],
        "noNewRow": ["rc_1", "p_1", "ret_1"],
        "noninterference": ["ob_1", "w_1", "p_1"],
        "diagnosticRetyping": ["ob_1", "ret_1"]
      }
    }
  },
  "releases": [
    {
      "id": "rc_1",
      "source": "H1",
      "target": "H4",
      "discharges": ["ob_1"],
      "preserves": ["w_1", "p_1"],
      "footprint": ["ob_1", "w_1", "rc_1", "p_1", "ret_1"],
      "discharge_map": {"ob_1": "rc_1"},
      "preservation_map": {"w_1": "p_1"},
      "retyping_map": {"ob_1": "ret_1"},
      "diagnostic_retyping": ["ret_1"],
      "checker_trace": ["release-table:rc_1:pass"],
      "local_stability": {
        "FootprintDet": true,
        "ComponentDebtPres": true,
        "StageStab": true,
        "SelKerStab": true,
        "OneStepReleaseBisim": true
      }
    }
  ]
}
```

For backward compatibility, missing `local_stability` predicates default to
`true` only in compatibility construction paths. Strict validation rejects
defaulted local-stability predicates because release descent should be backed by
explicit certificate data in portable specs. CLI audit uses strict release
checking by default; use `--compat-release` only for legacy replay.

Strict release checking also reads `release_check_table.footprint_predicates`,
`release_check_table.footprint_coordinates`, and
`release_check_table.predicate_coordinates`. A release certificate whose checker
reads outside its declared coordinate set fails strict conformance. Strict
release certificates should also provide total `discharge_map`,
`preservation_map`, `retyping_map`, and a nonempty `checker_trace`; missing maps
are rejected by `check_release(strict=True)`.

Optional execution bounds and audit scope:

```json
{
  "work_bounds": {
    "closure_steps": 256,
    "candidate_rows": 256,
    "support_subsets": 4096,
    "release_checks": 1024
  },
  "audit_scope": {
    "whole_domain": true,
    "abstraction_map_declared": false,
    "preservation_checks": []
  },
  "read_coordinates": ["row:o_1", "row:c_1", "atom:diag:rig_1"],
  "exact_support_limit": 12
}
```

`read_coordinates` should be declared for reproducible exact support audits. Without it, the implementation derives a finite coordinate universe from closed rows and evidence atoms.
Use `row:<row-id>` and `atom:<mode>:<atom-name>` labels in new specs. Bare strings are accepted as legacy row coordinates.

Structured mode decisions can replace legacy boolean `mode_matrix` entries:

```json
{
  "mode_matrix": {
    "diag->floor": {
      "allowed": true,
      "requires_release": true,
      "requires_retyping": true,
      "required_modes": ["rel"]
    }
  }
}
```

`StageCheck.reads` declares an audit footprint only. It does not synthesize evidence and cannot make a missing required atom pass.

## Output Schemas

The repository publishes JSON Schemas for portable specs and official
certificate outputs:

- `schemas/executable-band-spec.schema.json` is a permissive publication schema
  for spec shape. It is not a theorem-validity checker.
- `schemas/strict-executable-band-spec.schema.json` checks the stricter portable
  package shape expected by `validate --strict`.
- `schemas/wellformedness-report.schema.json` validates `validate --report`
  output.
- `schemas/audit-report.schema.json` validates `audit --exact-support` output,
  including completion, support, and release-action certificate sections.
- `schemas/closure-certificate.schema.json` validates `close --certificate`
  output, including accepted/failure/boundary/candidate/derived row ids and the
  fixed-point reason.
- `schemas/rech-certificate.schema.json` validates typed RECH node/arc,
  nine-clause, and store-preservation certificate output.
- `schemas/evidence-audit.schema.json` validates provenance-sensitive evidence
  audit output.
- `schemas/component-law-certificate.schema.json` validates finite component
  law certificates.
- `schemas/support-certificate.schema.json` validates support checker table
  certificates.
- `schemas/completion-certificate.schema.json` validates completion
  certificates, including universal-property witnesses.
- `schemas/release-check.schema.json` validates release checker output.
- `schemas/release-descent-certificate.schema.json` validates the
  `release_action_certificate` section, including release checks, descent
  certificates, and descent proofs.
- `schemas/conformance-matrix.schema.json` validates
  `docs/conformance-matrix.json`, the machine-readable theory-to-surface map.
