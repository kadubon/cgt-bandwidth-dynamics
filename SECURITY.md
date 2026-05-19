# Security Policy

`cgt-bandwidth` treats specs as data. It must not evaluate user-provided Python,
import arbitrary modules from specs, or mutate repositories/files as part of
release checking.

## Supported Versions

The project is currently `0.x` alpha software. Security fixes target the latest
published minor version once public releases begin.

## Reporting A Vulnerability

Report security issues privately to the project maintainer before opening a
public issue. Include:

- the affected version or commit;
- a minimal spec or command that reproduces the issue;
- the observed impact, especially arbitrary code execution, path traversal,
  resource exhaustion, or package artifact leakage.

## Security Boundaries

- JSON is parsed with the Python standard library.
- YAML is optional and must use safe loading.
- Exact support enumeration is exponential and must remain bounded.
- Release certificates are audit data, not filesystem deletion commands.
- Build artifacts, virtual environments, caches, logs, and secrets must not be
  included in source or wheel distributions.
