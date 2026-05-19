"""Publication readiness checks for cgt-bandwidth.

The script is intentionally conservative and side-effect free. It scans the
working tree for common local paths/secrets and, when requested, inspects built
artifacts for ignored local files.
"""

from __future__ import annotations

import argparse
import re
import tarfile
import zipfile
from pathlib import Path

FORBIDDEN_ARTIFACT_PARTS = (
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".coverage",
    ".env",
    "dist/",
)
LOCAL_PATH_PATTERNS = (
    re.compile(r"C:\\Users\\[^\\\s]+", re.IGNORECASE),
    re.compile(r"/home/[^/\s]+", re.IGNORECASE),
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
)
TEXT_SUFFIXES = {
    ".cfg",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yml",
    ".yaml",
}


def iter_text_files(root: Path) -> list[Path]:
    skipped_parts = {".venv", ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build"}
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skipped_parts for part in path.parts):
            continue
        if path == Path(__file__).resolve():
            continue
        if path.name == "uv.lock":
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            files.append(path)
    return files


def scan_text(root: Path) -> list[str]:
    problems: list[str] = []
    for path in iter_text_files(root):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in LOCAL_PATH_PATTERNS:
            if pattern.search(text):
                problems.append(f"{path}: local absolute path detected")
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                problems.append(f"{path}: secret-like token detected")
    return problems


def scan_worktree_artifacts(root: Path) -> list[str]:
    problems: list[str] = []
    for name in (".pytest_cache", ".mypy_cache", ".ruff_cache", ".coverage", "dist", "build"):
        if (root / name).exists():
            problems.append(f"{name}: generated artifact exists")
    for path in root.rglob("__pycache__"):
        if ".venv" not in path.parts:
            problems.append(f"{path}: generated artifact exists")
    return problems


def archive_names(path: Path) -> list[str]:
    if path.name.endswith(".whl"):
        with zipfile.ZipFile(path) as archive:
            return archive.namelist()
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return archive.getnames()
    return []


def scan_package_artifacts(package_dir: Path) -> list[str]:
    problems: list[str] = []
    for path in package_dir.glob("cgt_bandwidth-*"):
        bad = [
            name
            for name in archive_names(path)
            if any(part in name for part in FORBIDDEN_ARTIFACT_PARTS)
        ]
        if bad:
            problems.append(f"{path.name}: forbidden archive entries {bad[:10]}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--package", default="")
    parser.add_argument("--skip-worktree-artifacts", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    problems = scan_text(root)
    if not args.skip_worktree_artifacts:
        problems.extend(scan_worktree_artifacts(root))
    if args.package:
        problems.extend(scan_package_artifacts((root / args.package).resolve()))
    if problems:
        for problem in problems:
            print(problem)
        return 1
    print("publication audit passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
