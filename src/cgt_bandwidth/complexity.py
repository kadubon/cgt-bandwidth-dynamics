"""Finite release-cover synthesis algorithms."""

from __future__ import annotations

from itertools import combinations
from typing import Any


def solve_release_cover_exact(
    universe: set[str], sets: dict[str, set[str]], budget: int
) -> tuple[bool, tuple[str, ...]]:
    """Exact solver for the pure release-cover core."""

    universe = {str(item) for item in universe}
    normalized = {str(name): {str(item) for item in covered} for name, covered in sets.items()}
    names = sorted(normalized)
    for size in range(min(budget, len(names)) + 1):
        for combo in combinations(names, size):
            covered: set[str] = set()
            for name in combo:
                covered.update(normalized[name])
            if universe <= covered:
                return True, tuple(combo)
    return False, ()


def greedy_release_cover(
    universe: set[str], sets: dict[str, set[str]], budget: int | None = None
) -> tuple[bool, tuple[str, ...]]:
    """Greedy set-cover heuristic with the standard pure-coverage boundary."""

    remaining = {str(item) for item in universe}
    normalized = {str(name): {str(item) for item in covered} for name, covered in sets.items()}
    chosen: list[str] = []
    while remaining and (budget is None or len(chosen) < budget):
        best_name = None
        best_gain: set[str] = set()
        for name, covered in sorted(normalized.items()):
            gain = covered & remaining
            if len(gain) > len(best_gain):
                best_name = name
                best_gain = gain
        if best_name is None or not best_gain:
            break
        chosen.append(best_name)
        remaining -= best_gain
    return not remaining, tuple(chosen)


def parse_release_cover_instance(data: dict[str, Any]) -> tuple[set[str], dict[str, set[str]], int]:
    universe = {str(item) for item in data.get("universe", [])}
    sets = {
        str(name): {str(item) for item in covered} for name, covered in data.get("sets", {}).items()
    }
    budget = int(data.get("budget", len(sets)))
    return universe, sets, budget
