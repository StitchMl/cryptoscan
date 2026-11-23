"""Evidence-driven attack planning independent of named CTFs.

A strategy contributes a recognizer (precondition extraction), capabilities,
and an executor (which must verify its recovered result). The planner keeps
multiple applicable strategies instead of locking into the first match.
This module has no knowledge of any challenge-specific protocol.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence


_RECOVERABLE = (RuntimeError, ValueError, OSError, ImportError, ArithmeticError)


@dataclass(frozen=True)
class Strategy:
    name: str
    mode: str
    recognize: Callable[[Sequence[Any]], Any]
    recover: Callable[..., str]
    capabilities: tuple[str, ...] = ()
    rank: int = 100
    backend: str = "python"


@dataclass(frozen=True)
class Candidate:
    strategy: Strategy
    evidence: Any
    requirements: tuple[str, ...] = ()

    @property
    def family(self) -> str:
        return self.strategy.name


@dataclass(frozen=True)
class Rejected:
    family: str
    reason: str


@dataclass
class AttackPlan:
    candidates: list[Candidate] = field(default_factory=list)
    rejected: list[Rejected] = field(default_factory=list)

    def describe(self) -> list[dict[str, object]]:
        return [
            {
                "family": candidate.family,
                "capabilities": candidate.strategy.capabilities,
                "backend": candidate.strategy.backend,
                "rank": candidate.strategy.rank,
                "status": "applicable",
            }
            for candidate in self.candidates
        ] + [
            {"family": rejected.family, "status": "unavailable",
             "reason": rejected.reason}
            for rejected in self.rejected
        ]


class RecoveryExhausted(RuntimeError):
    def __init__(self, failures: Sequence[tuple[str, str]]):
        self.failures = tuple(failures)
        details = "; ".join(f"{family}: {reason}" for family, reason in failures)
        super().__init__("all applicable recovery strategies failed: " + details)


def build_plan(strategies: Iterable[Strategy], documents: Sequence[Any], *,
               mode: str, capabilities: frozenset[str] = frozenset()
               ) -> AttackPlan:
    """Collect every independently supported strategy and sort deterministically.

    Recognizers must be side-effect free; no solver runs during planning.
    Optional capability constraints prevent invoking an incompatible backend.
    """
    plan = AttackPlan()
    for strategy in strategies:
        if strategy.mode != mode:
            continue
        missing = sorted(set(strategy.capabilities) - capabilities)
        if missing:
            plan.rejected.append(Rejected(
                strategy.name, "missing capabilities: " + ", ".join(missing),
            ))
            continue
        try:
            evidence = strategy.recognize(documents)
        except _RECOVERABLE as exc:
            plan.rejected.append(Rejected(
                strategy.name, "recognition error: " + str(exc)[:200],
            ))
            continue
        if evidence is None or evidence is False or evidence == () or evidence == []:
            plan.rejected.append(Rejected(
                strategy.name, "source preconditions not established",
            ))
            continue
        plan.candidates.append(Candidate(strategy, evidence))
    plan.candidates.sort(key=lambda item: (
        item.strategy.rank, item.strategy.name,
    ))
    return plan


def execute_plan(plan: AttackPlan, documents: Sequence[Any], *args: Any,
                 **kwargs: Any) -> tuple[str, str]:
    """Try applicable attacks and return only a solver-verified plaintext.

    A failed strategy is not evidence that every attack has failed.
    Failures are collected, and the next independent strategy may run.
    Every solver remains responsible for verifying its own result.
    """
    failures: list[tuple[str, str]] = []
    for candidate in plan.candidates:
        try:
            output = candidate.strategy.recover(documents, *args, **kwargs)
            if not isinstance(output, str) or not output.strip():
                raise ValueError("solver did not return verified plaintext")
            return candidate.family, output
        except _RECOVERABLE as exc:
            failures.append((candidate.family, str(exc)[:300]))
    raise RecoveryExhausted(failures or [
        ("planner", "no applicable verified strategy"),
    ])
