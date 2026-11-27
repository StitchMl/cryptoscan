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
    preflight: Callable[[Any], bool] | None = None
    output_label: str = "FLAG"


@dataclass(frozen=True)
class Candidate:
    strategy: Strategy
    evidence: Any
    requirements: tuple[str, ...] = ()
    scope: str = "."

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
    investigations: list[Candidate] = field(default_factory=list)

    def describe(self) -> list[dict[str, object]]:
        return [
            {
                "family": candidate.family,
                "capabilities": candidate.strategy.capabilities,
                "backend": candidate.strategy.backend,
                "rank": candidate.strategy.rank,
                "status": "applicable",
                "scope": candidate.scope,
            }
            for candidate in self.candidates
        ] + [
            {
                "family": candidate.family,
                "status": "analysis-only",
                "scope": candidate.scope,
                "backend": candidate.strategy.backend,
                "reason": (
                    "Mathematical analysis available; no verified "
                    "plaintext-recovery solver"
                ),
            }
            for candidate in self.investigations
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


def _assess(strategy: Strategy, documents: Sequence[Any],
            capabilities: frozenset[str]) -> tuple[Any, str | None]:
    """Return (evidence, None) when applicable, else (None, rejection reason)."""
    missing = sorted(set(strategy.capabilities) - capabilities)
    if missing:
        return None, "missing capabilities: " + ", ".join(missing)
    try:
        evidence = strategy.recognize(documents)
    except _RECOVERABLE as exc:
        return None, "recognition error: " + str(exc)[:200]
    if evidence is None or evidence is False or evidence == () or evidence == []:
        return None, "source preconditions not established"
    if strategy.preflight is not None:
        try:
            verified = strategy.preflight(evidence)
        except _RECOVERABLE as exc:
            return None, "mathematical preflight failed: " + str(exc)[:200]
        if not verified:
            return None, "mathematical preconditions not established"
    return evidence, None


def build_plan(strategies: Iterable[Strategy], documents: Sequence[Any], *,
               mode: str, capabilities: frozenset[str] = frozenset(),
               scope: str = "."
               ) -> AttackPlan:
    """Collect every independently supported strategy and sort deterministically.

    Recognizers must be side-effect free; no solver runs during planning.
    Optional capability constraints prevent invoking an incompatible backend.
    """
    plan = AttackPlan()
    for strategy in strategies:
        if strategy.mode != mode:
            continue
        evidence, reason = _assess(strategy, documents, capabilities)
        if reason is not None:
            plan.rejected.append(Rejected(strategy.name, reason))
            continue
        plan.candidates.append(Candidate(strategy, evidence, scope=scope))
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
    scopes = {candidate.scope for candidate in plan.candidates}
    if len(scopes) > 1:
        raise RecoveryExhausted([(
            "planner", "multiple independent challenge scopes detected: "
            + ", ".join(sorted(scopes)) + "; select one challenge",
        )])
    failures: list[tuple[str, str]] = []
    for candidate in plan.candidates:
        try:
            relevant = [
                document for document in documents
                if getattr(document, "scope", candidate.scope) == candidate.scope
            ]
            output = candidate.strategy.recover(relevant, *args, **kwargs)
            if not isinstance(output, str) or not output.strip():
                raise ValueError("solver did not return verified plaintext")
            return candidate.family, output
        except _RECOVERABLE as exc:
            failures.append((candidate.family, str(exc)[:300]))
    raise RecoveryExhausted(failures or [
        ("planner", "no applicable verified strategy"),
    ])
