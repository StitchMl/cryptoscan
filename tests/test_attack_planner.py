"""Tests for evidence-based attack planning and controlled fallback."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from cryptoscan.attack_planner import (
    RecoveryExhausted, Strategy, build_plan, execute_plan,
)
from cryptoscan.parser import Document


def test_planner_ranks_independent_families_and_falls_back():
    calls = []
    def first(docs):
        calls.append("first")
        raise RuntimeError("independent verification failed")
    def second(docs):
        calls.append("second")
        return "TEST{verified_result}"
    candidates = [
        Strategy("later", "offline", lambda docs: {"equation": "B"}, second,
                 rank=20),
        Strategy("earlier", "offline", lambda docs: {"equation": "A"}, first,
                 rank=10),
    ]
    plan = build_plan(candidates, (), mode="offline")
    assert [candidate.family for candidate in plan.candidates] == [
        "earlier", "later",
    ]
    assert execute_plan(plan, ()) == ("later", "TEST{verified_result}")
    assert calls == ["first", "second"]


def test_planner_cannot_execute_network_capabilities_offline():
    strategy = Strategy(
        "chosen-message oracle", "remote", lambda docs: True,
        lambda docs: "TEST{should_not_run}", ("network",),
    )
    unsupported = build_plan([strategy], (), mode="remote")
    assert unsupported.candidates == []
    assert "missing capabilities" in unsupported.rejected[0].reason
    supported = build_plan(
        [strategy], (), mode="remote", capabilities=frozenset({"network"}),
    )
    assert len(supported.candidates) == 1


def test_planner_tracks_recognizer_failure_without_crashing():
    def fail(docs):
        raise ValueError("unsupported transcript encoding")
    candidates = [
        Strategy("invalid", "offline", fail, lambda docs: "never"),
        Strategy("not found", "offline", lambda docs: None, lambda docs: "never"),
    ]
    plan = build_plan(candidates, (), mode="offline")
    assert not plan.candidates
    assert len(plan.rejected) == 2
    with pytest.raises(RecoveryExhausted, match="no applicable"):
        execute_plan(plan, ())


def test_planner_requires_nonempty_solver_result_and_continues():
    strategies = [
        Strategy("inconclusive", "offline", lambda docs: True,
                 lambda docs: ""),
        Strategy("conclusive", "offline", lambda docs: True,
                 lambda docs: "TEST{validated}", rank=101),
    ]
    assert execute_plan(
        build_plan(strategies, (), mode="offline"), (),
    ) == ("conclusive", "TEST{validated}")


def test_planner_preserves_independent_failure_reasons():
    strategies = [
        Strategy("algebraic", "offline", lambda docs: True,
                 lambda docs: (_ for _ in ()).throw(
                     ValueError("no modular root"),
                 )),
        Strategy("lattice", "offline", lambda docs: True,
                 lambda docs: (_ for _ in ()).throw(
                     RuntimeError("backend unavailable"),
                 ), rank=200),
    ]
    with pytest.raises(RecoveryExhausted) as error:
        execute_plan(build_plan(strategies, (), mode="offline"), ())
    assert error.value.failures == (
        ("algebraic", "no modular root"),
        ("lattice", "backend unavailable"),
    )


def test_cli_attack_plan_and_fallback_with_unseen_source(tmp_path, monkeypatch, capsys):
    import cryptoscan.cli as cli

    (tmp_path / "random_name.txt").write_text(
        "source-defined generic crypto model", encoding="utf-8",
    )
    failed = []
    def unavailable(docs):
        failed.append("first")
        raise RuntimeError("candidate rejected by validator")
    def successful(docs):
        failed.append("second")
        return "TEST{independent_attack}"

    monkeypatch.setattr(cli, "_attack_strategies", lambda args: (
        Strategy("algebraic alternative", "offline",
                 lambda docs: ("public algebra",), unavailable, rank=10),
        Strategy("statistical alternative", "offline",
                 lambda docs: ("biased scalar range",), successful, rank=20),
    ))
    assert cli.main([str(tmp_path), "--plan-attacks"]) == 0
    text = capsys.readouterr().out
    assert "algebraic alternative" in text
    assert "statistical alternative" in text
    assert failed == []
    assert cli.main([str(tmp_path), "--solve"]) == 0
    output = capsys.readouterr().out
    assert "FLAG: TEST{independent_attack}" in output
    assert failed == ["first", "second"]


def test_cli_never_runs_network_strategy_without_network_opt_in(tmp_path, monkeypatch):
    import cryptoscan.cli as cli

    (tmp_path / "new_case.txt").write_text(
        "interactive source evidence", encoding="utf-8",
    )
    called = []
    monkeypatch.setattr(cli, "_attack_strategies", lambda args: (
        Strategy("network-only", "remote", lambda docs: True,
                 lambda docs: called.append(1) or "TEST{network} ",
                 ("network",)),
    ))
    assert cli.main([str(tmp_path), "--solve"]) == 2
    assert called == []


def test_cli_json_plan_is_one_valid_structured_document(tmp_path, monkeypatch, capsys):
    import json
    import cryptoscan.cli as cli

    (tmp_path / "unseen.txt").write_text(
        "source-defined mathematical evidence", encoding="utf-8",
    )
    monkeypatch.setattr(cli, "_attack_strategies", lambda args: (
        Strategy("modular equations", "offline",
                 lambda docs: {"coefficient_matrix": [[1, 2]]},
                 lambda docs: "TEST{not_executed}"),
    ))
    assert cli.main([
        str(tmp_path), "--plan-attacks", "--format", "json",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == 1
    assert isinstance(report["findings"], list)
    assert report["attack_plan"][0]["family"] == "modular equations"
    assert report["attack_plan"][0]["status"] == "applicable"


def test_multiple_independent_scopes_are_not_solved_as_one_case(tmp_path, monkeypatch, capsys):
    import cryptoscan.cli as cli
    for folder in ("case_one", "case_two"):
        directory = tmp_path / folder
        directory.mkdir()
        (directory / "unseen_source.py").write_text(
            "same generic attack class, independent source", encoding="utf-8",
        )
    called = []
    def detector(docs):
        return {"source_count": len(docs)}
    def solver(docs):
        called.append(1)
        return "TEST{wrong_scope}"
    monkeypatch.setattr(cli, "_attack_strategies", lambda args: (
        Strategy("source-driven attack", "offline", detector, solver),
    ))
    status = cli.main([str(tmp_path), "--solve"])
    assert status == 2
    assert called == []
    assert "multiple independent challenge scopes" in capsys.readouterr().err


def test_scope_filtering_passes_only_relevant_evidence_to_solver():
    docs = [
        Document("one.py", "A", None, "first"),
        Document("two.py", "B", None, "second"),
    ]
    received = []
    strategy = Strategy(
        "scoped algebra", "offline", lambda ds: True,
        lambda ds: received.extend(ds) or "TEST{only_first_scope}",
    )
    plan = build_plan(
        [strategy], docs[:1], mode="offline", scope="first",
    )
    assert execute_plan(plan, docs) == (
        "scoped algebra", "TEST{only_first_scope}",
    )
    assert received == docs[:1]
