"""Shared test configuration.

Online-attack tests talk to TCP oracles on loopback. The production network
policy refuses non-public destinations unless explicitly opted in, so the test
session opts in here; tests of the policy itself remove the variable again.
"""
import pytest


@pytest.fixture(autouse=True)
def _allow_loopback_oracles(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_ALLOW_PRIVATE_NETWORK", "1")
