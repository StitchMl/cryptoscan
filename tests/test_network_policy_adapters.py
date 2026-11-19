"""Ensure online solvers share the same SSRF protection boundary."""
import ast
from pathlib import Path

import pytest


@pytest.mark.parametrize("module", [
    "dghv_workflow", "mlwe_workflow", "gcm_hidden_live",
    "fischlin_workflow", "hamiltonicity_workflow",
])
def test_protocol_adapter_uses_authorized_connection(module):
    source = (Path(__file__).parents[1] / "src" / "cryptoscan" / f"{module}.py").read_text()
    tree = ast.parse(source)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assert any(isinstance(call.func, ast.Name) and call.func.id == "connect_authorized"
               for call in calls)
    assert not any(isinstance(call.func, ast.Attribute)
                   and call.func.attr == "create_connection" for call in calls)
