"""Ensure every online solver shares the same SSRF protection boundary."""
import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).parents[1] / "src" / "cryptoscan"
MODULES = sorted(path.stem for path in PACKAGE.glob("*.py") if path.stem != "network_policy")


def _calls(module: str) -> list[ast.Call]:
    tree = ast.parse((PACKAGE / f"{module}.py").read_text(encoding="utf-8"))
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


@pytest.mark.parametrize("module", MODULES)
def test_no_module_bypasses_authorized_connection(module):
    calls = _calls(module)
    assert not any(isinstance(call.func, ast.Attribute)
                   and call.func.attr in {"create_connection", "connect", "connect_ex"}
                   and not (isinstance(call.func.value, ast.Name) and call.func.value.id == "sqlite3")
                   for call in calls)


@pytest.mark.parametrize("module", [
    "dghv_workflow", "mlwe_workflow", "gcm_hidden_live",
    "fischlin_workflow", "hamiltonicity_workflow",
])
def test_protocol_adapter_uses_authorized_connection(module):
    assert any(isinstance(call.func, ast.Name) and call.func.id == "connect_authorized"
               for call in _calls(module))
