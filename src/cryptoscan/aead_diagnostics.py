"""Static checks for authenticated-decryption error handling."""

import ast


AUTH_STATUS_NAMES = frozenset({"is_auth", "tag_valid", "authenticated"})


def _decryption_status_assignment(statement: ast.stmt) -> str | None:
    """Return the validation flag bound by an AEAD decryption tuple."""
    if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
        return None
    decrypt = statement.value
    if not (isinstance(decrypt, ast.Call)
            and isinstance(decrypt.func, ast.Attribute)
            and decrypt.func.attr == "decrypt"):
        return None
    target = statement.targets[0]
    if not isinstance(target, ast.Tuple) or len(target.elts) != 2:
        return None
    status = target.elts[1]
    if isinstance(status, ast.Name) and status.id in AUTH_STATUS_NAMES:
        return status.id
    return None


def _status_used(statements: list[ast.stmt], status: str) -> bool:
    return any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == status
        for statement in statements
        for node in ast.walk(statement)
    )


def unused_validation_flags(source: str) -> list[int]:
    """Locate assignments of status flags that are never subsequently read."""
    try:
        module = ast.parse(source)
    except SyntaxError:
        return []
    locations: list[int] = []
    for function in ast.walk(module):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for index, statement in enumerate(function.body):
            status = _decryption_status_assignment(statement)
            if status and not _status_used(function.body[index + 1:], status):
                locations.append(statement.lineno)
    return locations
