"""Static checks for authenticated-decryption error handling."""

import ast


def unused_validation_flags(source: str) -> list[int]:
    """Locate assignments of status flags that are never subsequently read."""
    try:
        module = ast.parse(source)
    except SyntaxError:
        return []
    locations = []
    for function in ast.walk(module):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for index, statement in enumerate(function.body):
            if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
                continue
            if not (isinstance(statement.value, ast.Call) and isinstance(statement.value.func, ast.Attribute)
                    and statement.value.func.attr == "decrypt"):
                continue
            destination = statement.targets[0]
            if not isinstance(destination, ast.Tuple) or len(destination.elts) != 2:
                continue
            status = destination.elts[1]
            if not isinstance(status, ast.Name) or status.id not in {"is_auth", "tag_valid", "authenticated"}:
                continue
            remainder = function.body[index + 1:]
            if not any(isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == status.id
                       for item in remainder for node in ast.walk(item)):
                locations.append(statement.lineno)
    return locations
