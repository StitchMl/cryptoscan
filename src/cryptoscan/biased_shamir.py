"""Statistical Shamir recovery when coefficient sampling omits field elements.

The algebraic attack is independent of the source: given one fewer share
than the polynomial degree plus one, every possible constant term fixes
a unique polynomial. A restricted coefficient distribution rules out
many constants. Repeated independent polynomials with the same secret
intersect candidate sets; recovered residues from different prime fields
are combined via CRT once the plaintext bound makes the lift unique.

The remote adapter is only activated after source AST checks establish
a compatible interactive protocol. No source text is executed.
"""
from __future__ import annotations

import ast
import math
import re
import socket
import time
from dataclasses import dataclass
from typing import Sequence

from sympy import nextprime

from .parser import Document
from .source_units import parse_python

_MAX_SOURCE = 1_000_000
_MAX_PRIME = 367
_MAX_BATCH = 1024
_FLAG = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,39}\{[^{}\r\n]{1,256}\}")


@dataclass(frozen=True)
class BiasedShamirOracle:
    secret_bits: int
    excluded_high: int
    minimum_n: int
    prime_prompt: str
    count_prompt: str
    secret_prompt: str
    shares_label: str


def _symbol(node):
    return node.id if isinstance(node, ast.Name) else None


def _member(node):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return (node.value.id, node.attr)
    return None


def _call_label(node):
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "int" and len(node.args) == 1):
        return None
    expression = node.args[0]
    if not (isinstance(expression, ast.Call)
            and isinstance(expression.func, ast.Name)
            and expression.func.id == "input"
            and len(expression.args) <= 1):
        return None
    if not expression.args:
        return ""
    value = expression.args[0]
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def _bound_difference(node):
    """Recognize p-d where d>0 without evaluating source expressions."""
    if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub)
            and isinstance(node.right, ast.Constant)
            and type(node.right.value) is int
            and 1 <= node.right.value <= 32):
        return _member(node.left), _symbol(node.left), node.right.value
    return None


def _sampler_imports(tree):
    """Bind a sampling API to trusted standard/Crypto modules."""
    known = {
        "getRandomRange": "Crypto.Util.number",
        "randbelow": "secrets",
        "randrange": "random",
        "randint": "random",
    }
    names, modules = set(), set()
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            if statement.module not in set(known.values()):
                continue
            for alias in statement.names:
                if alias.name == "*":
                    names.update(
                        name for name, module in known.items()
                        if module == statement.module
                    )
                elif known.get(alias.name) == statement.module:
                    names.add(alias.asname or alias.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name in set(known.values()):
                    modules.add(alias.asname or alias.name)
    return names, modules


def _sampler_bound(node, permitted):
    if not isinstance(node, ast.Call):
        return None
    names, modules = permitted
    func = node.func
    if isinstance(func, ast.Name):
        if func.id not in names:
            return None
        method = func.id
        # Renamed imports retain API semantics; infer from arity.
    elif (isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in modules):
        method = func.attr
    else:
        return None
    if method in ("getRandomRange", "randrange", "randint") or (
            method in names and len(node.args) == 2):
        if len(node.args) != 2:
            return None
        low, high = node.args
        if not (isinstance(low, ast.Constant) and low.value == 0):
            return None
        bound = _bound_difference(high)
        if bound and method == "randint":
            member, name, difference = bound
            if difference <= 1:
                return None
            return member, name, difference - 1
        return bound
    if method in ("randbelow", "randrange") or (
            method in names and len(node.args) == 1):
        return _bound_difference(node.args[0]) if len(node.args) == 1 else None
    return None


def _constructor_roles(class_node, permitted):
    """Infer modulus, threshold, and constant-term roles from a class AST."""
    for method in class_node.body:
        if not isinstance(method, ast.FunctionDef) or len(method.args.args) < 4:
            continue
        parameters = [item.arg for item in method.args.args]
        arguments = set(parameters)
        self_name = parameters[0]
        assignments = {}
        for stmt in ast.walk(method):
            if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                    and (member := _member(stmt.targets[0])) is not None
                    and member[0] == self_name
                    and (value := _symbol(stmt.value)) in arguments):
                assignments[member[1]] = value
        for stmt in ast.walk(method):
            if not (isinstance(stmt, ast.Assign)
                    and len(stmt.targets) == 1
                    and (target := _member(stmt.targets[0])) is not None
                    and target[0] == self_name
                    and isinstance(stmt.value, ast.BinOp)
                    and isinstance(stmt.value.op, ast.Add)):
                continue
            values, random_part = stmt.value.left, stmt.value.right
            if (not isinstance(values, ast.List) or len(values.elts) != 1
                    or (secret_arg := _symbol(values.elts[0])) not in arguments
                    or not isinstance(random_part, ast.ListComp)
                    or len(random_part.generators) != 1):
                continue
            sampler = _sampler_bound(random_part.elt, permitted)
            if sampler is None:
                continue
            modulus_member, modulus_arg, excluded = sampler
            if modulus_member and modulus_member[0] == self_name:
                modulus_arg = assignments.get(modulus_member[1])
            if modulus_arg is None or modulus_arg == secret_arg:
                continue
            loop = random_part.generators[0]
            if not (isinstance(loop.iter, ast.Call)
                    and isinstance(loop.iter.func, ast.Name)
                    and loop.iter.func.id == "range"
                    and len(loop.iter.args) == 1):
                continue
            end = _bound_difference(loop.iter.args[0])
            if end is None:
                continue
            count_member, count_arg, degree_offset = end
            if degree_offset != 1:
                continue
            if count_member and count_member[0] == self_name:
                count_arg = assignments.get(count_member[1])
            if count_arg is None or count_arg in (modulus_arg, secret_arg):
                continue
            return (modulus_arg, count_arg, secret_arg, excluded,
                    target[1], self_name, method.name)
    return None


def _has_polynomial_evaluation(class_node, coefficient_field):
    """Require actual polynomial evaluation over a finite modulus."""
    for method in class_node.body:
        if not isinstance(method, ast.FunctionDef):
            continue
        nodes = list(ast.walk(method))
        if not any(
            isinstance(node, ast.Attribute)
            and node.attr == coefficient_field for node in nodes
        ):
            continue
        if not any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "pow" and len(node.args) == 3
            for node in nodes
        ):
            continue
        if any(
            isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod)
            for node in nodes
        ):
            return True
    return False


def _has_contiguous_shares(class_node, count_field):
    for method in class_node.body:
        if not isinstance(method, ast.FunctionDef):
            continue
        for node in ast.walk(method):
            if not (isinstance(node, (ast.ListComp, ast.GeneratorExp))
                    and len(node.generators) == 1
                    and isinstance(node.elt, ast.Call)
                    and isinstance(node.elt.func, ast.Attribute)
                    and len(node.elt.args) == 1):
                continue
            loop = node.generators[0]
            if not (isinstance(loop.target, ast.Name)
                    and isinstance(loop.iter, ast.Call)
                    and isinstance(loop.iter.func, ast.Name)
                    and loop.iter.func.id == "range"
                    and len(loop.iter.args) == 1
                    and (member := _member(loop.iter.args[0])) is not None
                    and member[1] == count_field):
                continue
            x = node.elt.args[0]
            if (isinstance(x, ast.BinOp)
                    and isinstance(x.op, ast.Add)
                    and _symbol(x.left) == loop.target.id
                    and isinstance(x.right, ast.Constant)
                    and x.right.value == 1):
                return True
    return False


def _secret_size(tree, secret_name):
    sizes = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and _symbol(node.targets[0]) == secret_name
                and isinstance(node.value, ast.Call)):
            continue
        outer = node.value
        for inner in ast.walk(outer):
            if not isinstance(inner, ast.Call) or len(inner.args) != 1:
                continue
            if (isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "urandom"
                    and isinstance(inner.args[0], ast.Constant)
                    and type(inner.args[0].value) is int
                    and 1 <= inner.args[0].value <= 256):
                sizes.add(8 * inner.args[0].value)
    return next(iter(sizes)) if len(sizes) == 1 else None


def _constant_lower_bound(node):
    if isinstance(node, ast.Constant) and type(node.value) in (int, float):
        return int(node.value)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "int" and len(node.args) == 1):
        return _constant_lower_bound(node.args[0])
    return None


def _prime_range_check(tree, p_name, n_name):
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        calls = [
            sub for sub in ast.walk(node.test)
            if isinstance(sub, ast.Call)
            and len(sub.args) == 1 and _symbol(sub.args[0]) == p_name
            and ((isinstance(sub.func, ast.Name)
                  and sub.func.id in ("isPrime", "isprime"))
                 or isinstance(sub.func, ast.Attribute)
                 and sub.func.attr in ("isPrime", "isprime"))
        ]
        if not calls:
            continue
        for condition in ast.walk(node.test):
            if not isinstance(condition, ast.Compare):
                continue
            if (len(condition.ops) == 2
                    and all(isinstance(op, ast.Lt) for op in condition.ops)
                    and len(condition.comparators) == 2
                    and _symbol(condition.comparators[0]) == n_name
                    and _symbol(condition.comparators[1]) == p_name
                    and (limit := _constant_lower_bound(condition.left)) is not None
                    and 0 <= limit <= 300):
                return limit
    return None


def _sharing_print(tree):
    outputs = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print" and len(node.args) == 2
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            continue
        value = node.args[1]
        if (isinstance(value, ast.Subscript)
                and isinstance(value.slice, ast.Slice)
                and value.slice.lower is None
                and value.slice.step is None
                and isinstance(value.slice.upper, ast.UnaryOp)
                and isinstance(value.slice.upper.op, ast.USub)
                and isinstance(value.slice.upper.operand, ast.Constant)
                and value.slice.upper.operand.value == 1):
            if (name := _symbol(value.value)) is not None:
                outputs.add((node.args[0].value.strip(), name))
    return next(iter(outputs)) if len(outputs) == 1 else None


def _source_profile(document):
    if not document.text or len(document.text) > _MAX_SOURCE:
        return None
    tree = parse_python(document)
    if tree is None:
        return None
    candidates = []
    permitted = _sampler_imports(tree)
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        roles = _constructor_roles(node, permitted)
        if roles is None:
            continue
        p_arg, n_arg, secret_arg, excluded, coeff_field, _, _ = roles
        if (not _has_polynomial_evaluation(node, coeff_field)
                or not _has_contiguous_shares(node, n_arg if n_arg else "")):
            # count_field is the self attribute, not its constructor argument
            count_field = next(
                (member.attr for stmt in ast.walk(node)
                 if isinstance(stmt, ast.Assign)
                 for member in stmt.targets
                 if isinstance(member, ast.Attribute)
                 and _symbol(stmt.value) == n_arg), None,
            )
            if (not _has_polynomial_evaluation(node, coeff_field)
                    or not count_field
                    or not _has_contiguous_shares(node, count_field)):
                continue
        # Match the constructor call to actual interactive input variables.
        for instance in ast.walk(tree):
            if not (isinstance(instance, ast.Call)
                    and isinstance(instance.func, ast.Name)
                    and instance.func.id == node.name
                    and len(instance.args) >= 3):
                continue
            ctor = next(
                method for method in node.body
                if isinstance(method, ast.FunctionDef)
                and len(method.args.args) >= 4
                and secret_arg in [arg.arg for arg in method.args.args]
            )
            parameters = [arg.arg for arg in ctor.args.args[1:]]
            bindings = {
                argument: _symbol(value)
                for argument, value in zip(parameters, instance.args)
            }
            public_p = bindings.get(p_arg)
            public_n = bindings.get(n_arg)
            public_secret = bindings.get(secret_arg)
            if not all((public_p, public_n, public_secret)):
                continue
            prompts = {}
            for assign in ast.walk(tree):
                if (isinstance(assign, ast.Assign)
                        and len(assign.targets) == 1
                        and (name := _symbol(assign.targets[0])) in
                        (public_p, public_n)):
                    label = _call_label(assign.value)
                    if label is not None:
                        prompts[name] = label
            if public_p not in prompts or public_n not in prompts:
                continue
            lower = _prime_range_check(tree, public_p, public_n)
            bound = _secret_size(tree, public_secret)
            printing = _sharing_print(tree)
            if lower is None or bound is None or printing is None:
                continue
            label, printed_name = printing
            # The observed slice must be derived from this very constructor.
            # A disjoint share print elsewhere in the source is not evidence.
            if not any(
                isinstance(assign, ast.Assign)
                and len(assign.targets) == 1
                and _symbol(assign.targets[0]) == printed_name
                and isinstance(assign.value, ast.Call)
                and isinstance(assign.value.func, ast.Attribute)
                and assign.value.func.value is instance
                for assign in ast.walk(tree)
            ):
                continue
            loops = [
                loop for loop in ast.walk(tree)
                if isinstance(loop, ast.While)
                and any(child is instance for child in ast.walk(loop))
            ]
            secret_definitions = [
                assign for assign in ast.walk(tree)
                if isinstance(assign, ast.Assign)
                and len(assign.targets) == 1
                and _symbol(assign.targets[0]) == public_secret
            ]
            if (len(loops) != 1 or len(secret_definitions) != 1
                    or secret_definitions[0].lineno >= loops[0].lineno):
                # Repeated observations must share the SAME constant term.
                continue
            secrets = set()
            for branch in ast.walk(tree):
                if not (isinstance(branch, ast.If)
                        and isinstance(branch.test, ast.Compare)):
                    continue
                condition = branch.test
                if (len(condition.ops) != 1
                        or not isinstance(condition.ops[0], ast.Eq)
                        or len(condition.comparators) != 1):
                    continue
                for left, right in (
                    (condition.left, condition.comparators[0]),
                    (condition.comparators[0], condition.left),
                ):
                    if _symbol(right) == public_secret:
                        value = _call_label(left)
                        if value is not None:
                            secrets.add(value)
            if len(secrets) == 1:
                candidates.append(BiasedShamirOracle(
                    bound, excluded, lower, prompts[public_p],
                    prompts[public_n], secrets.pop(), label,
                ))
    return candidates[0] if len(candidates) == 1 else None


def extract_instance(documents: Sequence[Document]):
    candidates = [
        profile for document in documents
        if (profile := _source_profile(document)) is not None
    ]
    return candidates[0] if len(candidates) == 1 else None


def _multiply_linear(polynomial, root, p):
    next_coefficients = [0] * (len(polynomial) + 1)
    for index, value in enumerate(polynomial):
        next_coefficients[index] = (
            next_coefficients[index] - root * value
        ) % p
        next_coefficients[index + 1] = (
            next_coefficients[index + 1] + value
        ) % p
    return next_coefficients


def candidate_secrets(shares, p, *, x_coordinates=None, excluded_high=1):
    """Enumerate source-compatible constant terms over F_p.

    If m shares of a polynomial of degree <=m are known, then every
    compatible polynomial is P_0(x) + t*prod(x-x_i). For each nonconstant
    coefficient, excluded field values forbid a small set of t.
    """
    values = list(shares)
    m = len(values)
    if not (3 <= p <= _MAX_PRIME and 1 <= m < p
            and 1 <= excluded_high < p):
        raise ValueError("unsupported finite-field share dimensions")
    points = list(range(1, m + 1)) if x_coordinates is None else list(x_coordinates)
    if (len(points) != m or len({x % p for x in points}) != m
            or any(x % p == 0 for x in points)
            or any(type(y) is not int or not 0 <= y < p for y in values)):
        raise ValueError("invalid or duplicate shares")
    if points == list(range(1, m + 1)):
        differences = values.copy()
        for level in range(1, m):
            inverse = pow(level, -1, p)
            for index in range(m - 1, level - 1, -1):
                differences[index] = (
                    (differences[index] - differences[index - 1])
                    * inverse
                ) % p
    else:
        differences = values.copy()
        for level in range(1, m):
            for index in range(m - 1, level - 1, -1):
                differences[index] = (
                    (differences[index] - differences[index - 1])
                    * pow(points[index] - points[index - level], -1, p)
                ) % p
    base = [differences[-1]]
    for index in range(m - 2, -1, -1):
        base = _multiply_linear(base, points[index], p)
        base[0] = (base[0] + differences[index]) % p
    kernel = [1]
    for point in points:
        kernel = _multiply_linear(kernel, point, p)
    forbidden = set()
    for degree in range(1, m + 1):
        base_coefficient = base[degree] if degree < len(base) else 0
        multiplier = kernel[degree]
        if multiplier == 0:
            if base_coefficient >= p - excluded_high:
                return frozenset()
            continue
        inverse = pow(multiplier, -1, p)
        for illegal in range(p - excluded_high, p):
            forbidden.add(
                (illegal - base_coefficient) * inverse % p
            )
    return frozenset(
        (base[0] + t * kernel[0]) % p
        for t in range(p) if t not in forbidden
    )


def _prime_schedule(bits, minimum_n, *, max_prime=_MAX_PRIME):
    """Choose extra small prime fields to tolerate unresolved candidates."""
    if not 8 <= bits <= 2048:
        raise ValueError("unsupported secret size")
    primes = []
    q = int(nextprime(max(2, minimum_n + 1)))
    modulus = 1
    # Extra fields allow successful CRT even with a few ambiguous residues.
    while modulus.bit_length() <= bits + 64:
        if q > max_prime or len(primes) >= 96:
            raise RuntimeError(
                "prime schedule too expensive for the proven plaintext bound"
            )
        primes.append(q)
        modulus *= q
        q = int(nextprime(q))
    return primes


def _crt(residues):
    value, modulus = 0, 1
    for prime, residue in sorted(residues.items()):
        value += modulus * (
            (residue - value) * pow(modulus, -1, prime) % prime
        )
        modulus *= prime
        value %= modulus
    return value, modulus


def _read_share_lists(conn, label, expected, deadline):
    if not 0 < expected <= _MAX_BATCH:
        raise ValueError("unsupported response batch")
    expression = re.compile(re.escape(label) + r"\s*(\[[\d\s,]+\])")
    buffer = ""
    results = []
    while len(results) < expected:
        if time.monotonic() >= deadline:
            raise TimeoutError("secret-sharing oracle deadline exceeded")
        conn.settimeout(max(.1, min(2.0, deadline - time.monotonic())))
        try:
            chunk = conn.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            raise ConnectionError(
                "secret-sharing server closed before returning all shares"
            )
        buffer += chunk.decode("utf-8", errors="replace")
        if len(buffer) > 3_000_000:
            raise ValueError("oversized secret-sharing response")
        while (match := expression.search(buffer)) is not None:
            raw = match.group(1)
            try:
                parsed = ast.literal_eval(raw)
            except (SyntaxError, ValueError):
                raise ValueError("invalid share list") from None
            if (not isinstance(parsed, list) or len(parsed) > _MAX_PRIME
                    or not all(type(value) is int for value in parsed)):
                raise ValueError("invalid finite-field shares")
            results.append(parsed)
            buffer = buffer[match.end():]
            if len(results) >= expected:
                break
    return results


def _query_batch(conn, profile, primes, deadline):
    if len(primes) > _MAX_BATCH:
        raise ValueError("too many bundled share requests")
    payload = "".join(
        str(prime) + "\n" + str(prime - 1) + "\n"
        for prime in primes
    ).encode("ascii")
    conn.sendall(payload)
    replies = _read_share_lists(
        conn, profile.shares_label, len(primes), deadline,
    )
    for prime, shares in zip(primes, replies, strict=True):
        if len(shares) != prime - 2:
            raise ValueError("unexpected number of shares from server")
    return replies


def recover_secret_from_oracle(conn, profile, *,
                               budget_seconds=27.0,
                               max_queries=650, max_prime=_MAX_PRIME):
    """Adaptive attack on independent biased Shamir distributions.

    Source must establish that one random polynomial is generated per
    query and the hidden constant remains fixed across queries.
    """
    start = time.monotonic()
    deadline = start + budget_seconds
    primes = _prime_schedule(
        profile.secret_bits, profile.minimum_n, max_prime=max_prime,
    )
    possibilities = {prime: frozenset(range(prime)) for prime in primes}
    queries = 0
    # Pipeline a short initial batch to avoid per-query network RTT.
    pending = primes * 3
    while True:
        if pending:
            if queries + len(pending) > max_queries:
                raise RuntimeError("bounded share-query budget exhausted")
            observed = _query_batch(conn, profile, pending, deadline)
            queries += len(pending)
            for prime, shares in zip(pending, observed, strict=True):
                possibilities[prime] &= candidate_secrets(
                    shares, prime, excluded_high=profile.excluded_high,
                )
                if not possibilities[prime]:
                    raise RuntimeError(
                        "the observed shares contradict the source-defined "
                        "coefficient distribution"
                    )
        unique = {
            prime: next(iter(values))
            for prime, values in possibilities.items() if len(values) == 1
        }
        total = math.prod(unique)
        if total > (1 << profile.secret_bits):
            secret, crt_modulus = _crt(unique)
            if crt_modulus <= (1 << profile.secret_bits):
                raise RuntimeError("CRT has not determined a unique secret")
            return secret, {
                "queries": queries, "primes_used": len(unique),
                "crt_modulus_bits": crt_modulus.bit_length(),
                "secret_upper_bound_bits": profile.secret_bits,
                "independent_residues": True,
            }
        pending = [
            p for p in primes if len(possibilities[p]) > 1
        ]
        if not pending:
            raise RuntimeError("too few prime fields to cover secret bound")


def recover_flag(documents: Sequence[Document], host: str, port: int, *,
                 timeout=30.0, max_queries=650):
    profile = extract_instance(documents)
    if profile is None:
        raise ValueError("source does not prove a biased Shamir oracle")
    if not 1 <= max_queries <= 10000:
        raise ValueError("invalid interactive share-query budget")
    # Source includes a 30-second alarm; reserve time for final submission.
    budget = min(float(timeout), 27.0)
    if budget <= 0:
        raise ValueError("timeout must be positive")
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(min(timeout, 2.0))
        secret, certificate = recover_secret_from_oracle(
            conn, profile, budget_seconds=budget, max_queries=max_queries,
        )
        # An invalid prime exits the loop. Input for the final guess may
        # already be queued because the server reads line-buffered values.
        conn.sendall(
            b"0\n0\n" + str(secret).encode("ascii") + b"\n"
        )
        output = bytearray()
        final_deadline = time.monotonic() + max(1.0, min(3.0, timeout))
        while len(output) < 65536 and time.monotonic() < final_deadline:
            conn.settimeout(max(.1, min(1.0, final_deadline - time.monotonic())))
            try:
                packet = conn.recv(4096)
            except socket.timeout:
                continue
            if not packet:
                break
            output.extend(packet)
    text = output.decode("utf-8", errors="replace")
    matches = _FLAG.findall(text)
    if len(matches) != 1:
        raise RuntimeError(
            "oracle returned no unique verified flag after CRT recovery: "
            + text[-400:]
        )
    return matches[0]
