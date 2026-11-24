"""Sage hyperelliptic Jacobian state-leak analysis and curve reconstruction.

This is a general capability, NOT a claim that every Jacobian keystream
is predictable: if a chosen plaintext reveals Mumford u/v coefficients,
they disclose evaluations of the (possibly secret) hyperelliptic curve
polynomial via f ≡ v² (mod u). Reconstruct f by modular linear algebra
from several independent, valid divisors.

Source recognition uses a bounded Sage-to-Python grammar adapter and AST
dataflow, not source filenames, CTF strings, or execution of untrusted code.
"""
from __future__ import annotations

import ast
import re
import struct
from dataclasses import dataclass
from typing import Sequence

from .parser import Document

_MAX_SOURCE = 300_000
_SAGE_RING = re.compile(
    r"(?m)^(\s*)([A-Za-z_]\w*)\s*\.\s*<\s*([A-Za-z_]\w*)\s*>\s*"
    r"=\s*GF\s*\(\s*([^)]+?)\s*\)\s*\[\s*\]\s*;?\s*$"
)


@dataclass(frozen=True)
class HyperellipticStreamLeak:
    prime: int
    polynomial_degree_bound: int
    genus: int
    coefficients_per_state: int
    coefficient_bytes: int
    byte_order: str
    coefficient_encoding: str
    known_plaintext_suffix: bytes | None
    chosen_plaintext: bool
    scalar_multiplier_reused_for_flag: int | None

    @property
    def state_bytes(self):
        return self.coefficients_per_state * self.coefficient_bytes


def _sage_tree(text):
    if not text or len(text) > _MAX_SOURCE or "\x00" in text:
        return None
    normalized = _SAGE_RING.sub(
        lambda m: m.group(1) + m.group(2) + " = GF(" +
                  m.group(4) + ")['" + m.group(3) + "']",
        text,
    )
    # Sage ^ is exponentiation; ^^ is XOR. Only transform lexical code
    # tokens (not comments/strings) through Python's tokenizer.
    import io
    import tokenize
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(normalized).readline))
        transformed = []
        for index, token in enumerate(tokens):
            if token.type == tokenize.OP and token.string == "^":
                # Consecutive '^' tokens in Sage represent XOR; leave
                # one caret rather than converting to exponentiation.
                if index + 1 < len(tokens) and tokens[index+1].string == "^":
                    transformed.append(token._replace(string="^"))
                elif index > 0 and tokens[index-1].string == "^":
                    continue
                else:
                    transformed.append(token._replace(string="**"))
            else:
                transformed.append(token)
        return ast.parse(tokenize.untokenize(transformed))
    except (SyntaxError, ValueError, tokenize.TokenError, RecursionError):
        return None


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _call(node, name):
    return isinstance(node, ast.Call) and (
        _name(node.func) == name or
        isinstance(node.func, ast.Attribute) and node.func.attr == name
    )


def _combine_integers(op, a, b):
    if isinstance(op, ast.Add):
        return a + b
    if isinstance(op, ast.Sub):
        return a - b
    if isinstance(op, ast.Pow) and 0 <= b <= 256:
        return a**b
    return None


def _integer(node, assignments, seen=frozenset()):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if (isinstance(node, ast.Name) and node.id in assignments
            and node.id not in seen):
        return _integer(assignments[node.id], assignments, seen | {node.id})
    if isinstance(node, ast.BinOp):
        a = _integer(node.left, assignments, seen)
        b = _integer(node.right, assignments, seen)
        if a is None or b is None:
            return None
        return _combine_integers(node.op, a, b)
    return None


def _poly_degree(node, ring_generator, assignments):
    """Recognize a dense random polynomial whose degree is source-defined."""
    if not _call(node, "sum") or len(node.args) != 1:
        return None
    iterable = node.args[0]
    if not isinstance(iterable, (ast.ListComp, ast.GeneratorExp)):
        return None
    if len(iterable.generators) != 1:
        return None
    loop = iterable.generators[0]
    if not _call(loop.iter, "range") or len(loop.iter.args) != 1:
        return None
    width = _integer(loop.iter.args[0], assignments)
    var = _name(loop.target)
    if width is None or not 3 <= width <= 512 or var is None:
        return None
    # Multiplication of field element and polynomial monomial.
    value = iterable.elt
    if not isinstance(value, ast.BinOp) or not isinstance(value.op, ast.Mult):
        return None
    terms = (value.left, value.right)
    if not any(
        isinstance(term, ast.BinOp) and isinstance(term.op, ast.Pow)
        and _name(term.left) == ring_generator and _name(term.right) == var
        for term in terms
    ):
        return None
    if not any(
        any(_call(call, "randrange") or _call(call, "randbelow")
            for call in ast.walk(term))
        for term in terms
    ):
        return None
    return width - 1


def _xor_generators(tree):
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.GeneratorExp, ast.ListComp)):
            continue
        if not (isinstance(node.elt, ast.BinOp) and
                isinstance(node.elt.op, ast.BitXor) and
                len(node.generators) == 1):
            continue
        loop = node.generators[0]
        if not _call(loop.iter, "zip") or len(loop.iter.args) != 2:
            continue
        iterator, plaintext = loop.iter.args
        if not isinstance(iterator, ast.Call):
            continue
        ctor = _name(iterator.func)
        if ctor is None:
            continue
        found.append((ctor, iterator, plaintext))
    return found


def _chosen_input_names(tree):
    return {
        node.targets[0].id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and any(_call(sub, "input") for sub in ast.walk(node.value))
        and any(_call(sub, "fromhex") for sub in ast.walk(node.value))
    }


def _fixed_seed_of(ctor_call):
    if len(ctor_call.args) == 1 and isinstance(ctor_call.args[0], ast.Constant):
        if type(ctor_call.args[0].value) is int:
            return ctor_call.args[0].value
    return None


def _known_suffix_of(arg):
    suffix = None
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        for value in (arg.left, arg.right):
            if isinstance(value, ast.Constant) and isinstance(value.value, bytes):
                suffix = value.value
    return suffix


def _secret_and_chosen_xor(tree):
    """Verify two plaintext uses of a generator, with attacker-controlled bytes."""
    xor_generators = _xor_generators(tree)
    if len(xor_generators) < 2:
        return None
    chosen_names = _chosen_input_names(tree)
    chosen = [
        (ctor, ctor_call) for ctor, ctor_call, arg in xor_generators
        if _name(arg) in chosen_names and not ctor_call.args
    ]
    if not chosen:
        return None
    for ctor, ctor_call, arg in xor_generators:
        if ctor != chosen[0][0] or not ctor_call.args:
            continue
        suffix = _known_suffix_of(arg)
        if suffix is not None:
            return ctor, _fixed_seed_of(ctor_call), suffix
    return None


def _gf_prime(expr, assignments):
    if _call(expr, "GF") and len(expr.args) == 1:
        p = _integer(expr.args[0], assignments)
        if p and p > 3 and p.bit_length() <= 128:
            return p
    return None


def _field_ring_primes(assignments):
    field_rings = {}
    for name, expr in assignments.items():
        p = _gf_prime(expr, assignments)
        if p is not None:
            field_rings[name] = p
        if isinstance(expr, ast.Subscript):
            p = _gf_prime(expr.value, assignments)
            if p is not None:
                field_rings[name] = p
    return field_rings


def _polynomial_candidates(assignments, generators, field_rings):
    poly = []
    for name, expr in assignments.items():
        for ring_name, variable in generators.items():
            if ring_name not in field_rings:
                continue
            degree = _poly_degree(expr, variable, assignments)
            if degree is not None:
                poly.append((name, degree))
    return poly


def _jacobian_names(assignments, polynomial):
    curve_names = {
        name for name, expr in assignments.items()
        if _call(expr, "HyperellipticCurve") and expr.args
        and _name(expr.args[0]) == polynomial
    }
    if len(curve_names) != 1:
        return None
    curve = next(iter(curve_names))
    return {
        name for name, expr in assignments.items()
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
        and expr.func.attr == "jacobian" and _name(expr.func.value) == curve
    }


def _rng_class(tree, rng_name, jacobians):
    classes = {
        node.name: node for node in tree.body if isinstance(node, ast.ClassDef)
    }
    if rng_name not in classes:
        return None
    rng = classes[rng_name]
    # Trace scalar multiplication through a state update and require an
    # initializer that derives a point from the constructed Jacobian.
    initialized = any(
        isinstance(node, ast.Call) and _name(node.func) in jacobians
        for node in ast.walk(rng)
    )
    scalar_state = any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult)
        and any(isinstance(x, ast.Attribute) for x in (node.left, node.right))
        for node in ast.walk(rng)
    )
    if not initialized or not scalar_state:
        return None
    return rng


def _pack_signature(call):
    if not _call(call, "pack") or len(call.args) < 2:
        return None
    fmt = call.args[0]
    # Sage often constructs struct formats via concatenation.
    if not isinstance(fmt, ast.BinOp) or not isinstance(fmt.op, ast.Add):
        return None
    left, right = fmt.left, fmt.right
    if not (isinstance(left, ast.Constant)
            and isinstance(left.value, str)
            and left.value in ("<", ">")):
        return None
    if not (isinstance(right, ast.BinOp)
            and isinstance(right.op, ast.Mult)):
        return None
    if not (isinstance(right.left, ast.Constant)
            and right.left.value in ("Q", "I", "H", "B")
            and isinstance(right.right, ast.Call)
            and _call(right.right, "len")):
        return None
    # Extract u,v coefficient output by tracing a two-list
    # concatenation rather than requiring variable identifiers.
    output_vars = [_name(arg.value) for arg in call.args[1:]
                   if isinstance(arg, ast.Starred)]
    if len(output_vars) != 1 or output_vars[0] is None:
        return None
    return (left.value, right.left.value, output_vars[0])


def _serialized_signature(rng):
    funcs = [node for node in rng.body if isinstance(node, ast.FunctionDef)]
    serialized = [
        signature for fn in funcs for call in ast.walk(fn)
        if (signature := _pack_signature(call)) is not None
    ]
    return serialized[0] if len(serialized) == 1 else None


def _list_range(node, assignments):
    if len(node.generators) != 1:
        return None
    loop = node.generators[0]
    if not _call(loop.iter, "range") or len(loop.iter.args) != 1:
        return None
    return _integer(loop.iter.args[0], assignments)


def _coefficient_widths_match(rng, output_name, genus, assignments):
    coeff_lists = [
        stmt for stmt in ast.walk(rng)
        if isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and _name(stmt.targets[0]) == output_name
        and isinstance(stmt.value, ast.BinOp)
        and isinstance(stmt.value.op, ast.Add)
        and isinstance(stmt.value.left, ast.ListComp)
        and isinstance(stmt.value.right, ast.ListComp)
    ]
    if len(coeff_lists) != 1:
        return False
    width = _list_range(coeff_lists[0].value.left, assignments)
    width2 = _list_range(coeff_lists[0].value.right, assignments)
    return width == genus and width2 == genus


def _source_profile(document):
    tree = _sage_tree(document.text)
    if tree is None:
        return None
    assignments = {
        target.id: stmt.value
        for stmt in tree.body if isinstance(stmt, ast.Assign)
        for target in stmt.targets if isinstance(target, ast.Name)
    }
    field_rings = _field_ring_primes(assignments)
    if len(field_rings) != 1:
        return None
    _, prime = next(iter(field_rings.items()))
    generators = {
        match.group(2): match.group(3)
        for match in _SAGE_RING.finditer(document.text)
    }
    poly = _polynomial_candidates(assignments, generators, field_rings)
    if len(poly) != 1:
        return None
    polynomial, degree = poly[0]
    if degree % 2 != 1 or degree < 5:
        return None
    jacobians = _jacobian_names(assignments, polynomial)
    if not jacobians:
        return None
    plaintext_uses = _secret_and_chosen_xor(tree)
    if plaintext_uses is None:
        return None
    rng_name, fixed_seed, suffix = plaintext_uses
    rng = _rng_class(tree, rng_name, jacobians)
    if rng is None:
        return None
    signature = _serialized_signature(rng)
    if signature is None:
        return None
    order, primitive, output_name = signature
    genus = (degree - 1)//2
    if not _coefficient_widths_match(rng, output_name, genus, assignments):
        return None
    return HyperellipticStreamLeak(
        prime=prime, polynomial_degree_bound=degree,
        genus=genus, coefficients_per_state=2*genus,
        coefficient_bytes=struct.calcsize(primitive),
        byte_order="little" if order == "<" else "big",
        coefficient_encoding=primitive,
        known_plaintext_suffix=suffix,
        chosen_plaintext=True,
        scalar_multiplier_reused_for_flag=fixed_seed,
    )


def extract_instance(documents: Sequence[Document]):
    models = [
        model for doc in documents
        if (model := _source_profile(doc)) is not None
    ]
    return models[0] if len(models) == 1 else None


def unpack_state(data: bytes, model: HyperellipticStreamLeak):
    """Parse a fully exposed Mumford pair, never silently truncate."""
    if len(data) < model.state_bytes:
        raise ValueError("not enough complete coefficient bytes")
    if model.coefficient_encoding not in ("Q", "I", "H", "B"):
        raise ValueError("unsupported pack format")
    fmt = ("<" if model.byte_order == "little" else ">")
    values = struct.unpack(
        fmt+model.coefficient_encoding*model.coefficients_per_state,
        data[:model.state_bytes],
    )
    if any(coefficient >= model.prime for coefficient in values):
        raise ValueError("coefficient not in source-defined field")
    g = model.genus
    return list(values[:g])+[1], list(values[g:])


def _polynomial_remainder(polynomial, divisor, p):
    if divisor[-1] != 1:
        raise ValueError("expected a monic Mumford divisor")
    result = list(polynomial)
    for i in range(len(result)-1, len(divisor)-2, -1):
        factor = result[i] % p
        if factor:
            for j in range(len(divisor)):
                result[i-len(divisor)+1+j] -= factor*divisor[j]
    # The remainder is a fixed-width coefficient vector of degree < deg(u).
    # Basis monomials of lower degree still need explicit trailing zeros.
    return [
        int(result[index] % p) if index < len(result) else 0
        for index in range(len(divisor)-1)
    ]


def _divisor_equations(observations, model):
    p = model.prime
    degree = model.polynomial_degree_bound
    genus = model.genus
    equations = []
    for u, v in observations:
        if len(u) != genus+1 or len(v) != genus or u[-1] != 1:
            raise ValueError("inconsistent Mumford polynomial dimensions")
        square = [0]*(2*genus-1)
        for i,a in enumerate(v):
            for j,b in enumerate(v):
                square[i+j] += a*b
        residue = _polynomial_remainder(square, u, p)
        basis = [
            _polynomial_remainder([0]*j+[1], u, p)
            for j in range(degree+1)
        ]
        for index in range(genus):
            equations.append([
                basis[j][index] for j in range(degree+1)
            ] + [residue[index]])
    return equations


def _reduce_equations(equations, unknowns, p):
    rank = 0
    for column in range(unknowns):
        pivot = next((i for i in range(rank, len(equations))
                      if equations[i][column] % p), None)
        if pivot is None:
            raise RuntimeError("insufficient independent divisors for curve reconstruction")
        equations[rank], equations[pivot] = equations[pivot], equations[rank]
        inverse = pow(equations[rank][column], -1, p)
        equations[rank] = [
            entry*inverse % p for entry in equations[rank]
        ]
        for row in range(len(equations)):
            if row == rank:
                continue
            factor = equations[row][column]
            if factor:
                equations[row] = [
                    (current-factor*lead) % p
                    for current,lead in zip(equations[row], equations[rank])
                ]
        rank += 1
    return rank


def curve_from_divisors(observations, model: HyperellipticStreamLeak):
    """Reconstruct f in y²=f(x) from f≡v² (mod u), with consistency check.

    Observations can come from independent chosen-plaintext sessions.
    Rank-deficient systems return a clear error, not arbitrary free vars.
    """
    p = model.prime
    equations = _divisor_equations(observations, model)
    unknowns = model.polynomial_degree_bound+1
    if len(equations) < unknowns:
        raise ValueError("too few independent coefficient constraints")
    rank = _reduce_equations(equations, unknowns, p)
    if any(
        not any(row[:unknowns]) and row[unknowns] % p
        for row in equations[rank:]
    ):
        raise RuntimeError("inconsistent divisors cannot share one curve")
    answer = tuple(equations[i][unknowns] for i in range(unknowns))
    if any(_polynomial_remainder(answer, u, p) !=
           _polynomial_remainder(
               [sum(v[j]*v[k-j] for j in range(len(v))
                    if 0 <= k-j < len(v))
                for k in range(2*len(v)-1)], u, p)
           for u,v in observations):
        raise RuntimeError("curve polynomial fails Mumford congruence verification")
    return answer
