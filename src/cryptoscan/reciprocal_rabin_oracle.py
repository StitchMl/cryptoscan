"""Chosen-ciphertext CRT inconsistency attack on reciprocal Rabin encryption.

In a reciprocal Rabin construction r = m + c/m (mod n), decryption
solves X^2-rX+c separately modulo each RSA prime and combines roots
using CRT. If a faulty root solver returns a plausible but incorrect
root when the quadratic has no root in one field, re-encryption may
produce several distinct r' values for the *same supplied r*.

Each difference r'_i-r'_j is divisible by the prime component where
the reconstruction was consistent. Pairwise GCDs of independent
differences recover the formerly hidden RSA primes. The unknown public
parameter c then follows from two re-encryption residues modulo each
recovered prime:
    x+y = r, A = x+c/x, B = y+c/y
    (2*r-A-B)*x = r*(r-B) mod p
    c = A*x-x^2 mod p.

This model neither stores challenge values nor executes source text.
The only online action is an explicitly authorized CTF TCP oracle.
"""
from __future__ import annotations

import ast
import math
import re
import socket
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .source_units import parse_python

_MAX_SOURCE = 500_000
_TRIPLE = re.compile(
    rb"(?m)^[ \t]*([A-Za-z_]\w*)\s*=\s*([+-]?\d+)\s*$"
)
_FLAG = re.compile(rb"^[A-Za-z][A-Za-z0-9_]{1,39}\{[^{}\r\n]{1,256}\}")


@dataclass(frozen=True)
class ReciprocalRabinOracle:
    factor_bits: int
    ciphertext_labels: tuple[str, str, str]
    input_prompt: str
    ciphertext_header: str
    result_header: str
    failure_marker: str
    input_separator: str = ","


@dataclass(frozen=True)
class OracleResult:
    modulus: int
    factors: tuple[int, int]
    reciprocal_constant: int
    plaintext: bytes
    secret: str
    probes: int


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _member(node):
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id, node.attr
    return None


def _calls(node, name):
    return [
        x for x in ast.walk(node)
        if isinstance(x, ast.Call)
        and (_name(x.func) == name or
             isinstance(x.func, ast.Attribute) and x.func.attr == name)
    ]


def _jacobi_call_sites(tree):
    """Accept genuine Jacobi routines through resolved library imports.

    A source may define a function called 'jacobi' that always returns 1.
    Its name is not evidence of the disambiguation bit. Resolve either
    gmpy2.jacobi or sympy.jacobi_symbol (including import aliases).
    """
    functions = set()
    modules = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            if statement.module not in ("gmpy2", "sympy"):
                continue
            canonical = "jacobi" if statement.module == "gmpy2" else "jacobi_symbol"
            for alias in statement.names:
                if alias.name == canonical:
                    functions.add(alias.asname or alias.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name in ("gmpy2", "sympy"):
                    modules[alias.asname or alias.name] = alias.name

    rebound = set()
    for stmt in ast.walk(tree):
        if isinstance(stmt, (ast.FunctionDef, ast.ClassDef)):
            rebound.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            rebound.update(
                node.id for target in stmt.targets
                for node in ast.walk(target) if isinstance(node, ast.Name)
            )
    functions -= rebound
    modules = {
        alias: library for alias, library in modules.items()
        if alias not in rebound
    }

    def jacobi_calls(section):
        for call in ast.walk(section):
            if not isinstance(call, ast.Call) or len(call.args) != 2:
                continue
            if _name(call.func) in functions:
                yield call
            elif isinstance(call.func, ast.Attribute):
                base = _name(call.func.value)
                actual = modules.get(base)
                expected = ("jacobi" if actual == "gmpy2"
                            else "jacobi_symbol" if actual == "sympy" else None)
                if actual and call.func.attr == expected:
                    yield call
    return jacobi_calls


def _flatten_binop(node, operation):
    if isinstance(node, ast.BinOp) and isinstance(node.op, operation):
        return (_flatten_binop(node.left, operation)
                + _flatten_binop(node.right, operation))
    return [node]


def _resolved(node, definitions, *, seen=frozenset(), limit=12):
    """Bounded symbolic expansion of simple expression aliases.

    Only AST assignments are inspected; no user source is evaluated.
    Reject cycles and ambiguous reassignments instead of guessing.
    """
    if limit <= 0:
        return node
    if isinstance(node, ast.Name) and node.id in definitions:
        if node.id in seen or definitions[node.id] is None:
            return node
        return _resolved(definitions[node.id], definitions,
                         seen=seen | {node.id}, limit=limit-1)
    if isinstance(node, ast.BinOp):
        return ast.BinOp(
            left=_resolved(node.left, definitions, seen=seen, limit=limit-1),
            op=node.op,
            right=_resolved(node.right, definitions, seen=seen, limit=limit-1),
        )
    if isinstance(node, ast.Call):
        return ast.Call(
            func=node.func,
            args=[_resolved(arg, definitions, seen=seen, limit=limit-1)
                  for arg in node.args],
            keywords=node.keywords,
        )
    return node


def _simple_definitions(function):
    assignments = {}
    for statement in function.body:
        if (isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)):
            name = statement.targets[0].id
            if name in assignments:
                assignments[name] = None
            else:
                assignments[name] = statement.value
        elif isinstance(statement, ast.AugAssign) and isinstance(
                statement.target, ast.Name):
            assignments[statement.target.id] = None
    return assignments


def _inverse_calls(tree):
    """Resolve verified modular-inverse library imports and aliases.

    Neither arbitrary user functions named 'inverse' nor arbitrary
    attributes named 'invert' are trusted.
    """
    recognized = {
        ("gmpy2", "invert"),
        ("sympy", "mod_inverse"),
        ("Crypto.Util.number", "inverse"),
    }
    direct = set()
    modules = {}
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            for alias in statement.names:
                if (statement.module, alias.name) in recognized:
                    direct.add(alias.asname or alias.name)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name in ("gmpy2", "sympy", "Crypto.Util.number"):
                    modules[alias.asname or alias.name] = alias.name
    # Imported helpers can be rebound later in the source. A name that
    # is overwritten is not a proof of a mathematical library operation.
    rebound = set()
    for statement in ast.walk(tree):
        if isinstance(statement, (ast.FunctionDef, ast.ClassDef)):
            rebound.add(statement.name)
        elif isinstance(statement, ast.Assign):
            rebound.update(
                node.id for target in statement.targets
                for node in ast.walk(target) if isinstance(node, ast.Name)
            )
        elif isinstance(statement, ast.AnnAssign) and isinstance(
                statement.target, ast.Name):
            rebound.add(statement.target.id)
    direct -= rebound
    modules = {
        alias: actual for alias, actual in modules.items()
        if alias not in rebound
    }
    return direct, modules, recognized


def _is_inverse(node, message, modulus, imports):
    """Recognize modular inverses without executing user code."""
    if not isinstance(node, ast.Call):
        return False
    direct, modules, recognized = imports
    if (_name(node.func) == "pow" and len(node.args) == 3
            and _name(node.args[0]) == message):
        exponent = node.args[1]
        is_minus_one = (isinstance(exponent, ast.UnaryOp)
                        and isinstance(exponent.op, ast.USub)
                        and isinstance(exponent.operand, ast.Constant)
                        and exponent.operand.value == 1)
        return is_minus_one and ast.dump(node.args[2]) == ast.dump(modulus)
    if len(node.args) != 2 or _name(node.args[0]) != message:
        return False
    if ast.dump(node.args[1]) != ast.dump(modulus):
        return False
    if _name(node.func) in direct:
        return True
    if isinstance(node.func, ast.Attribute):
        base = _name(node.func.value)
        if base in modules and (modules[base], node.func.attr) in recognized:
            return True
    return False


def _reciprocal_encryption(tree):
    """Recognize algebraically equivalent reciprocal encryption expressions.

    Normalize bounded temporary assignments and associativity/commutation
    in additions and products. The Jacobi and order-bit evidence remains
    mandatory and must bind to the actual message and modulus.
    """
    jacobi_calls = _jacobi_call_sites(tree)
    inversion_imports = _inverse_calls(tree)
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef) or len(fn.args.args) < 2:
            continue
        message = fn.args.args[0].arg
        defs = _simple_definitions(fn)
        expressions = [
            _resolved(node, defs)
            for node in ast.walk(fn)
            if isinstance(node, (ast.BinOp, ast.Name))
        ]
        for expression in expressions:
            if not (isinstance(expression, ast.BinOp)
                    and isinstance(expression.op, ast.Mod)):
                continue
            modulus = expression.right
            n_field = _member(modulus)
            if n_field is None:
                continue
            additions = _flatten_binop(expression.left, ast.Add)
            if len(additions) != 2:
                continue
            if _name(additions[0]) == message:
                reciprocal = additions[1]
            elif _name(additions[1]) == message:
                reciprocal = additions[0]
            else:
                continue
            factors = _flatten_binop(reciprocal, ast.Mult)
            if len(factors) != 2:
                continue
            inverses = [
                factor for factor in factors
                if _is_inverse(factor, message, modulus, inversion_imports)
            ]
            if len(inverses) != 1:
                continue
            constant = next(factor for factor in factors
                            if factor is not inverses[0])
            c_field = _member(constant)
            if c_field is None or c_field[0] != n_field[0]:
                continue
            if not any(
                _name(call.args[0]) == message
                and ast.dump(call.args[1]) == ast.dump(modulus)
                for call in jacobi_calls(fn)
            ):
                continue
            # The companion bit must distinguish a comparison involving
            # the message; the inverse expression may be a temporary.
            if not any(
                isinstance(node, ast.Compare)
                and any(isinstance(op, (ast.Lt, ast.Gt))
                        for op in node.ops)
                and any(_name(x) == message
                        for x in [node.left, *node.comparators])
                for node in ast.walk(fn)
            ):
                continue
            return fn.name, n_field[1], c_field[1]
    return None


def _crt_functions(tree):
    """Identify algebraic CRT from residue and modulus dataflow.

    A mere 'something % (p*q)' is not sufficient evidence. Both
    residues and both moduli must contribute, and the function must
    use extended GCD or a modular inverse to combine congruences.
    This recognizes standard arithmetic variants without using names.
    """
    result = set()
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef) or len(fn.args.args) != 4:
            continue
        args = {arg.arg for arg in fn.args.args}
        for node in ast.walk(fn):
            if not (
                isinstance(node, ast.BinOp)
                and isinstance(node.op, ast.Mod)
                and isinstance(node.right, ast.BinOp)
                and isinstance(node.right.op, ast.Mult)
                and (left_mod := _name(node.right.left)) in args
                and (right_mod := _name(node.right.right)) in args
                and left_mod != right_mod
            ):
                continue
            residues = args - {left_mod, right_mod}
            numerator_names = {
                child.id for child in ast.walk(node.left)
                if isinstance(child, ast.Name)
            }
            if not residues.issubset(numerator_names):
                continue
            inverse = any(
                (isinstance(call, ast.Call)
                 and isinstance(call.func, ast.Attribute)
                 and call.func.attr == "gcdext")
                or (isinstance(call, ast.Call)
                    and _name(call.func) == "pow"
                    and len(call.args) == 3
                    and isinstance(call.args[1], ast.UnaryOp)
                    and isinstance(call.args[1].op, ast.USub)
                    and isinstance(call.args[1].operand, ast.Constant)
                    and call.args[1].operand.value == 1)
                for call in ast.walk(fn)
            )
            if inverse:
                result.add(fn.name)
    return result


def _quotient_quadratic_solver(fn):
    """Source-proof the specific root extraction identity used by the fault.

    Do not confuse any modular inverse and two-value return with an
    implementation of a quadratic solver. The faulty extraction computes
    x = -(v[0]-1)/v[1] modulo p after exponentiation by (p-1)//2 in the
    polynomial quotient, and returns x alongside the complementary r-x.
    The surrounding code must also use both polynomial parameters in
    arithmetic. Other root algorithms require separate recognizers.
    """
    if not isinstance(fn, ast.FunctionDef) or len(fn.args.args) < 3:
        return False
    r, c, p = (arg.arg for arg in fn.args.args[:3])
    calls = [
        node for node in ast.walk(fn)
        if isinstance(node, ast.Call) and _name(node.func) == "pow"
        and len(node.args) == 3 and _name(node.args[2]) == p
        and isinstance(node.args[1], ast.UnaryOp)
        and isinstance(node.args[1].op, ast.USub)
        and isinstance(node.args[1].operand, ast.Constant)
        and node.args[1].operand.value == 1
        and isinstance(node.args[0], ast.Subscript)
        and isinstance(node.args[0].value, ast.Name)
        and isinstance(node.args[0].slice, ast.Constant)
        and node.args[0].slice.value == 1
    ]
    if len(calls) != 1:
        return False
    state_name = node_name = _name(calls[0].args[0].value)
    power = any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.FloorDiv)
        and isinstance(node.left, ast.BinOp)
        and isinstance(node.left.op, ast.Sub)
        and _name(node.left.left) == p
        and isinstance(node.left.right, ast.Constant)
        and node.left.right.value == 1
        and isinstance(node.right, ast.Constant)
        and node.right.value == 2
        for node in ast.walk(fn)
    )
    if not power:
        return False
    # Require the same quotient-ring coefficient vector in the numerator
    # of the root formula and in its inverse denominator.
    coefficient_zero = any(
        isinstance(node, ast.Subscript)
        and _name(node.value) == state_name
        and isinstance(node.slice, ast.Constant)
        and node.slice.value == 0
        for node in ast.walk(fn)
    )
    if not coefficient_zero:
        return False
    # Reject unrelated modular inverse routines by checking the root-sum
    # relationship in both the returned pair and the function's equations.
    final_return = [
        node for node in fn.body
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Tuple)
        and len(node.value.elts) == 2
        and all(isinstance(item, ast.Name) for item in node.value.elts)
    ]
    if len(final_return) != 1:
        return False
    root, complement = (_name(item) for item in final_return[0].value.elts)
    # Root-validation guards can prevent a faulty component from ever
    # reaching CRT and therefore invalidate this attack's precondition.
    # Reject when the root is used in a post-computation assertion or an
    # explicit failing control-flow branch.
    root_assignments = [
        stmt for stmt in fn.body
        if isinstance(stmt, ast.Assign)
        and any(_name(target) == root for target in stmt.targets)
    ]
    if len(root_assignments) != 1:
        return False
    root_line = root_assignments[0].lineno
    for statement in ast.walk(fn):
        if getattr(statement, "lineno", 0) <= root_line:
            continue
        if isinstance(statement, ast.Assert) and any(
            isinstance(child, ast.Name) and child.id == root
            for child in ast.walk(statement.test)
        ):
            return False
        if isinstance(statement, ast.If) and any(
            isinstance(child, ast.Name) and child.id == root
            for child in ast.walk(statement.test)
        ) and any(
            isinstance(child, (ast.Raise, ast.Return))
            for branch in statement.body for child in ast.walk(branch)
        ):
            return False
    complementary = any(
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and _name(node.targets[0]) == complement
        and isinstance(node.value, ast.BinOp)
        and isinstance(node.value.op, ast.Mod)
        and _name(node.value.right) == p
        and isinstance(node.value.left, ast.BinOp)
        and isinstance(node.value.left.op, ast.Sub)
        and _name(node.value.left.left) == r
        and _name(node.value.left.right) == root
        for node in fn.body
    )
    # A proper quotient-field multiplication/reduction must involve both
    # coefficients of X**2-rX+c, not simply a formal inverse.
    uses_r = any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult)
        and (_name(node.left) == r or _name(node.right) == r)
        for node in ast.walk(fn)
    )
    uses_c = any(
        isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult)
        and (_name(node.left) == c or _name(node.right) == c)
        for node in ast.walk(fn)
    )
    return complementary and uses_r and uses_c


def _quadratic_decrypt(tree, encryption):
    """Match a CRT combination of independently inverted quadratic roots.

    The implementation may use a hand-written quotient-ring exponentiation
    instead of a literal x**2 in source: accept the inverse of the linear
    coefficient and the complementary root r-a, then verify two private
    prime calls and CRT in the surrounding decryptor.
    """
    solver_names = set()
    jacobi_calls = _jacobi_call_sites(tree)
    crt_names = _crt_functions(tree)
    if not crt_names:
        return None
    for fn in tree.body:
        if _quotient_quadratic_solver(fn):
            solver_names.add(fn.name)
    if not solver_names:
        return None
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef) or fn.name == encryption:
            continue
        invoked = [
            node for node in ast.walk(fn)
            if isinstance(node, ast.Call)
            and _name(node.func) in solver_names
        ]
        if len(invoked) < 2:
            continue
        moduli = {
            member for call in invoked for arg in call.args
            if (member := _member(arg)) is not None
        }
        invokes_crt = any(
            isinstance(call, ast.Call)
            and _name(call.func) in crt_names
            for call in ast.walk(fn)
        )
        if (len(moduli) >= 2 and invokes_crt
                and any(jacobi_calls(fn))):
            return fn.name
    return None


def _protocol_profile(tree, encrypt, decrypt):
    for loop in ast.walk(tree):
        if not isinstance(loop, ast.While):
            continue
        prompts = [
            node.args[0].value for node in ast.walk(loop)
            if isinstance(node, ast.Call) and _name(node.func) == "input"
            and len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ]
        if len(set(prompts)) != 1:
            continue
        # Derive the source's input wire representation rather than
        # assuming comma-separated triples. Fail closed for unfamiliar
        # parsing or inconsistent delimiters.
        separators = set()
        for call in ast.walk(loop):
            if not (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "split"):
                continue
            if not (len(call.args) in (0, 1)
                    and (not call.args or isinstance(
                        call.args[0], ast.Constant))):
                continue
            separator = (
                call.args[0].value if call.args else " "
            )
            if (isinstance(separator, str) and len(separator) == 1
                    and separator in {",", ";", " ", "|", ":"}):
                separators.add(separator)
        if len(separators) != 1:
            continue
        separator = next(iter(separators))
        nested = [
            call for call in ast.walk(loop)
            if isinstance(call, ast.Call)
            and _name(call.func) == encrypt
            and call.args and isinstance(call.args[0], ast.Call)
            and _name(call.args[0].func) == decrypt
        ]
        if not nested:
            continue
        prints = [
            node.args[0].value for node in ast.walk(loop)
            if isinstance(node, ast.Call) and _name(node.func) == "print"
            and len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ]
        # Exception marker identity comes from the exception-handler
        # control-flow branch, never from English words in the message.
        failure_texts = {
            arg.value
            for handler in ast.walk(loop)
            if isinstance(handler, ast.ExceptHandler)
            for call in ast.walk(handler)
            if isinstance(call, ast.Call) and _name(call.func) == "print"
            for arg in call.args
            if isinstance(arg, ast.Constant)
            and isinstance(arg.value, str)
        }
        if len(failure_texts) != 1:
            continue
        marker = next(iter(failure_texts))
        success = [value for value in prints if value != marker]
        if len(success) != 1:
            continue
        # Some services put their banner directly at module scope;
        # others guard startup under if __name__ == "__main__".
        # The relevant invariant is that the banner is printed outside
        # the interactive oracle loop.
        loop_nodes = {id(node) for node in ast.walk(loop)}
        banners = [
            call.args[0].value for call in ast.walk(tree)
            if id(call) not in loop_nodes
            and isinstance(call, ast.Call) and _name(call.func) == "print"
            and len(call.args) == 1
            and isinstance(call.args[0], ast.Constant)
            and isinstance(call.args[0].value, str)
        ]
        banners = [s for s in banners if s not in prints]
        if len(banners) != 1:
            continue
        return prompts[0], banners[0], success[0], marker, separator
    return None


def _source_profile(document):
    if not document.text or len(document.text) > _MAX_SOURCE:
        return None
    tree = parse_python(document)
    if tree is None:
        return None
    encryption = _reciprocal_encryption(tree)
    if encryption is None:
        return None
    encrypt, modulus_field, constant_field = encryption
    if _quadratic_decrypt(tree, encrypt) is None:
        return None
    decrypt = _quadratic_decrypt(tree, encrypt)
    protocol = _protocol_profile(tree, encrypt, decrypt)
    if protocol is None:
        return None
    definitions = {}
    for stmt in ast.walk(tree):
        if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and isinstance(stmt.value, ast.Constant)
                and type(stmt.value.value) is int):
            definitions[stmt.targets[0].id] = stmt.value.value
    functions = {
        fn.name: fn for fn in tree.body if isinstance(fn, ast.FunctionDef)
    }
    # Resolve generator bit length across arbitrary finite chains of wrapper
    # functions and positional arguments. This is symbolic source dataflow,
    # never execution of the user's Python.
    bits = None
    for fn in functions.values():
        if not _calls(fn, "getPrime"):
            continue
        parameters = [arg.arg for arg in fn.args.args]
        prime_widths = [
            call.args[0] for call in _calls(fn, "getPrime") if call.args
        ]
        if not prime_widths or len({
                ast.dump(value) for value in prime_widths
        }) != 1:
            continue
        width = prime_widths[0]
        if isinstance(width, ast.Constant) and type(width.value) is int:
            bits = width.value
            break
        parameter = _name(width)
        if parameter not in parameters:
            continue
        current_function = fn.name
        parameter_index = parameters.index(parameter)
        for _ in range(5):
            calls = [
                call for call in ast.walk(tree)
                if isinstance(call, ast.Call)
                and _name(call.func) == current_function
                and len(call.args) > parameter_index
            ]
            if len(calls) == 0:
                break
            arguments = [call.args[parameter_index] for call in calls]
            values = [
                arg.value if isinstance(arg, ast.Constant) else
                definitions.get(_name(arg))
                for arg in arguments
            ]
            numbers = [
                value for value in values
                if type(value) is int
            ]
            if numbers and len(set(numbers)) == 1:
                bits = numbers[0]
                break
            # Follow a name forwarded from an enclosing function.
            names = {_name(arg) for arg in arguments}
            if len(names) != 1 or None in names:
                break
            forward = next(iter(names))
            owners = [
                owner for owner in functions.values()
                if forward in [arg.arg for arg in owner.args.args]
                and any(child is calls[0] for child in ast.walk(owner))
            ]
            if len(owners) != 1:
                break
            owner = owners[0]
            current_function = owner.name
            parameter_index = [arg.arg for arg in owner.args.args].index(forward)
        if bits is not None:
            break
    if bits is None or not isinstance(bits, int) or not 16 <= bits <= 4096:
        return None
    # The source must generate odd primes in a known congruence class.
    if not any(
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.BinOp)
        and isinstance(node.left.op, ast.Mod)
        and isinstance(node.left.right, ast.Constant)
        and node.left.right.value == 4
        and any(isinstance(comparator, ast.Constant)
                and comparator.value == 3
                for comparator in node.comparators)
        for node in ast.walk(tree)
    ):
        return None
    # Follow the encryption function's *constructed* ciphertext type.
    # Unrelated three-field records are not evidence of an output schema.
    classes = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            fields = [
                stmt.target.id for stmt in node.body
                if isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
            ]
            if len(fields) == 3:
                classes[node.name] = tuple(fields)
    encrypt_fn = next(
        fn for fn in tree.body
        if isinstance(fn, ast.FunctionDef) and fn.name == encrypt
    )
    output_types = {
        _name(call.func) for call in ast.walk(encrypt_fn)
        if isinstance(call, ast.Call)
        and _name(call.func) in classes
    }
    if len(output_types) != 1:
        return None
    ciphertext_class = next(iter(output_types))
    return ReciprocalRabinOracle(
        bits, classes[ciphertext_class], protocol[0], protocol[1],
        protocol[2], protocol[3], protocol[4],
    )


def extract_instance(documents: Sequence[Document]):
    models = [
        profile for doc in documents
        if (profile := _source_profile(doc)) is not None
    ]
    return models[0] if len(models) == 1 else None


def _records_to_factors(records, minimum_factor_bits):
    from sympy import isprime
    # Any two distinct successful selector responses give a candidate
    # difference. Do not require precisely two distinct outputs or
    # demand success from every selector combination.
    deltas = [
        abs(a-b) for _, outputs in records if len(outputs) >= 2
        for i, a in enumerate(sorted(outputs))
        for b in sorted(outputs)[i+1:] if a != b
    ]
    factors = set()
    # Repeated independent deltas share the hidden prime, with
    # accidental small co-factors removed by intersection.
    for i, left in enumerate(deltas):
        for right in deltas[i+1:]:
            factor = math.gcd(left, right)
            if factor.bit_length() < minimum_factor_bits:
                continue
            if isprime(factor):
                factors.add(factor)
            if len(factors) >= 2:
                primes = sorted(factors)
                if primes[0] != primes[1]:
                    return tuple(primes[:2])
    return None


def _recover_constant(records, factors):
    p, q = factors
    n = p*q
    residues = {}
    for r, values in records:
        values = sorted(values)
        for index, A in enumerate(values):
            for B in values[index+1:]:
                shared = math.gcd(abs(A-B), n)
                if shared not in (p,q):
                    continue
                target = n//shared
                denominator = (2*r-A-B) % target
                if math.gcd(denominator, target) != 1:
                    continue
                x = (r*(r-B)*pow(denominator, -1, target)) % target
                c = (A*x-x*x) % target
                residues.setdefault(target, []).append(c)
    if not all(prime in residues for prime in factors):
        return None
    chosen = {}
    for prime in factors:
        counts = {}
        for residue in residues[prime]:
            counts[residue] = counts.get(residue, 0) + 1
        ordered = sorted(counts, key=lambda value: (-counts[value], value))
        if not ordered:
            return None
        # At least two independently obtained observations must agree.
        if counts[ordered[0]] < 2:
            return None
        chosen[prime] = ordered[0]
    return (
        chosen[p] + p*((chosen[q]-chosen[p])*pow(p,-1,q)%q)
    ) % n


def _jacobi(a, modulus):
    if modulus < 3 or modulus % 2 == 0:
        raise ValueError("Jacobi modulus must be odd")
    result = 1
    a %= modulus
    while a:
        while not a % 2:
            a //= 2
            if modulus % 8 in (3,5):
                result = -result
        a, modulus = modulus, a
        if a % 4 == modulus % 4 == 3:
            result = -result
        a %= modulus
    return result if modulus == 1 else 0


def _encrypt(m, n, c):
    if not 0 < m < n or math.gcd(m,n) != 1:
        return None
    reciprocal = c*pow(m,-1,n) % n
    return ((m+reciprocal)%n, _jacobi(m,n), int(reciprocal < m))


def _decrypt_candidates(ciphertext, p, q, c):
    """CRT four quadratic roots; verify every candidate by re-encryption."""
    n = p*q
    r, s, t = ciphertext
    from sympy import sqrt_mod
    roots = []
    for prime in (p,q):
        discr = (r*r-4*c) % prime
        value = sqrt_mod(discr, prime)
        if value is None:
            return []
        inv2 = pow(2,-1,prime)
        roots.append(tuple(set(((r+int(value))*inv2 % prime,
                                (r-int(value))*inv2 % prime))))
    candidates = []
    for a in roots[0]:
        for b in roots[1]:
            m = (a + p*((b-a)*pow(p,-1,q)%q)) % n
            if _encrypt(m,n,c) == ciphertext:
                candidates.append(m)
    return sorted(set(candidates))


def _decode_flag(m):
    raw = m.to_bytes((m.bit_length()+7)//8, "big")
    # The source may append random bytes to the plaintext. Only the
    # complete ASCII marker is interpreted as a flag.
    found = _FLAG.match(raw)
    if found is None:
        raise RuntimeError("recovered integer has no leading verified CTF flag")
    return found.group().decode("ascii"), raw


class TextOracle:
    """Bounded prompt-driven TCP adapter for triple ciphertext responses."""
    def __init__(self, conn, profile):
        self.conn = conn
        self.profile = profile
        self.buffer = b""
        self.probes = 0

    def _until_prompt(self):
        marker = self.profile.input_prompt.encode()
        while marker not in self.buffer:
            if len(self.buffer) > 65536:
                raise RuntimeError("oversized oracle response")
            packet = self.conn.recv(8192)
            if not packet:
                raise ConnectionError("oracle session closed")
            self.buffer += packet
        before, self.buffer = self.buffer.split(marker, 1)
        return before

    def initial(self):
        banner = self._until_prompt()
        if self.profile.ciphertext_header.encode() not in banner:
            raise RuntimeError("missing source-defined initial ciphertext header")
        return self._triple(banner)

    def _triple(self, data):
        """Decode named integer records without evaluating remote strings.

        Supports one-field-per-line output, Python dataclass repr, and
        JSON / Python mapping style records. Ambiguous values are rejected.
        """
        if len(data) > 65536:
            raise ValueError("oversized ciphertext record")
        labels = self.profile.ciphertext_labels
        observed = {}
        for name in labels:
            token = re.escape(name.encode("ascii"))
            pattern = (
                rb"(?<![A-Za-z0-9_])(?:[\"']" + token
                + rb"[\"']|" + token
                + rb")\s*[:=]\s*([+-]?[0-9]+)(?![0-9])"
            )
            matches = re.findall(pattern, data)
            if len(matches) != 1:
                raise ValueError(
                    f"missing or ambiguous ciphertext attribute {name}"
                )
            observed[name] = int(matches[0])
        return tuple(observed[label] for label in labels)

    def query(self, r,s,t):
        delimiter = self.profile.input_separator
        self.conn.sendall(f"{r}{delimiter}{s}{delimiter}{t}\n".encode())
        self.probes += 1
        message = self._until_prompt()
        if self.profile.failure_marker.encode() in message:
            return None
        if self.profile.result_header.encode() not in message:
            raise RuntimeError("unexpected oracle response")
        return self._triple(message)


def recover_details(documents, host, port, *, timeout=30.0, max_queries=320):
    profile = extract_instance(documents)
    if profile is None:
        raise ValueError("source does not establish reciprocal Rabin CRT oracle")
    if not 8 <= max_queries <= 2048:
        raise ValueError("unsupported chosen-ciphertext query budget")
    records = []
    with socket.create_connection((host,port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        oracle = TextOracle(conn, profile)
        encrypted_flag = oracle.initial()
        factors = None
        c = None
        for r in range(1, max_queries//4+1):
            observations = [
                oracle.query(r,s,t) for s in (-1,1) for t in (0,1)
            ]
            # An exception from one selector need not discard useful
            # re-encryption differences from the remaining responses.
            values = frozenset(
                value[0] for value in observations if value is not None
            )
            if len(values) < 2:
                continue
            records.append((r, values))
            if factors is None:
                factors = _records_to_factors(
                    records, max(16,profile.factor_bits-2),
                )
            if factors is not None and c is None:
                c = _recover_constant(records, factors)
                if c is not None:
                    break
    if factors is None or c is None:
        raise RuntimeError(
            "bounded reciprocal-Rabin oracle probes did not reveal "
            "two independent CRT factors and the public constant"
        )
    p,q = factors
    n = p*q
    if not 0 <= encrypted_flag[0] < n:
        raise RuntimeError("encrypted flag is inconsistent with reconstructed modulus")
    if _jacobi(c,p) != -1 or _jacobi(c,q) != -1:
        raise RuntimeError("recovered public constant violates source key generation")
    candidates = _decrypt_candidates(encrypted_flag,p,q,c)
    if len(candidates) != 1:
        raise RuntimeError("encrypted flag does not have a unique verified decryption")
    flag, plaintext = _decode_flag(candidates[0])
    if _encrypt(candidates[0],n,c) != encrypted_flag:
        raise RuntimeError("plaintext failed source-defined re-encryption")
    return OracleResult(n,(p,q),c,plaintext,flag,oracle.probes)


def recover_flag(documents, host, port, *, timeout=30.0):
    return recover_details(documents,host,port,timeout=timeout).secret
