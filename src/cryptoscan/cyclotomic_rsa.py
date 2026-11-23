"""Factor cyclotomic-related RSA primes via finite-extension subgroup collapse.

If a public RSA modulus contains p and Q(p)=1+p+...+p**(d-1),
then Q(p) divides p**d-1. In F_(p**d), raising an element to N
kills its Q(p)-order component: the resulting element is in F_p.
A degree-d quotient ring over Z/NZ reduces to that finite field modulo p
when its defining polynomial is irreducible. Its nonconstant coefficients
of a**N must then vanish modulo p, yielding gcd(coefficient, N) = p
with positive probability. A *verified* p determines Q(p), the remaining
factor, and the RSA plaintext. No factor or flag is hard-coded.
"""
from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .source_units import parse_python

_SOURCE_LIMIT = 1_000_000
_OUTPUT_LIMIT = 2_000_000
_FLAG = re.compile(rb"[A-Za-z][A-Za-z0-9_-]{1,31}\{[^{}\r\n]{1,256}\}")


@dataclass(frozen=True)
class CyclotomicRSA:
    modulus: int
    exponent: int
    ciphertext: int
    degree: int
    prime_bits: int


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _literal(node, bindings=None):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if (isinstance(node, ast.Name) and bindings
            and node.id in bindings):
        return bindings[node.id]
    if isinstance(node, ast.BinOp):
        left = _literal(node.left, bindings)
        right = _literal(node.right, bindings)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
    return None


def _sum_of_powers(node, base, index, degree):
    """Accept a geometric series independent of list/generator syntax."""
    if not isinstance(node, ast.Call) or len(node.args) != 1:
        return False
    if _name(node.func) != "sum":
        return False
    values = node.args[0]
    if not isinstance(values, (ast.ListComp, ast.GeneratorExp)):
        return False
    if len(values.generators) != 1:
        return False
    loop = values.generators[0]
    if (_name(loop.target) != index
            or not isinstance(loop.iter, ast.Call)
            or _name(loop.iter.func) != "range"
            or len(loop.iter.args) != 1
            or _name(loop.iter.args[0]) != degree):
        return False
    elt = values.elt
    return (isinstance(elt, ast.BinOp)
            and isinstance(elt.op, ast.Pow)
            and _name(elt.left) == base
            and _name(elt.right) == index)


def _function_roles(tree):
    """Return name and formal parameter names of a coupled-prime factory."""
    candidates = []
    for function in tree.body:
        if not isinstance(function, ast.FunctionDef):
            continue
        formal = [arg.arg for arg in function.args.args]
        if len(formal) < 2:
            continue
        prime, correlated = None, None
        for statement in ast.walk(function):
            if (not isinstance(statement, ast.Assign)
                    or len(statement.targets) != 1
                    or not isinstance(statement.targets[0], ast.Name)):
                continue
            name = statement.targets[0].id
            value = statement.value
            if (isinstance(value, ast.Call)
                    and len(value.args) == 1
                    and (call := value.func)
                    and ((isinstance(call, ast.Name) and call.id == "getPrime")
                         or (isinstance(call, ast.Attribute)
                             and call.attr == "getPrime"))
                    and _name(value.args[0]) == formal[0]):
                prime = name
            if (isinstance(value, ast.Call)
                    and _name(value.func) == "sum"
                    and len(value.args) == 1
                    and isinstance(value.args[0], (ast.ListComp, ast.GeneratorExp))):
                comp = value.args[0]
                if len(comp.generators) == 1:
                    idx = _name(comp.generators[0].target)
                    if idx and prime and _sum_of_powers(value, prime, idx, formal[1]):
                        correlated = name
        if not prime or not correlated:
            continue
        primality = any(
            isinstance(node, ast.Call)
            and len(node.args) == 1
            and _name(node.args[0]) == correlated
            and ((isinstance(node.func, ast.Name)
                  and node.func.id in ("isPrime", "isprime"))
                 or (isinstance(node.func, ast.Attribute)
                     and node.func.attr in ("isPrime", "isprime")))
            for node in ast.walk(function)
        )
        returns = any(
            isinstance(node, ast.Return)
            and isinstance(node.value, ast.Tuple)
            and len(node.value.elts) == 2
            and tuple(map(_name, node.value.elts)) == (prime, correlated)
            for node in ast.walk(function)
        )
        if primality and returns:
            candidates.append((function.name, formal[0], formal[1]))
    return candidates[0] if len(candidates) == 1 else None


def _multiply_factor_names(node):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left = _multiply_factor_names(node.left)
        right = _multiply_factor_names(node.right)
        return left + right if left and right else []
    name = _name(node)
    return [name] if name else []


def _source_profile(source):
    if not source or len(source) > _SOURCE_LIMIT:
        return None
    tree = parse_python(Document("unknown-source", source, None))
    if tree is None:
        return None
    factory = _function_roles(tree)
    if factory is None:
        return None
    fn, _, _ = factory
    constants = {
        stmt.targets[0].id: stmt.value.value
        for stmt in tree.body
        if (isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Constant)
            and type(stmt.value.value) is int)
    }
    coupled = []
    for statement in tree.body:
        if (isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Tuple)
                and len(statement.targets[0].elts) == 2
                and isinstance(statement.value, ast.Call)
                and _name(statement.value.func) == fn
                and len(statement.value.args) >= 2):
            names = tuple(map(_name, statement.targets[0].elts))
            bits = _literal(statement.value.args[0], constants)
            degree = _literal(statement.value.args[1], constants)
            if (all(names) and bits is not None and degree is not None
                    and 32 <= bits <= 8192 and 2 <= degree <= 8):
                coupled.append((names, bits, degree))
    if len(coupled) != 1:
        return None
    (prime_name, other_name), bits, degree = coupled[0]
    modulus_names = []
    for statement in tree.body:
        if not (isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and (modulus_name := _name(statement.targets[0]))):
            continue
        factors = _multiply_factor_names(statement.value)
        if (len(factors) >= 3
                and factors.count(prime_name) == 1
                and factors.count(other_name) == 1):
            modulus_names.append(modulus_name)
    if len(modulus_names) != 1:
        return None
    modulus_name = modulus_names[0]
    encryptions = []
    for statement in ast.walk(tree):
        if not (isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and (cipher_name := _name(statement.targets[0]))
                and isinstance(statement.value, ast.Call)
                and _name(statement.value.func) == "pow"
                and len(statement.value.args) == 3
                and _name(statement.value.args[2]) == modulus_name):
            continue
        exponent_name = _name(statement.value.args[1])
        if exponent_name is None or exponent_name not in constants:
            continue
        exponent = constants[exponent_name]
        if exponent > 1 and exponent % 2 == 1:
            encryptions.append((cipher_name, exponent_name, exponent))
    if len(encryptions) != 1:
        return None
    cipher_name, exponent_name, exponent = encryptions[0]
    return modulus_name, exponent_name, cipher_name, bits, degree, exponent


def _public_values(document, roles):
    if len(document.text) > _OUTPUT_LIMIT:
        return None
    labels = roles[:3]
    parsed = {}
    for line in document.text.splitlines():
        match = re.fullmatch(
            r"\s*([A-Za-z_]\w*)\s*=\s*(0[xX][\da-fA-F]+|\d+)\s*",
            line,
        )
        if match and match.group(1) in labels:
            name, value = match.groups()
            if name in parsed:
                return None
            parsed[name] = int(value, 0) if value.startswith(("0x", "0X")) else int(value)
    if set(parsed) != set(labels):
        return None
    n, e, c = (parsed[name] for name in labels)
    if (not 128 <= n.bit_length() <= 65536
            or e != roles[5]
            or not 0 <= c < n):
        return None
    return n, e, c


def extract_instance(documents: Sequence[Document]):
    matches = []
    for source in documents:
        roles = _source_profile(source.text)
        if roles is None:
            continue
        for output in documents:
            if output.scope != source.scope or output.path == source.path:
                continue
            public = _public_values(output, roles)
            if public is not None:
                matches.append(CyclotomicRSA(
                    *public, degree=roles[4], prime_bits=roles[3],
                ))
    return matches[0] if len(matches) == 1 else None


def extension_multiply(left, right, polynomial, modulus):
    """Multiply in (Z/NZ)[x]/(x**d + a[d-1]x**(d-1)+...+a[0])."""
    d = len(polynomial)
    if len(left) != d or len(right) != d:
        raise ValueError("extension polynomial dimensions differ")
    result = [0] * (2 * d - 1)
    for i, l in enumerate(left):
        for j, r in enumerate(right):
            result[i + j] += l * r
    for k in range(2 * d - 2, d - 1, -1):
        high = result[k]
        for j, coefficient in enumerate(polynomial):
            result[k - d + j] -= high * coefficient
    return tuple(value % modulus for value in result[:d])


def extension_pow(base, exponent, polynomial, modulus):
    if exponent < 0 or modulus <= 1:
        raise ValueError("invalid quotient-ring exponentiation")
    d = len(polynomial)
    result = (1,) + (0,) * (d - 1)
    while exponent:
        if exponent & 1:
            result = extension_multiply(result, base, polynomial, modulus)
        exponent >>= 1
        if exponent:
            base = extension_multiply(base, base, polynomial, modulus)
    return result


def related_factors(n, degree, *, max_attempts=48):
    """Try independent monic extensions and validate every recovered factor."""
    if not 2 <= degree <= 8 or max_attempts < 1:
        raise ValueError("unsupported extension degree or attempt limit")
    for index in range(1, max_attempts + 1):
        # Deterministic bounded exploration; coefficients are not
        # sourced from, or matched to, any CTF.
        polynomial = tuple(index**(j + 1) + 1 for j in range(degree))
        if math.gcd(polynomial[0], n) != 1:
            continue
        element = (0, 1) + (0,) * (degree - 2)
        result = extension_pow(element, n, polynomial, n)
        for coefficient in result[1:]:
            p = math.gcd(coefficient, n)
            if not 1 < p < n:
                continue
            q = sum(p**j for j in range(degree))
            if q > 1 and n % (p * q) == 0:
                r = n // (p * q)
                if r > 1:
                    return p, q, r, index
    raise RuntimeError(
        "no certified cyclotomic prime factor from bounded finite-field trials"
    )


def recover_details(instance: CyclotomicRSA, *, attempts=48):
    try:
        from Crypto.Util.number import isPrime
    except ImportError:
        from sympy import isprime as isPrime
    p, q, r, attempt = related_factors(
        instance.modulus, instance.degree, max_attempts=attempts,
    )
    if not all(isPrime(factor) for factor in (p, q, r)):
        raise RuntimeError("RSA factor primality certificate rejected")
    if not 1 << (instance.prime_bits - 1) <= p < 1 << instance.prime_bits:
        raise RuntimeError("recovered factor violates source-defined bit size")
    phi = (p - 1) * (q - 1) * (r - 1)
    if math.gcd(instance.exponent, phi) != 1:
        raise RuntimeError("RSA public exponent has no modular inverse")
    secret = pow(instance.ciphertext, pow(instance.exponent, -1, phi), instance.modulus)
    if pow(secret, instance.exponent, instance.modulus) != instance.ciphertext:
        raise RuntimeError("RSA plaintext fails re-encryption certificate")
    message = secret.to_bytes((secret.bit_length() + 7) // 8, "big")
    if not _FLAG.fullmatch(message):
        raise RuntimeError("decrypted plaintext has no verified CTF token shape")
    return message.decode("utf-8"), {
        "factor_count": 3,
        "extension_degree": instance.degree,
        "trial": attempt,
        "factorization_verified": True,
        "reencryption_verified": True,
    }


def recover_flag(documents: Sequence[Document], *, attempts=48):
    model = extract_instance(documents)
    if model is None:
        raise ValueError("no source-verified cyclotomic-related RSA instance")
    return recover_details(model, attempts=attempts)[0]
