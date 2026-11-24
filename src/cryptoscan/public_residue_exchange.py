"""Recover plaintext from a multiplicative key determined by public residues.

Recognize a private value published modulo p, an exchange monomial computed
modulo the same p, and exact integer multiplication for encryption. Python
challenge sources are parsed as data and never executed.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document, assignments

FLAG_SHAPE = re.compile(rb"[A-Za-z0-9_]{2,32}\{[\x20-\x7e]{1,200}\}")
MAX_SOURCE = 2_000_000
MAX_BITS = 16_384


@dataclass(frozen=True)
class Monomial:
    coefficient: int = 1
    public: int = 0
    private: int = 0
    peer: int = 0
    reduced: bool = False


@dataclass(frozen=True)
class Profile:
    public_power: int
    peer_power: int
    coefficient: int
    byteorder: str


@dataclass(frozen=True)
class Instance:
    p: int
    public_a: int
    public_b: int
    ciphertext: int
    profile: Profile
    source: str
    output: str
    scope: str


def _attribute(node: ast.AST, name: str) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == name
            and isinstance(node.value, ast.Name) and node.value.id == "self")


def _public_relation(cls: ast.ClassDef) -> tuple[str, str, str] | None:
    for node in ast.walk(cls):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target, value = node.targets[0], node.value
        if not isinstance(target, ast.Attribute) or not _attribute(target, target.attr):
            continue
        if not isinstance(value, ast.BinOp) or not isinstance(value.op, ast.Mod):
            continue
        left, right = value.left, value.right
        if not isinstance(left, ast.Attribute) or not isinstance(right, ast.Attribute):
            continue
        if (_attribute(left, left.attr) and _attribute(right, right.attr)
                and len({target.attr, left.attr, right.attr}) == 3):
            return target.attr, left.attr, right.attr
    return None


def _multiply(left: Monomial, right: Monomial) -> Monomial | None:
    if left.reduced or right.reduced:
        return None
    result = Monomial(
        left.coefficient * right.coefficient,
        left.public + right.public,
        left.private + right.private,
        left.peer + right.peer,
    )
    if min(result.coefficient, result.public, result.private, result.peer) < 0:
        return None
    if max(result.public, result.private, result.peer) > 8:
        return None
    return result if result.coefficient.bit_length() <= 64 else None


def _power(node: ast.BinOp, env: dict[str, Monomial],
           relation: tuple[str, str, str]) -> Monomial | None:
    if not isinstance(node.right, ast.Constant):
        return None
    power = node.right.value
    base = _expression(node.left, env, relation)
    if type(power) is not int or not 1 <= power <= 8 or base is None:
        return None
    result = Monomial()
    for _ in range(power):
        result = _multiply(result, base)
        if result is None:
            return None
    return result


def _binary(node: ast.BinOp, env: dict[str, Monomial],
            relation: tuple[str, str, str]) -> Monomial | None:
    if isinstance(node.op, ast.Mod) and _attribute(node.right, relation[2]):
        inner = _expression(node.left, env, relation)
        if inner is not None and not inner.reduced:
            return Monomial(inner.coefficient, inner.public, inner.private,
                            inner.peer, reduced=True)
        return None
    if isinstance(node.op, ast.Mult):
        left = _expression(node.left, env, relation)
        right = _expression(node.right, env, relation)
        return _multiply(left, right) if left is not None and right is not None else None
    if isinstance(node.op, ast.Pow):
        return _power(node, env, relation)
    return None


def _expression(node: ast.AST, env: dict[str, Monomial],
                relation: tuple[str, str, str]) -> Monomial | None:
    public, private, _ = relation
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if _attribute(node, public):
        return Monomial(public=1)
    if _attribute(node, private):
        return Monomial(private=1)
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return Monomial(coefficient=node.value) if 0 < node.value <= 2**32 else None
    return _binary(node, env, relation) if isinstance(node, ast.BinOp) else None


def _exchange_keys(method: ast.FunctionDef,
                   relation: tuple[str, str, str]) -> dict[str, Monomial]:
    if len(method.args.args) != 2:
        return {}
    peer_name = method.args.args[1].arg
    env = {peer_name: Monomial(peer=1)}
    keys = {}
    for statement in method.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        value = _expression(statement.value, env, relation)
        target = statement.targets[0]
        if isinstance(target, ast.Name):
            if value is not None:
                env[target.id] = value
            else:
                env.pop(target.id, None)
        if (isinstance(target, ast.Attribute) and _attribute(target, target.attr)
                and value is not None and value.reduced):
            keys[target.attr] = value
    return keys


def _cipher_product(node: ast.AST, message: str, aliases: set[str],
                    key_attribute: str) -> bool:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mult):
        return False
    terms = (node.left, node.right)
    has_message = any(isinstance(term, ast.Name) and term.id == message
                      for term in terms)
    has_key = any(
        (isinstance(term, ast.Name) and term.id in aliases)
        or _attribute(term, key_attribute)
        for term in terms
    )
    return has_message and has_key


def _encrypts_with(method: ast.FunctionDef, key_attribute: str) -> bool:
    if len(method.args.args) != 2:
        return False
    message = method.args.args[1].arg
    aliases = {key_attribute} if key_attribute != message else set()
    for statement in method.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            if isinstance(target, ast.Name) and _attribute(statement.value, key_attribute):
                aliases.add(target.id)
        if isinstance(statement, ast.Return) and _cipher_product(
                statement.value, message, aliases, key_attribute):
            return True
    return False


def _byteorder(tree: ast.Module) -> str | None:
    orders = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        func = node.func
        if (isinstance(func, ast.Attribute) and func.attr == "from_bytes"
                and isinstance(func.value, ast.Name) and func.value.id == "int"
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in {"big", "little"}):
            orders.add(node.args[1].value)
    return next(iter(orders)) if len(orders) == 1 else None


def source_profiles(document: Document) -> list[Profile]:
    if not document.path.lower().endswith(".py") or len(document.text) > MAX_SOURCE:
        return []
    try:
        tree = ast.parse(document.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    order = _byteorder(tree)
    if order is None:
        return []
    found = []
    for cls in tree.body:
        if not isinstance(cls, ast.ClassDef):
            continue
        relation = _public_relation(cls)
        if relation is None:
            continue
        methods = [node for node in cls.body if isinstance(node, ast.FunctionDef)]
        for method in methods:
            for key_attribute, key in _exchange_keys(method, relation).items():
                if not any(_encrypts_with(encryptor, key_attribute)
                           for encryptor in methods):
                    continue
                powers = (key.public + key.private, key.peer)
                if key.private and all(powers):
                    found.append(Profile(*powers, key.coefficient, order))
    return list(dict.fromkeys(found))


def _field(values: dict[str, object], *names: str) -> int | None:
    selected = [values[name] for name in names if name in values]
    if len(selected) != 1 or type(selected[0]) is not int:
        return None
    return selected[0]


def _output_values(document: Document) -> tuple[int, int, int, int] | None:
    values = assignments(document.text)
    p = _field(values, "p", "modulus")
    public_a = _field(values, "y_a", "public_a", "alice_public_key")
    public_b = _field(values, "y_b", "public_b", "bob_public_key")
    ciphertext = _field(values, "c", "ciphertext")
    if any(value is None for value in (p, public_a, public_b, ciphertext)):
        return None
    if (p <= 2 or p.bit_length() > MAX_BITS or ciphertext < 0
            or ciphertext.bit_length() > 2 * MAX_BITS
            or not 0 <= public_a < p or not 0 <= public_b < p):
        return None
    return p, public_a, public_b, ciphertext


def extract_instance(documents: Sequence[Document]) -> Instance | None:
    """Join a source-verified exchange with one public transcript per scope."""
    found = set()
    for source in documents:
        for profile in source_profiles(source):
            for output in documents:
                if source.path == output.path or source.scope != output.scope:
                    continue
                values = _output_values(output)
                if values is not None:
                    found.add(Instance(*values, profile, source.path,
                                       output.path, source.scope))
    return next(iter(found)) if len(found) == 1 else None


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("need one source-verified public-residue exchange and transcript")
    profile = instance.profile
    key = (profile.coefficient
           * pow(instance.public_a, profile.public_power, instance.p)
           * pow(instance.public_b, profile.peer_power, instance.p)) % instance.p
    if key == 0:
        raise RuntimeError("publicly reconstructed shared key is zero")
    message, remainder = divmod(instance.ciphertext, key)
    if remainder:
        raise RuntimeError("ciphertext is not an exact multiple of the shared key")
    size = max(1, (message.bit_length() + 7) // 8)
    plaintext = message.to_bytes(size, profile.byteorder)
    if not FLAG_SHAPE.fullmatch(plaintext):
        raise RuntimeError("recovered plaintext does not have a CTF flag shape")
    if int.from_bytes(plaintext, profile.byteorder) * key != instance.ciphertext:
        raise RuntimeError("ciphertext round-trip verification failed")
    return plaintext.decode("ascii")

