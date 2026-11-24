"""Invert recursively applied Cantor pairing over a bounded byte sequence.

The source profile is established from Python syntax, and a published integer
must be present in the same challenge scope. Challenge files are never run.
"""
from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document

MAX_BYTES = 256
MAX_OUTPUT_DIGITS = 2000
FLAG_SHAPE = re.compile(rb"[A-Za-z0-9_]{2,32}\{[\x20-\x7e]{1,200}\}")
COMMENT_NUMBER = re.compile(r"(?m)^[ \t]*#[ \t]*(\d{1,2000})[ \t]*$")
BARE_NUMBER = re.compile(r"^\d{1,2000}$")
OUTPUT_NUMBER = re.compile(
    r"(?m)^[ \t]*(?:output|encoded|result|flag_n)[ \t]*=[ \t]*(\d{1,2000})[ \t]*$"
)


@dataclass(frozen=True)
class Instance:
    number: int
    source: str
    output: str
    scope: str


def _name(node: ast.AST, expected: str) -> bool:
    return isinstance(node, ast.Name) and node.id == expected


def _literal(node: ast.AST, value: int) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) is int and node.value == value


def _sum(node: ast.AST) -> tuple[str, str] | None:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
        return None
    if isinstance(node.left, ast.Name) and isinstance(node.right, ast.Name):
        return node.left.id, node.right.id
    return None


def _cantor_formula(node: ast.AST) -> tuple[str, str] | None:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
        return None
    quotient, right = node.left, node.right
    if not isinstance(right, ast.Name):
        return None
    if not isinstance(quotient, ast.BinOp) or not isinstance(quotient.op, ast.FloorDiv):
        return None
    if not _literal(quotient.right, 2):
        return None
    product = quotient.left
    if not isinstance(product, ast.BinOp) or not isinstance(product.op, ast.Mult):
        return None
    left_sum = _sum(product.left)
    other = product.right
    if not isinstance(other, ast.BinOp) or not isinstance(other.op, ast.Add):
        return None
    if (
        left_sum is not None
        and _sum(other.left) == left_sum
        and _literal(other.right, 1)
        and right.id == left_sum[1]
    ):
        return left_sum
    return None


def _base_case(function: ast.FunctionDef, parameter: str) -> bool:
    return any(
        isinstance(node, ast.Return)
        and isinstance(node.value, ast.Subscript)
        and _name(node.value.value, parameter)
        and _literal(node.value.slice, 0)
        for node in ast.walk(function)
    )


def _length_terms(function: ast.FunctionDef, parameter: str) -> set[str]:
    terms = set()
    for node in ast.walk(function):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        call = node.value
        if (isinstance(node.targets[0], ast.Name)
                and isinstance(call, ast.Call) and _name(call.func, "len")
                and len(call.args) == 1 and _name(call.args[0], parameter)):
            terms.add(node.targets[0].id)
    return terms


def _half_split(node: ast.AST, length_names: set[str]) -> bool:
    if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Sub):
        return False
    if not isinstance(node.left, ast.Name) or node.left.id not in length_names:
        return False
    half = node.right
    return (
        isinstance(half, ast.BinOp)
        and isinstance(half.op, ast.FloorDiv)
        and ast.dump(half.left) == ast.dump(node.left)
        and _literal(half.right, 2)
    )


def _recursion_children(node: ast.AST, function_name: str) -> list[ast.AST] | None:
    if not isinstance(node, ast.Call) or not _name(node.func, function_name):
        return None
    if len(node.args) != 1 or not isinstance(node.args[0], (ast.List, ast.Tuple)):
        return None
    children = node.args[0].elts
    if len(children) != 2:
        return None
    if not all(isinstance(child, ast.Call) and _name(child.func, function_name)
               and len(child.args) == 1 for child in children):
        return None
    return [child.args[0] for child in children]


def _matching_slices(children: list[ast.AST], parameter: str,
                     length_names: set[str]) -> bool:
    if not all(isinstance(item, ast.Subscript) and _name(item.value, parameter)
               and isinstance(item.slice, ast.Slice) for item in children):
        return False
    first, second = (item.slice for item in children)
    return (
        first.lower is None and first.upper is not None
        and second.upper is None and second.lower is not None
        and ast.dump(first.upper) == ast.dump(second.lower)
        and _half_split(first.upper, length_names)
    )


def _recursive_split(function: ast.FunctionDef, parameter: str) -> bool:
    length_names = _length_terms(function, parameter)
    for node in ast.walk(function):
        children = _recursion_children(node, function.name)
        if children is not None and _matching_slices(children, parameter, length_names):
            return True
    return False


def _pair_return(function: ast.FunctionDef, parameter: str) -> bool:
    for node in ast.walk(function):
        if not isinstance(node, ast.Return):
            continue
        names = _cantor_formula(node.value)
        if names is None:
            continue
        for assignment in ast.walk(function):
            if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
                continue
            target = assignment.targets[0]
            if (isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == 2
                    and all(isinstance(item, ast.Name) for item in target.elts)
                    and tuple(item.id for item in target.elts) == names
                    and _name(assignment.value, parameter)):
                return True
    return False


def _source_profile(document: Document) -> bool:
    if not document.path.lower().endswith(".py") or len(document.text) > 2_000_000:
        return False
    try:
        tree = ast.parse(document.text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or len(node.args.args) != 1:
            continue
        parameter = node.args.args[0].arg
        if (_base_case(node, parameter)
                and _recursive_split(node, parameter)
                and _pair_return(node, parameter)):
            return True
    return False


def _published_numbers(document: Document) -> set[int]:
    candidates = [match.group(1) for match in COMMENT_NUMBER.finditer(document.text)]
    candidates.extend(match.group(1) for match in OUTPUT_NUMBER.finditer(document.text))
    if BARE_NUMBER.fullmatch(document.text.strip()):
        candidates.append(document.text.strip())
    return {int(value) for value in candidates if len(value) <= MAX_OUTPUT_DIGITS}


def extract_instance(documents: Sequence[Document]) -> Instance | None:
    """Require one matching source and exactly one public numeric output."""
    found = []
    for source in documents:
        if not _source_profile(source):
            continue
        outputs = {(doc.path, number) for doc in documents
                   if doc.scope == source.scope
                   for number in _published_numbers(doc)
                   if number.bit_length() <= 8 * MAX_OUTPUT_DIGITS}
        numbers = {number for _, number in outputs}
        if len(numbers) == 1:
            number = numbers.pop()
            path = sorted(path for path, value in outputs if value == number)[0]
            found.append(Instance(number, source.path, path, source.scope))
    return found[0] if len(found) == 1 else None


def pair(left: int, right: int) -> int:
    if left < 0 or right < 0:
        raise ValueError("Cantor pairing requires nonnegative integers")
    total = left + right
    return total * (total + 1) // 2 + right


def unpair(number: int) -> tuple[int, int]:
    if number < 0:
        raise ValueError("Cantor pairing requires a nonnegative integer")
    diagonal = (math.isqrt(8 * number + 1) - 1) // 2
    right = number - diagonal * (diagonal + 1) // 2
    return diagonal - right, right


def encode(values: Sequence[int]) -> int:
    """Mirror the source's left=(length-length//2), right=length//2 split."""
    if not values or any(type(value) is not int or not 0 <= value <= 255
                         for value in values):
        raise ValueError("expected a nonempty byte sequence")
    if len(values) == 1:
        return values[0]
    pivot = len(values) - len(values) // 2
    return pair(encode(values[:pivot]), encode(values[pivot:]))


def decode(number: int, length: int) -> bytes:
    if not 1 <= length <= MAX_BYTES:
        raise ValueError("byte length outside supported bounds")
    if length == 1:
        if not 0 <= number <= 255:
            raise ValueError("leaf outside byte range")
        return bytes([number])
    left, right = unpair(number)
    pivot = length - length // 2
    return decode(left, pivot) + decode(right, length // 2)


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("need one recursive Cantor source and one public integer")
    candidates: set[bytes] = set()
    for length in range(2, MAX_BYTES + 1):
        try:
            plain = decode(instance.number, length)
        except ValueError:
            continue
        if FLAG_SHAPE.fullmatch(plain) and encode(plain) == instance.number:
            candidates.add(plain)
    if len(candidates) != 1:
        raise RuntimeError(f"expected one verified flag, found {len(candidates)}")
    return next(iter(candidates)).decode("ascii")

