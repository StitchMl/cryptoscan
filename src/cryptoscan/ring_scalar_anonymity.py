"""Source-verified anonymity attack on unequal ring-signature scalar ranges.

When simulated responses are full-width random scalars but the genuine
signer reduces its two response scalars modulo the subgroup order,
both genuine entries must be below the order. Candidates are checked
against a source-derived symmetric key, never a stored flag or index.
"""
from __future__ import annotations

import ast
import itertools
import json
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .source_units import parse_python


@dataclass(frozen=True)
class RingScalarLeak:
    order: int
    levels: tuple[dict, ...]
    iv: bytes
    ciphertext: bytes
    key_slice: tuple[int, int]


def _source_profile(source):
    if len(source) > 1_000_000:
        return None
    tree = parse_python(Document("candidate.py", source, None))
    if tree is None:
        return None
    bit_widths, reduced = set(), {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "getrandbits" and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and type(node.args[0].value) is int):
            bit_widths.add(node.args[0].value)
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target, value = node.targets[0], node.value
        if not (isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and isinstance(value, ast.BinOp)
                and isinstance(value.op, ast.Mod)
                and isinstance(value.right, ast.Attribute)):
            continue
        reduced.setdefault((ast.unparse(target.slice), value.right.attr), set()
                           ).add(target.value.id)
    symbols = {order for (_, order), arrays in reduced.items()
               if len(arrays) >= 2}
    if (not any(bits >= 128 for bits in bit_widths)
            or len(symbols) != 1):
        return None
    if not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "new"
        and any(isinstance(arg, ast.Attribute) and arg.attr == "MODE_CBC"
                for arg in node.args)
        for node in ast.walk(tree)
    ):
        return None
    slices = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Subscript)
                and isinstance(node.slice, ast.Slice)
                and isinstance(node.slice.lower, ast.Constant)
                and isinstance(node.slice.upper, ast.Constant)
                and isinstance(node.value, ast.Subscript)
                and isinstance(node.value.value, ast.Subscript)):
            continue
        start, end = node.slice.lower.value, node.slice.upper.value
        if (type(start) is int and type(end) is int and
                0 <= start < end <= 64 and (end - start) % 2 == 0):
            slices.add((start, end))
    if len(slices) != 1 or not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fromhex" for node in ast.walk(tree)
    ):
        return None
    return slices.pop(), symbols.pop()


def _order(source, symbol):
    tree = parse_python(Document("curve.py", source, None))
    if tree is None:
        return None
    def constant(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.BinOp):
            left, right = constant(node.left), constant(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Pow) and 0 <= right <= 1024:
                return left ** right
        raise ValueError("nonconstant group order")
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == symbol):
            try:
                value = constant(node.value)
            except ValueError:
                return None
            return value if 2**127 < value < 2**520 else None
    return None


def _corpus(document):
    try:
        data = (document.data if isinstance(document.data, dict)
                else json.loads(document.text))
        levels = data["levels"]
        iv, ciphertext = bytes.fromhex(data["iv"]), bytes.fromhex(data["enc"])
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
    if (not isinstance(levels, list) or not 1 <= len(levels) <= 128
            or len(iv) != 16 or not ciphertext or len(ciphertext) % 16):
        return None
    for level in levels:
        if not isinstance(level, dict):
            return None
        signature, keys = level.get("signature"), level.get("public_keys")
        if (not isinstance(signature, list) or len(signature) != 3
                or not isinstance(keys, list) or not 2 <= len(keys) <= 256
                or not isinstance(signature[1], list)
                or not isinstance(signature[2], list)
                or len(signature[1]) != len(keys)
                or len(signature[2]) != len(keys)):
            return None
        if (not all(type(x) is int and 0 <= x
                    for part in signature[1:] for x in part)
                or not all(isinstance(key, str)
                           and re.fullmatch(r"[a-fA-F0-9]{64}", key)
                           for key in keys)):
            return None
    return tuple(levels), iv, ciphertext


def extract_instance(documents: Sequence[Document]) -> RingScalarLeak | None:
    candidates = []
    for source in documents:
        profile = _source_profile(source.text)
        if profile is None:
            continue
        key_slice, symbol = profile
        for helper in documents:
            if helper.scope != source.scope:
                continue
            order = _order(helper.text, symbol)
            if order is None:
                continue
            for data_document in documents:
                if (data_document.scope != source.scope
                        or data_document.path in (source.path, helper.path)):
                    continue
                corpus = _corpus(data_document)
                if corpus is not None:
                    candidates.append(RingScalarLeak(order, *corpus, key_slice))
    return candidates[0] if len(candidates) == 1 else None


def signer_candidates(level, order):
    _, challenges, responses = level["signature"]
    return [i for i, (c, r) in enumerate(
        zip(challenges, responses, strict=True)
    ) if c < order and r < order]


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no supported source-verified ring scalar anonymity leak")
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    choices = [signer_candidates(level, instance.order)
               for level in instance.levels]
    if any(not candidates for candidates in choices):
        raise RuntimeError("no scalar-range-compatible signer in a ring")
    combinations = 1
    for candidates in choices:
        combinations *= len(candidates)
        if combinations > 2_000_000:
            raise RuntimeError("ambiguous signer search exceeds safety bound")
    start, end = instance.key_slice
    verified = set()
    for indices in itertools.product(*choices):
        material = "".join(level["public_keys"][index][start:end]
                           for level, index in zip(
                               instance.levels, indices, strict=True))
        try:
            key = bytes.fromhex(material)
            if len(key) not in (16, 24, 32):
                continue
            plaintext = AES.new(
                key, AES.MODE_CBC, iv=instance.iv
            ).decrypt(instance.ciphertext)
            try:
                unpadded = unpad(plaintext, 16)
            except ValueError:
                unpadded = plaintext
            possible = (plaintext, unpadded)
            for candidate in possible:
                decoded = candidate.decode("utf-8")
                if re.fullmatch(r"\w{2,32}\{[^{}\r\n]{1,256}\}", decoded):
                    verified.add(decoded)
        except (ValueError, UnicodeError):
            continue
    if len(verified) != 1:
        raise RuntimeError("no unique, verified flag from ring signer candidates")
    return verified.pop()
