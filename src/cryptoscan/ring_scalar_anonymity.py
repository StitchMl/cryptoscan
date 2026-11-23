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


def _scalar_sampler_functions(tree, minimum_bits):
    """Statically identify helper functions that return wide random scalars."""
    identified = set()
    for function in (node for node in ast.walk(tree)
                     if isinstance(node, ast.FunctionDef)):
        calls = [node for node in ast.walk(function)
                 if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute)
                 and node.func.attr == "getrandbits"
                 and len(node.args) == 1
                 and isinstance(node.args[0], ast.Constant)
                 and type(node.args[0].value) is int
                 and node.args[0].value >= minimum_bits]
        if calls and any(isinstance(node, ast.Return)
                         for node in ast.walk(function)):
            identified.add(function.name)
    return identified


def _reduced_scalar_arrays(function):
    """Group signer-side modular reductions by index and order reference."""
    groups = {}
    for node in ast.walk(function):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Subscript)
                and isinstance(node.targets[0].value, ast.Name)
                and isinstance(node.value, ast.BinOp)
                and isinstance(node.value.op, ast.Mod)
                and isinstance(node.value.right, (ast.Name, ast.Attribute))):
            continue
        target = node.targets[0]
        order_node = node.value.right
        order = order_node.id if isinstance(order_node, ast.Name) else order_node.attr
        groups.setdefault((ast.dump(target.slice), order), set()).add(
            target.value.id
        )
    return {order for (_, order), arrays in groups.items() if len(arrays) >= 2}


def _source_profile(source):
    if len(source) > 1_000_000:
        return None
    tree = parse_python(Document("candidate.py", source, None))
    if tree is None:
        return None
    bit_widths = {
        node.args[0].value for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "getrandbits" and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and type(node.args[0].value) is int
        and 128 <= node.args[0].value <= 1024
    }
    if not bit_widths:
        return None
    generators = _scalar_sampler_functions(tree, 128)
    linked = set()
    for function in (node for node in ast.walk(tree)
                     if isinstance(node, ast.FunctionDef)):
        function_orders = _reduced_scalar_arrays(function)
        if not function_orders:
            continue
        calls = [node for node in ast.walk(function)
                 if isinstance(node, ast.Call)]
        if any(
            isinstance(call.func, ast.Name) and call.func.id in generators
            or (isinstance(call.func, ast.Attribute)
                and call.func.attr == "getrandbits")
            for call in calls
        ):
            linked.update(function_orders)
    if len(linked) != 1:
        return None
    symbols = linked
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
    return slices.pop(), symbols.pop(), max(bit_widths)


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


def _hex_bytes(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]+", value):
        return None
    if len(value) % 2:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _ring_record(record):
    """Normalize any uniquely identifiable ring record to a stable model."""
    if not isinstance(record, dict):
        return None
    signatures, public_keys = [], []
    for item in record.values():
        if (isinstance(item, (tuple, list)) and len(item) == 3
                and isinstance(item[0], str)
                and _hex_bytes(item[0]) is not None
                and all(isinstance(vector, (tuple, list)) for vector in item[1:])
                and len(item[1]) == len(item[2])
                and all(type(x) is int and 0 <= x
                        for vector in item[1:] for x in vector)):
            signatures.append(item)
        if (isinstance(item, (tuple, list))
                and 2 <= len(item) <= 256
                and all((raw := _hex_bytes(value)) is not None
                        and 16 <= len(raw) <= 128 for value in item)
                and len({len(value) for value in item}) == 1):
            public_keys.append(item)
    compatible = [
        (sig, keys) for sig in signatures for keys in public_keys
        if len(sig[1]) == len(keys)
    ]
    if len(compatible) != 1:
        return None
    signature, keys = compatible[0]
    return {
        "signature": signature,
        "public_keys": keys,
    }


def _corpus(document):
    """Identify the payload from its nested types, not JSON field names."""
    try:
        data = (document.data if isinstance(document.data, dict)
                else json.loads(document.text))
    except (ValueError, TypeError, AttributeError):
        return None
    if not isinstance(data, dict):
        return None
    possible_levels = []
    for value in data.values():
        if not isinstance(value, list) or not 1 <= len(value) <= 128:
            continue
        parsed = [_ring_record(record) for record in value]
        if all(record is not None for record in parsed):
            possible_levels.append(tuple(parsed))
    if len(possible_levels) != 1:
        return None
    levels = possible_levels[0]
    # The public ciphertext and IV are identified by their CBC byte shapes.
    # Known field names are only a disambiguation aid, not a requirement.
    byte_fields = [
        (name, raw) for name, value in data.items()
        if (raw := _hex_bytes(value)) is not None
        and len(raw) >= 16 and len(raw) % 16 == 0
    ]
    iv_candidates = [(name, raw) for name, raw in byte_fields if len(raw) == 16]
    ct_candidates = [(name, raw) for name, raw in byte_fields
                     if len(raw) > 16]
    if len(iv_candidates) != 1 or len(ct_candidates) != 1:
        # A single-block ciphertext is possible: use schema hints only to
        # disambiguate, never silently guess two same-sized byte strings.
        iv_candidates = [
            (name, raw) for name, raw in byte_fields
            if str(name).casefold() in ("iv", "nonce", "initialization_vector")
            and len(raw) == 16
        ]
        ct_candidates = [
            (name, raw) for name, raw in byte_fields
            if str(name).casefold() in ("enc", "ciphertext", "encrypted")
            and len(raw) % 16 == 0
        ]
        if len(iv_candidates) != 1 or len(ct_candidates) != 1:
            return None
    iv = iv_candidates[0][1]
    ciphertext = ct_candidates[0][1]
    if iv == ciphertext and iv_candidates[0][0] == ct_candidates[0][0]:
        return None
    return levels, iv, ciphertext


def extract_instance(documents: Sequence[Document]) -> RingScalarLeak | None:
    candidates = []
    for source in documents:
        profile = _source_profile(source.text)
        if profile is None:
            continue
        key_slice, symbol, simulated_bits = profile
        for helper in documents:
            if helper.scope != source.scope:
                continue
            order = _order(helper.text, symbol)
            # With uniform modulo-order scalar sampling there is no
            # distinguishing information in the scalar magnitude.
            if order is None or simulated_bits <= order.bit_length():
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
