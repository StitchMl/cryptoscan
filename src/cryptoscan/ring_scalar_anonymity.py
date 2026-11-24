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


def _power_of_two_exponent(argument):
    """Exponent of `1 << n` or `2 ** n` with a literal n in 1..1024."""
    if not (isinstance(argument, ast.BinOp)
            and isinstance(argument.left, ast.Constant)
            and isinstance(argument.right, ast.Constant)):
        return None
    base = {ast.LShift: 1, ast.Pow: 2}.get(type(argument.op))
    exponent = argument.right.value
    if (base is not None and argument.left.value == base
            and type(exponent) is int and 1 <= exponent <= 1024):
        return exponent
    return None


def _random_scalar_width(call):
    """Infer an upper-bound bit width without executing random APIs."""
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        return None
    name = call.func.attr
    if len(call.args) != 1:
        return None
    argument = call.args[0]
    if name in ("getrandbits", "randbits"):
        if isinstance(argument, ast.Constant) and type(argument.value) is int:
            return argument.value if 1 <= argument.value <= 1024 else None
    if name in ("randbelow", "randrange"):
        return _power_of_two_exponent(argument)
    return None


def _scalar_sampler_functions(tree, minimum_bits):
    """Resolve source-level functions that return the PRNG result itself."""
    identified = {}
    for function in (node for node in ast.walk(tree)
                     if isinstance(node, ast.FunctionDef)):
        widths = [
            bits for node in ast.walk(function)
            if isinstance(node, ast.Return)
            and (bits := _random_scalar_width(node.value)) is not None
            and bits >= minimum_bits
        ]
        if widths:
            identified[function.name] = max(widths)
    return identified


def _reduced_scalar_arrays(function):
    """Map group-order symbols to signer response arrays sharing an index."""
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
    result = {}
    for (_, order), arrays in groups.items():
        if len(arrays) >= 2:
            result.setdefault(order, set()).update(arrays)
    return result


def _sampler_width(node, generators):
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return generators.get(node.func.id)
    return _random_scalar_width(node)


def _name_widths(assignments, generators):
    values = {}
    for _ in range(3):
        for assignment in assignments:
            target, value = assignment.targets[0], assignment.value
            if isinstance(target, ast.Name):
                width = _sampler_width(value, generators)
                if (width is None and isinstance(value, ast.Name)):
                    width = values.get(value.id)
                if width is not None:
                    values[target.id] = width
    return values


def _record_array_width(arrays, target, value, values, generators):
    if isinstance(target, ast.Name):
        if isinstance(value, (ast.ListComp, ast.GeneratorExp)):
            width = _sampler_width(value.elt, generators)
            if width is not None:
                arrays[target.id] = width
    elif (isinstance(target, ast.Subscript)
          and isinstance(target.value, ast.Name)):
        width = _sampler_width(value, generators)
        if width is None and isinstance(value, ast.Name):
            width = values.get(value.id)
        if width is not None:
            arrays[target.value.id] = max(
                arrays.get(target.value.id, 0), width,
            )


def _simulated_response_arrays(function, generators):
    """Conservative local def-use check: PRNG values flow into responses."""
    arrays = {}
    assignments = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Assign) and len(node.targets) == 1
    ]
    values = _name_widths(assignments, generators)
    for assignment in assignments:
        _record_array_width(
            arrays, assignment.targets[0], assignment.value, values, generators)
    return arrays


def _linked_orders(tree, generators):
    linked = {}
    for function in (node for node in ast.walk(tree)
                     if isinstance(node, ast.FunctionDef)):
        group_orders = _reduced_scalar_arrays(function)
        if not group_orders:
            continue
        sampled_arrays = _simulated_response_arrays(function, generators)
        for order_name, response_arrays in group_orders.items():
            # A signer bias is demonstrated only when the SAME response
            # arrays contain raw random decoys and reduced true responses.
            if all(name in sampled_arrays for name in response_arrays):
                linked.setdefault(order_name, set()).add(
                    min(sampled_arrays[name] for name in response_arrays)
                )
    return linked


def _uses_cbc(tree):
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "new"
        and any(isinstance(arg, ast.Attribute) and arg.attr == "MODE_CBC"
                for arg in node.args)
        for node in ast.walk(tree)
    )


def _key_slices(tree):
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
    return slices


def _calls_fromhex(tree):
    return any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "fromhex" for node in ast.walk(tree)
    )


def _source_profile(source):
    if len(source) > 1_000_000:
        return None
    tree = parse_python(Document("candidate.py", source, None))
    if tree is None:
        return None
    generators = _scalar_sampler_functions(tree, 128)
    linked = _linked_orders(tree, generators)
    if len(linked) != 1:
        return None
    symbols = set(linked)
    simulated_bits = max(next(iter(linked.values())))
    if not _uses_cbc(tree):
        return None
    slices = _key_slices(tree)
    if len(slices) != 1 or not _calls_fromhex(tree):
        return None
    return slices.pop(), symbols.pop(), simulated_bits


def _constant_order(node):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.BinOp):
        left, right = _constant_order(node.left), _constant_order(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Pow) and 0 <= right <= 1024:
            return left ** right
    raise ValueError("nonconstant group order")


def _order(source, symbol):
    tree = parse_python(Document("curve.py", source, None))
    if tree is None:
        return None
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == symbol):
            try:
                value = _constant_order(node.value)
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


def _ring_levels(data):
    possible_levels = []
    for value in data.values():
        if not isinstance(value, list) or not 1 <= len(value) <= 128:
            continue
        parsed = [_ring_record(record) for record in value]
        if all(record is not None for record in parsed):
            possible_levels.append(tuple(parsed))
    return possible_levels[0] if len(possible_levels) == 1 else None


def _iv_and_ciphertext(data):
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
    return iv, ciphertext


def _corpus(document):
    """Identify the payload from its nested types, not JSON field names."""
    try:
        data = (document.data if isinstance(document.data, dict)
                else json.loads(document.text))
    except (ValueError, TypeError, AttributeError):
        return None
    if not isinstance(data, dict):
        return None
    levels = _ring_levels(data)
    if levels is None:
        return None
    shapes = _iv_and_ciphertext(data)
    if shapes is None:
        return None
    return levels, *shapes


def _source_leaks(documents, source, profile):
    key_slice, symbol, simulated_bits = profile
    found = []
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
                found.append(RingScalarLeak(order, *corpus, key_slice))
    return found


def extract_instance(documents: Sequence[Document]) -> RingScalarLeak | None:
    candidates = []
    for source in documents:
        profile = _source_profile(source.text)
        if profile is not None:
            candidates.extend(_source_leaks(documents, source, profile))
    return candidates[0] if len(candidates) == 1 else None


def signer_candidates(level, order):
    _, challenges, responses = level["signature"]
    return [i for i, (c, r) in enumerate(
        zip(challenges, responses, strict=True)
    ) if c < order and r < order]


def _signer_choices(instance):
    choices = [signer_candidates(level, instance.order)
               for level in instance.levels]
    if any(not candidates for candidates in choices):
        raise RuntimeError("no scalar-range-compatible signer in a ring")
    combinations = 1
    for candidates in choices:
        combinations *= len(candidates)
        if combinations > 2_000_000:
            raise RuntimeError("ambiguous signer search exceeds safety bound")
    return choices


def _collect_flags(material, instance, verified, aes, unpad):
    try:
        key = bytes.fromhex(material)
        if len(key) not in (16, 24, 32):
            return
        plaintext = aes.new(
            key, aes.MODE_CBC, iv=instance.iv
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
    except ValueError:
        return


def recover_flag(documents: Sequence[Document]) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no supported source-verified ring scalar anonymity leak")
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    choices = _signer_choices(instance)
    start, end = instance.key_slice
    verified = set()
    for indices in itertools.product(*choices):
        material = "".join(level["public_keys"][index][start:end]
                           for level, index in zip(
                               instance.levels, indices, strict=True))
        _collect_flags(material, instance, verified, AES, unpad)
    if len(verified) != 1:
        raise RuntimeError("no unique, verified flag from ring signer candidates")
    return verified.pop()
