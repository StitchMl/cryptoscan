"""Recover key residues from LWE-like mixtures with structured modular noise.

A source-proven t-bit zero suffix in the additive error exposes exact
linear equations modulo 2**t. Group-wise RANSAC separates coherent real
samples from uniform decoys and lifts the hidden key bits one layer at a time.
No named-challenge constants, known secret or flag are used.
"""
from __future__ import annotations

import ast
import hashlib
import random
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .source_units import parse_python

_FLAG = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,31}\{[^{}\r\n]{1,256}\}")
_MAX_SOURCE = 300000
_MAX_OUTPUT = 4000000


@dataclass(frozen=True)
class ModularNoiseMixture:
    key_bytes: int
    modulus: int
    noise_bits: int
    samples_per_bit: int
    true_bit: int
    groups: tuple[tuple[tuple[bytes, int], ...], ...]


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _const(node):
    return node.value if isinstance(node, ast.Constant) and type(node.value) is int else None


def _call(node, name):
    return isinstance(node, ast.Call) and (
        _name(node.func) == name or isinstance(node.func, ast.Attribute)
        and node.func.attr == name
    )


def _is_len_key(node, key):
    return _call(node, "len") and len(node.args) == 1 and _name(node.args[0]) == key


def _key_generation(function):
    if not isinstance(function, ast.FunctionDef):
        return None
    for stmt in function.body:
        if isinstance(stmt, ast.Return) and _call(stmt.value, "token_bytes"):
            call = stmt.value
            if len(call.args) == 1 and (size := _const(call.args[0])) is not None:
                if 2 <= size <= 32:
                    return size
    return None


def _noise_trailing_zero_bits(function):
    if not isinstance(function, ast.FunctionDef):
        return None
    for start in function.body:
        if not (isinstance(start, ast.Assign) and len(start.targets) == 1
                and (acc := _name(start.targets[0])) is not None
                and _const(start.value) == 0):
            continue
        for loop in function.body:
            if not isinstance(loop, ast.For) or not loop.body:
                continue
            tail = loop.body[-1]
            if not (isinstance(tail, ast.AugAssign) and _name(tail.target) == acc
                    and isinstance(tail.op, ast.LShift)
                    and (shift := _const(tail.value)) is not None
                    and 1 <= shift <= 4):
                continue
            if not any(
                isinstance(node, ast.AugAssign) and _name(node.target) == acc
                and isinstance(node.op, ast.BitOr)
                for node in loop.body[:-1]
            ):
                continue
            try:
                following = function.body[function.body.index(loop) + 1:]
            except ValueError:
                continue
            # Do not infer a divisible error if the accumulator changes
            # between the final shift and the returned value.
            if (len(following) == 1
                    and isinstance(following[0], ast.Return)
                    and _name(following[0].value) == acc):
                return shift
    return None


def _linear_dot(function):
    if not isinstance(function, ast.FunctionDef) or len(function.args.args) < 2:
        return False
    names = [arg.arg for arg in function.args.args[:2]]
    for node in ast.walk(function):
        if not (isinstance(node, ast.Return) and _call(node.value, "sum")
                and len(node.value.args) == 1):
            continue
        gen = node.value.args[0]
        if not (isinstance(gen, (ast.GeneratorExp, ast.ListComp))
                and len(gen.generators) == 1
                and isinstance(gen.elt, ast.BinOp)
                and isinstance(gen.elt.op, ast.Mult)):
            continue
        loop = gen.generators[0]
        if not (isinstance(loop.target, (ast.Tuple, ast.List))
                and len(loop.target.elts) == 2
                and _call(loop.iter, "zip") and len(loop.iter.args) == 2):
            continue
        variables = [_name(x) for x in loop.target.elts]
        factors = [_name(gen.elt.left), _name(gen.elt.right)]
        arguments = [_name(x) for x in loop.iter.args]
        if set(variables) == set(factors) and arguments == names and len(set(variables)) == 2:
            return True
    return False


def _tuple_sampler(function, dots, noises):
    if not isinstance(function, ast.FunctionDef) or len(function.args.args) != 1:
        return None
    key = function.args.args[0].arg
    assignments = {
        stmt.targets[0].id: stmt.value
        for stmt in function.body
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
    }
    for node in function.body:
        if not (isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple)
                and len(node.value.elts) == 2):
            continue
        vec, value = node.value.elts
        vecname = _name(vec)
        if vecname not in assignments or not _call(assignments[vecname], "token_bytes"):
            continue
        vecsource = assignments[vecname]
        if len(vecsource.args) != 1 or not _is_len_key(vecsource.args[0], key):
            continue
        if _call(value, "randbelow") and len(value.args) == 1:
            modulus = _const(value.args[0])
            if modulus and modulus >= 4 and modulus & (modulus - 1) == 0:
                return ("decoy", modulus, None)
        if not (isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod)
                and (modulus := _const(value.right)) is not None
                and modulus >= 4 and modulus & (modulus - 1) == 0):
            continue
        added = value.left
        if not (isinstance(added, ast.BinOp) and isinstance(added.op, ast.Add)):
            continue
        for linear, noise in ((added.left, added.right), (added.right, added.left)):
            if not (isinstance(linear, ast.Call)
                    and _name(linear.func) in dots and len(linear.args) == 2
                    and [_name(x) for x in linear.args] == [vecname, key]):
                continue
            noise_value = assignments.get(_name(noise)) if isinstance(noise, ast.Name) else noise
            offset = 0
            if (isinstance(noise_value, ast.BinOp)
                    and isinstance(noise_value.op, ast.Sub)
                    and (sub := _const(noise_value.right)) is not None):
                offset = sub
                noise_value = noise_value.left
            if (isinstance(noise_value, ast.Call)
                    and (noise_name := _name(noise_value.func)) in noises
                    and offset % (1 << noises[noise_name]) == 0):
                return ("real", modulus, noises[noise_name])
    return None


def _flag_bits(function):
    """Ensure that the source packs each byte least-significant bit first."""
    if not isinstance(function, ast.FunctionDef):
        return False
    for stmt in function.body:
        if not (isinstance(stmt, ast.Return)
                and isinstance(stmt.value, ast.ListComp)):
            continue
        generator = stmt.value
        if len(generator.generators) != 2:
            continue
        expression = generator.elt
        loop = generator.generators[1]
        index = _name(loop.target)
        if (isinstance(expression, ast.BinOp)
                and isinstance(expression.op, ast.BitAnd)
                and _const(expression.right) == 1
                and isinstance(expression.left, ast.BinOp)
                and isinstance(expression.left.op, ast.RShift)
                and _name(expression.left.right) == index
                and _call(loop.iter, "range")
                and len(loop.iter.args) == 1
                and _const(loop.iter.args[0]) == 8):
            return True
    return False


def _key_initialized_before(tree, bit_loop, key_arg, generators):
    """Prove one key is constructed outside and before the bit loop."""
    for container in ast.walk(tree):
        statements = getattr(container, "body", None)
        if not isinstance(statements, list) or bit_loop not in statements:
            continue
        for statement in statements[:statements.index(bit_loop)]:
            if (isinstance(statement, ast.Assign)
                    and len(statement.targets) == 1
                    and _name(statement.targets[0]) == key_arg
                    and isinstance(statement.value, ast.Call)
                    and _name(statement.value.func) in generators):
                return True
    return False


def _source_profile(source):
    if not source or len(source) > _MAX_SOURCE:
        return None
    tree = parse_python(Document("unknown-source", source, None))
    if tree is None:
        return None
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    keys = {name: size for name, fn in functions.items()
            if (size := _key_generation(fn)) is not None}
    noises = {name: bits for name, fn in functions.items()
              if (bits := _noise_trailing_zero_bits(fn)) is not None}
    dots = {name for name, fn in functions.items() if _linear_dot(fn)}
    if len(keys) != 1 or not noises or not dots:
        return None
    roles = {name: role for name, fn in functions.items()
             if (role := _tuple_sampler(fn, dots, noises)) is not None}
    reals = [(name, role) for name, role in roles.items() if role[0] == "real"]
    decoys = [(name, role) for name, role in roles.items() if role[0] == "decoy"]
    if len(reals) != 1 or len(decoys) != 1:
        return None
    real_name, real = reals[0]
    decoy_name, decoy = decoys[0]
    if real[1] != decoy[1] or real[2] > real[1].bit_length() - 1:
        return None
    bit_functions = {
        name for name, fn in functions.items() if _flag_bits(fn)
    }
    if not bit_functions:
        return None
    candidates = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ListComp) and len(node.generators) == 1
                and isinstance(node.elt, ast.Call)
                and len(node.elt.args) == 1
                and isinstance(node.elt.func, ast.Subscript)
                and isinstance(node.elt.func.value, (ast.List, ast.Tuple))):
            continue
        options = node.elt.func.value.elts
        if len(options) != 2:
            continue
        order = [_name(item) for item in options]
        if set(order) != {real_name, decoy_name}:
            continue
        loop = node.generators[0].iter
        if not (_call(loop, "range") and len(loop.args) == 1):
            continue
        samples = _const(loop.args[0])
        if samples is None or not 2 <= samples <= 32:
            continue
        parents = [
            parent for parent in ast.walk(tree)
            if isinstance(parent, (ast.For, ast.ListComp))
            and node is not parent
            and any(child is node for child in ast.walk(parent))
        ]
        if not any(
            isinstance(parent, ast.For)
            and isinstance(parent.iter, ast.Call)
            and _name(parent.iter.func) in bit_functions
            for parent in parents
        ):
            continue
        key_arg = _name(node.elt.args[0])
        if key_arg is not None and any(
            _key_initialized_before(tree, parent, key_arg, keys)
            for parent in parents
            if isinstance(parent, ast.For)
            and isinstance(parent.iter, ast.Call)
            and _name(parent.iter.func) in bit_functions
        ):
            candidates.append((next(iter(keys.values())), real[1], real[2],
                               samples, order.index(real_name)))
    return candidates[0] if len(candidates) == 1 else None


def _transcript(document, size, modulus, count):
    if len(document.text) > _MAX_OUTPUT:
        return None
    groups = []
    for line in document.text.splitlines():
        if not line.strip():
            continue
        if len(line) > 10000:
            return None
        try:
            block = ast.literal_eval(line)
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            return None
        if not isinstance(block, list) or len(block) != count:
            return None
        observed = []
        for item in block:
            if (not isinstance(item, (tuple, list)) or len(item) != 2
                    or not isinstance(item[0], bytes)
                    or len(item[0]) != size or type(item[1]) is not int
                    or not 0 <= item[1] < modulus):
                return None
            observed.append((item[0], item[1]))
        groups.append(tuple(observed))
    if len(groups) < 32 or len(groups) % 8:
        return None
    return tuple(groups)


def extract_instance(documents: Sequence[Document]):
    matches = []
    for source in documents:
        profile = _source_profile(source.text)
        if profile is None:
            continue
        size, modulus, bits, samples, real_bit = profile
        for transcript in documents:
            if transcript.scope != source.scope or transcript.path == source.path:
                continue
            groups = _transcript(transcript, size, modulus, samples)
            if groups is not None:
                matches.append(ModularNoiseMixture(
                    size, modulus, bits, samples, real_bit, groups,
                ))
    return matches[0] if len(matches) == 1 else None


def _gf2_solve(equations, width):
    pivots = {}
    for coefficients, rhs in equations:
        row = coefficients | ((rhs & 1) << width)
        while row & ((1 << width) - 1):
            bit = (row & -row).bit_length() - 1
            if bit in pivots:
                row ^= pivots[bit]
            else:
                pivots[bit] = row
                break
        else:
            if row >> width:
                return None
    if len(pivots) != width:
        return None
    result = 0
    for bit in sorted(pivots, reverse=True):
        equation = pivots[bit]
        value = (equation >> width) & 1
        value ^= ((equation & ((1 << width) - 1) & ~(1 << bit)) & result).bit_count() & 1
        result |= value << bit
    return result


def _consistent(group, key_digits, modulus):
    return all(
        (sum(a * s for a, s in zip(vector, key_digits)) - value) % modulus == 0
        for vector, value in group
    )


def _recover_key(model, *, trials=4096):
    size, t = model.key_bytes, model.noise_bits
    groups = model.groups
    rnd = random.Random(int.from_bytes(hashlib.sha256(
        repr(groups[:8]).encode("utf-8")).digest()[:8], "big"))
    digits = [0] * size
    for layer in range(t):
        candidates = list(range(len(groups))) if layer == 0 else [
            idx for idx, block in enumerate(groups)
            if _consistent(block, digits, 1 << layer)
        ]
        minimum = (size + 2 + model.samples_per_bit - 1) // model.samples_per_bit
        if len(candidates) < minimum:
            raise RuntimeError("not enough consistent samples for modular-noise recovery")
        best_key, best_score = None, -1
        for _ in range(trials):
            selected = rnd.sample(candidates, minimum)
            equations = []
            for index in selected:
                for vector, value in groups[index]:
                    mask = sum((int(a) & 1) << j for j, a in enumerate(vector))
                    digit = ((value - sum(a * s for a, s in zip(vector, digits))) >> layer) & 1
                    equations.append((mask, digit))
            solved = _gf2_solve(equations, size)
            if solved is None:
                continue
            hypothetical = [
                digits[j] + (((solved >> j) & 1) << layer)
                for j in range(size)
            ]
            modulus = 1 << (layer + 1)
            score = sum(
                _consistent(groups[idx], hypothetical, modulus)
                for idx in candidates
            )
            if score > best_score:
                best_key, best_score = hypothetical, score
            if score > .40 * len(candidates):
                break
        expected_decoy_matches = len(candidates) / (2 ** model.samples_per_bit)
        if best_key is None or best_score < max(8, 6 * expected_decoy_matches):
            raise RuntimeError("no statistically distinguishable linear secret recovered")
        digits = best_key
    return tuple(digits)


def recover_details(model: ModularNoiseMixture, *, trials=4096):
    key = _recover_key(model, trials=trials)
    modulus = 1 << model.noise_bits
    matches = [_consistent(block, key, modulus) for block in model.groups]
    bits = [model.true_bit if match else 1 - model.true_bit for match in matches]
    plaintext = bytes(
        sum(bits[start + index] << index for index in range(8))
        for start in range(0, len(bits), 8)
    )
    try:
        decoded = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("recovered bit classes are not valid UTF-8") from exc
    if not _FLAG.fullmatch(decoded):
        raise RuntimeError("recovered bit classes fail the flag text format")
    return decoded, {
        "key_residues": key,
        "noise_divisibility": modulus,
        "matched_blocks": sum(matches),
        "total_blocks": len(matches),
        "sample_count": model.samples_per_bit,
        "residual_fake_false_positive_probability": modulus ** -model.samples_per_bit,
    }


def recover_flag(documents: Sequence[Document], *, trials=4096):
    model = extract_instance(documents)
    if model is None:
        raise ValueError("no source-verified modular-noise mixture")
    return recover_details(model, trials=trials)[0]
