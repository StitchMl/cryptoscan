"""Offline recovery from reversible message-recovery signatures hidden among decoys.

Generic extended twisted-Edwards arithmetic and source-derived SHA-256 domain
separation are used; no curve, key, flag, filenames or challenge data are baked in.
"""
from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .source_units import parse_python

MAX_PAIRS = 50000
IDENTITY = (0, 1, 1, 0)


@dataclass(frozen=True)
class MaskedSignature:
    field: int
    a: int
    d: int
    generator: tuple[int, int]
    subgroup_order: int
    transform: ast.expr
    coordinate_names: tuple[str, str]
    field_parameter_names: tuple[str, str]
    f1: bytes
    f2: bytes
    signature_hash: bytes
    separator: bytes
    counter_width: int
    counter_byteorder: str
    key_bytes: int
    kdf_salt: bytes
    kdf_rounds: int
    kdf_length: int
    nonce: bytes


@dataclass(frozen=True)
class RecoveryInstance:
    scheme: MaskedSignature
    public_point: tuple[int, int]
    ciphertext: bytes
    signatures: tuple[tuple[bytes, int], ...]


def _assignments(tree: ast.AST):
    return {
        node.targets[0].id: node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    }


def _static_integer(node):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_static_integer(node.operand)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add, ast.Sub)):
        left, right = _static_integer(node.left), _static_integer(node.right)
        if isinstance(node.op, ast.Mult):
            return left * right
        return left + right if isinstance(node.op, ast.Add) else left - right
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
        # Sage preparser writes exponentiation with ^; never execute source.
        base, exponent = _static_integer(node.left), _static_integer(node.right)
        if 0 <= exponent <= 2048 and 0 <= base <= 2**1024:
            return base ** exponent
    raise ValueError("unsupported static integer expression")


def _literal_call(node, func: str):
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return None
    if node.func.id != func or len(node.args) != 1:
        return None
    try:
        return _static_integer(node.args[0])
    except (ValueError, OverflowError):
        return None


def _field_eval(node, values, p):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value % p
    if isinstance(node, ast.Name) and node.id in values:
        return values[node.id] % p
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_field_eval(node.operand, values, p) % p
    if isinstance(node, ast.BinOp):
        left = _field_eval(node.left, values, p)
        right = _field_eval(node.right, values, p)
        if isinstance(node.op, ast.Add):
            return (left + right) % p
        if isinstance(node.op, ast.Sub):
            return (left - right) % p
        if isinstance(node.op, ast.Mult):
            return (left * right) % p
        if isinstance(node.op, ast.Div):
            return (left * pow(right, -1, p)) % p
    raise ValueError("unsupported coordinate transformation")


def _curve_spec(tree):
    for fn in (item for item in tree.body if isinstance(item, ast.FunctionDef)):
        assignments = _assignments(fn)
        field = next((
            (target, assignments[node.args[0].id])
            for target, node in assignments.items()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "GF" and len(node.args) == 1
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in assignments
        ), None)
        if field is None:
            continue
        try:
            p = _static_integer(field[1])
        except ValueError:
            continue
        if not 127 <= p.bit_length() <= 1024 or p % 2 == 0:
            continue
        scalars = {}
        for name, expr in assignments.items():
            value = _literal_call(expr, field[0])
            if value is not None:
                scalars[name] = value % p
        transforms = [
            inner for inner in fn.body if isinstance(inner, ast.FunctionDef)
            and len(inner.args.args) == 2
            and any(isinstance(stmt, ast.Return)
                    and isinstance(stmt.value, ast.Tuple)
                    and len(stmt.value.elts) == 2 for stmt in inner.body)
        ]
        calls = [
            node for node in ast.walk(fn) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "set_order" and len(node.args) == 1
        ]
        if len(calls) != 1 or not transforms:
            continue
        try:
            group_size = _static_integer(calls[0].args[0])
        except ValueError:
            continue
        generators = [
            node for node in ast.walk(fn) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and len(node.args) == 2
            and all(_literal_call(arg, field[0]) is not None for arg in node.args)
        ]
        if len(generators) != 1:
            continue
        coords = tuple(_literal_call(arg, field[0]) for arg in generators[0].args)
        transform = next((
            inner for inner in transforms
            if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                   and node.func.id == inner.name and node is not generators[0]
                   for node in ast.walk(fn))
            and any(isinstance(node, ast.Name) and node.id in scalars
                    for node in ast.walk(inner))
        ), None)
        if transform is None:
            continue
        result = next(item for item in transform.body if isinstance(item, ast.Return))
        if not isinstance(result.value, ast.Tuple):
            continue
        params = tuple(item.arg for item in transform.args.args)
        if len(scalars) < 2:
            continue
        edwards = [
            (name_a, name_d)
            for name_a in scalars for name_d in scalars if name_a != name_d
            if (scalars[name_a]*coords[0]**2 + coords[1]**2
                - 1 - scalars[name_d]*coords[0]**2*coords[1]**2) % p == 0
            and all(any(isinstance(item, ast.Name) and item.id == name
                        for item in ast.walk(result.value.elts[0]))
                    for name in (name_a, name_d))
        ]
        if len(edwards) != 1:
            continue
        name_a, name_d = edwards[0]
        a, d = scalars[name_a], scalars[name_d]
        subgroup = None
        for factor in (16, 8, 4, 2, 1):
            if group_size % factor:
                continue
            candidate = group_size // factor
            if candidate.bit_length() >= 120 and _multiply(
                    _point(coords, p), candidate, p, a, d) == IDENTITY:
                subgroup = candidate
                break
        if subgroup is None:
            continue
        return (p, a, d, coords, subgroup, result.value.elts[0], params,
                (name_a, name_d))
    return None


def _hash_scheme(tree):
    assignments = _assignments(tree)
    lambdas = {
        name: value for name, value in assignments.items()
        if isinstance(value, ast.Lambda) and isinstance(value.body, ast.Call)
        and len(value.body.args) == 4
        and isinstance(value.body.args[-1], ast.Constant)
        and isinstance(value.body.args[-1].value, bytes)
    }
    if len(lambdas) < 3:
        return None
    for fn in (item for item in tree.body if isinstance(item, ast.FunctionDef)):
        code = ast.unparse(fn)
        if not ("secrets.randbelow" in code and "xor(" in code and ".hex()" in code):
            continue
        sign_assigns = _assignments(fn)
        composite = [
            expr for expr in sign_assigns.values()
            if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add)
            and isinstance(expr.left, ast.Call)
            and isinstance(expr.left.func, ast.Name)
        ]
        for expr in composite:
            first = expr.left.func.id
            if first not in lambdas:
                continue
            right = expr.right
            if not (isinstance(right, ast.Call) and len(right.args) == 2
                    and isinstance(right.args[0], ast.Call)
                    and isinstance(right.args[0].func, ast.Name)):
                continue
            second = right.args[0].func.id
            if second not in lambdas:
                continue
            remaining = [
                value.body.args[3].value for name, value in lambdas.items()
                if name not in (first, second)
            ]
            if len(remaining) != 1:
                continue
            f1 = lambdas[first].body.args[3].value
            f2 = lambdas[second].body.args[3].value
            return f1, f2, remaining[0]
    return None


def _kdf_scheme(tree):
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "kdf" and len(node.args) == 4
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, bytes)):
            continue
        try:
            length = _static_integer(node.args[2])
            rounds = _static_integer(node.args[3])
        except ValueError:
            continue
        if not (1 <= length <= 64 and 1 <= rounds <= 1000000):
            continue
        aes = [
            item for item in ast.walk(tree)
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)
            and item.func.attr == "new" and any(
                isinstance(value, ast.Attribute) and value.attr == "MODE_CTR"
                for value in ast.walk(item)
            )
        ]
        if len(aes) != 1:
            continue
        nonce = next((value.value for value in aes[0].keywords
                      if value.arg == "nonce" and isinstance(value.value, ast.Constant)
                      and isinstance(value.value.value, bytes)), None)
        if nonce is not None:
            return node.args[1].value, rounds, length, nonce
    return None


def _hash_parameters(tree):
    for fn in (item for item in tree.body if isinstance(item, ast.FunctionDef)):
        hashes = [node for node in ast.walk(fn)
                  if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr == "sha256"]
        if len(hashes) != 1:
            continue
        constants = [
            node.value for node in ast.walk(hashes[0])
            if isinstance(node, ast.Constant) and isinstance(node.value, bytes)
        ]
        counters = [
            node for node in ast.walk(hashes[0])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "to_bytes" and len(node.args) == 2
            and isinstance(node.args[0], ast.Constant)
            and type(node.args[0].value) is int
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in ("big", "little")
        ]
        if len(constants) == 1 and len(counters) == 1:
            counter = counters[0]
            return constants[0], counter.args[0].value, counter.args[1].value
    return None


def _source_model(doc: Document) -> MaskedSignature | None:
    tree = parse_python(doc)
    if tree is None:
        return None
    scheme = _hash_scheme(tree)
    curve = _curve_spec(tree)
    kdf = _kdf_scheme(tree)
    hash_parameters = _hash_parameters(tree)
    if not all((scheme, curve, kdf, hash_parameters)):
        return None
    p, a, d, G, order, transform, params, field_names = curve
    constants = {field_names[0]: a, field_names[1]: d}
    try:
        test_point = _field_eval(
            transform, {**constants, params[0]: G[0], params[1]: G[1]}, p,
        )
    except (ValueError, ZeroDivisionError):
        return None
    if not 0 <= test_point < p:
        return None
    top_level = _assignments(tree)
    key_length_calls = [
        node.args[0] for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "token_bytes" and len(node.args) == 1
    ]
    key_lengths = []
    for expr in key_length_calls:
        if (isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.FloorDiv)
                and isinstance(expr.left, ast.Name)
                and isinstance(expr.right, ast.Constant)
                and expr.right.value == 8 and expr.left.id in top_level):
            try:
                key_lengths.append(_static_integer(top_level[expr.left.id]))
            except ValueError:
                continue
    k2 = key_lengths[0] if len(key_lengths) == 1 else None
    if k2 is None or k2 % 8:
        return None
    return MaskedSignature(p, a, d, G, order, transform, params,
                           field_names, *scheme, *hash_parameters, k2//8, *kdf)


def _point(xy, p):
    x, y = xy
    return x % p, y % p, 1, x*y % p


def _add(first, second, p, a, d):
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    aa, bb = x1*x2 % p, y1*y2 % p
    cc, dd = d*t1*t2 % p, z1*z2 % p
    ee = ((x1+y1)*(x2+y2)-aa-bb) % p
    ff, gg = (dd-cc) % p, (dd+cc) % p
    hh = (bb-a*aa) % p
    return ee*ff%p, gg*hh%p, ff*gg%p, ee*hh%p


def _double(point, p, a):
    x, y, z, unused = point
    xx, yy, zz = x*x%p, y*y%p, 2*z*z%p
    dd = a*xx%p
    ee = ((x+y)**2-xx-yy)%p
    gg = (dd+yy)%p
    ff, hh = (gg-zz)%p, (dd-yy)%p
    return ee*ff%p, gg*hh%p, ff*gg%p, ee*hh%p


def _multiply(point, scalar, p, a, d):
    result = IDENTITY
    while scalar:
        if scalar & 1:
            result = _add(result, point, p, a, d)
        point = _double(point, p, a)
        scalar >>= 1
    return result


def _tables(generator, public, order, p, a, d):
    width = (order.bit_length()+7)//4 + 3
    tables = []
    for coords in (generator, public):
        current = _point(coords, p)
        by_digit = []
        for _ in range(width):
            values = [IDENTITY, current]
            for _ in range(2, 16):
                values.append(_add(values[-1], current, p, a, d))
            by_digit.append(values)
            for _ in range(4):
                current = _double(current, p, a)
        tables.append(by_digit)
    return tables


def _linear_combination(z, c, tables, p, a, d):
    result = IDENTITY
    for position in range(len(tables[0])):
        if z == 0 and c == 0:
            break
        if (value := z & 15):
            result = _add(result, tables[0][position][value], p, a, d)
        if (value := c & 15):
            result = _add(result, tables[1][position][value], p, a, d)
        z >>= 4
        c >>= 4
    if z or c:
        raise ValueError("signature scalar exceeds precomputed range")
    return result


def _expand_sha256(data, length, domain, separator, width, order):
    result = bytearray()
    for counter in range((length+31)//32):
        result.extend(hashlib.sha256(
            data + separator + domain + counter.to_bytes(width, order),
        ).digest())
    return bytes(result[:length])


def _read_output(document: Document, key_bytes: int):
    if len(document.text) > 15000000:
        return None
    lines = document.text.splitlines()
    pub = None
    encrypted = None
    signatures = None
    for line in lines[:6]:
        record = line.partition("=")[2].strip()
        if not record:
            continue
        if record.startswith("(") and record.endswith(")"):
            try:
                value = ast.literal_eval(record)
            except (ValueError, SyntaxError):
                continue
            if (type(value) is tuple and len(value) == 2
                    and all(type(x) is int for x in value)):
                pub = value
        elif re.fullmatch(r"[a-fA-F0-9]{2,4096}", record):
            encrypted = bytes.fromhex(record)
    for line in lines:
        candidate = line.strip()
        if not candidate.startswith("[("):
            continue
        try:
            values = ast.literal_eval(candidate)
        except (ValueError, SyntaxError, RecursionError):
            continue
        if (not isinstance(values, list) or not 2 <= len(values) <= MAX_PAIRS):
            continue
        pairs = []
        for element in values:
            if not (isinstance(element, tuple) and len(element) == 2
                    and isinstance(element[0], str)
                    and type(element[1]) is int and element[1] >= 0
                    and len(element[0]) <= 4096):
                break
            try:
                pairs.append((bytes.fromhex(element[0]), element[1]))
            except ValueError:
                break
        if len(pairs) == len(values):
            signatures = tuple(pairs)
            break
    if (pub is not None and encrypted is not None and signatures
            and any(len(r) > key_bytes for r, _ in signatures)):
        return pub, encrypted, signatures
    return None


def extract_instance(documents: Sequence[Document]) -> RecoveryInstance | None:
    matches = []
    for source in documents:
        scheme = _source_model(source)
        if scheme is None:
            continue
        for record in documents:
            if source.path == record.path or source.scope != record.scope:
                continue
            parsed = _read_output(record, scheme.key_bytes)
            if parsed is None:
                continue
            pub, ciphertext, signatures = parsed
            p, a, d = scheme.field, scheme.a, scheme.d
            x, y = pub
            if not (0 <= x < p and 0 <= y < p
                    and (a*x*x + y*y - 1 - d*x*x*y*y) % p == 0):
                continue
            if any(z >= scheme.subgroup_order for _, z in signatures):
                continue
            if len({len(r) for r, _ in signatures}) != 1:
                continue
            matches.append(RecoveryInstance(scheme, pub, ciphertext, signatures))
    return matches[0] if len(matches) == 1 else None


def recover_flag(documents: Sequence[Document], progress=print) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no source-verified reversible masked EC signature corpus")
    scheme = instance.scheme
    p, a, d = scheme.field, scheme.a, scheme.d
    byte_width = len(instance.signatures[0][0])
    if byte_width <= scheme.key_bytes or byte_width > 256:
        raise ValueError("unsupported message recovery encoding")
    f1len = byte_width - scheme.key_bytes
    expand = lambda data, length, domain: _expand_sha256(
        data, length, domain, scheme.separator,
        scheme.counter_width, scheme.counter_byteorder,
    )
    tables = _tables(scheme.generator, instance.public_point,
                     scheme.subgroup_order, p, a, d)
    constants = {scheme.field_parameter_names[0]: a,
                 scheme.field_parameter_names[1]: d}
    for index, (r, z) in enumerate(instance.signatures):
        challenge = int.from_bytes(expand(r, byte_width, scheme.signature_hash), "big")
        point = _linear_combination(z, challenge, tables, p, a, d)
        if point[2] % p == 0:
            continue
        affine = (point[0]*pow(point[2], -1, p) % p,
                  point[1]*pow(point[2], -1, p) % p)
        values = {**constants, scheme.coordinate_names[0]: affine[0],
                  scheme.coordinate_names[1]: affine[1]}
        try:
            coord = _field_eval(scheme.transform, values, p)
            masked = bytes(left ^ right for left, right in zip(
                coord.to_bytes(byte_width, "big"), r, strict=True,
            ))
        except (OverflowError, ValueError, ZeroDivisionError):
            continue
        prefix, tail = masked[:f1len], masked[f1len:]
        derived = expand(prefix, scheme.key_bytes, scheme.f2)
        key_material = bytes(x ^ y for x, y in zip(tail, derived, strict=True))
        if expand(key_material, f1len, scheme.f1) != prefix:
            continue
        progress(f"[MASKED-EC-SIGNATURE] Verified candidate {index+1}/{len(instance.signatures)}")
        try:
            import bcrypt
            from Crypto.Cipher import AES
        except ImportError as exc:
            raise RuntimeError(
                "Install optional cipher dependencies: python -m pip install bcrypt pycryptodome"
            ) from exc
        key = bcrypt.kdf(
            password=key_material, salt=scheme.kdf_salt,
            desired_key_bytes=scheme.kdf_length, rounds=scheme.kdf_rounds,
        )
        plaintext = AES.new(key, AES.MODE_CTR, nonce=scheme.nonce).decrypt(
            instance.ciphertext,
        )
        try:
            result = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("recovered AES plaintext is not UTF-8") from exc
        if not re.search(r"\w{2,32}\{[^\r\n{}]{1,256}\}", result):
            raise ValueError("verified candidate does not decrypt to a CTF flag")
        return result
    raise RuntimeError("no signature candidate passed the independent message hash check")
