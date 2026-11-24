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


_STATIC_ARITHMETIC = {
    ast.Mult: lambda left, right: left * right,
    ast.Add: lambda left, right: left + right,
    ast.Sub: lambda left, right: left - right,
}


def _static_power(node):
    # Sage preparser writes exponentiation with ^; never execute source.
    base, exponent = _static_integer(node.left), _static_integer(node.right)
    if 0 <= exponent <= 2048 and 0 <= base <= 2**1024:
        return base ** exponent
    raise ValueError("unsupported static integer expression")


def _static_integer(node):
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_static_integer(node.operand)
    if isinstance(node, ast.BinOp) and type(node.op) in _STATIC_ARITHMETIC:
        left, right = _static_integer(node.left), _static_integer(node.right)
        return _STATIC_ARITHMETIC[type(node.op)](left, right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
        return _static_power(node)
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


_FIELD_ARITHMETIC = {
    ast.Add: lambda left, right, p: (left + right) % p,
    ast.Sub: lambda left, right, p: (left - right) % p,
    ast.Mult: lambda left, right, p: (left * right) % p,
    ast.Div: lambda left, right, p: (left * pow(right, -1, p)) % p,
}


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
        operation = _FIELD_ARITHMETIC.get(type(node.op))
        if operation is not None:
            return operation(left, right, p)
    raise ValueError("unsupported coordinate transformation")


def _curve_field(fn):
    assignments = _assignments(fn)
    for alias, node in assignments.items():
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "GF" and len(node.args) == 1
                and isinstance(node.args[0], ast.Name)):
            continue
        modulus_node = assignments.get(node.args[0].id)
        if modulus_node is None:
            continue
        try:
            modulus = _static_integer(modulus_node)
        except ValueError:
            continue
        if 127 <= modulus.bit_length() <= 1024 and modulus % 2:
            return modulus, alias, assignments
    return None


def _curve_constants(assignments, field_alias, modulus):
    constants = {}
    for name, expr in assignments.items():
        value = _literal_call(expr, field_alias)
        if value is not None:
            constants[name] = value % modulus
    return constants


def _curve_generator(fn, field_alias):
    candidates = [
        node for node in ast.walk(fn) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name) and len(node.args) == 2
        and all(_literal_call(arg, field_alias) is not None for arg in node.args)
    ]
    if len(candidates) != 1:
        return None
    call = candidates[0]
    coordinates = tuple(_literal_call(arg, field_alias) for arg in call.args)
    return call.func.id, coordinates


def _curve_conversion(fn, generator_name, constants, xy, modulus):
    transforms = [
        inner for inner in fn.body if isinstance(inner, ast.FunctionDef)
        and inner.name == generator_name and len(inner.args.args) == 2
        and any(isinstance(stmt, ast.Return)
                and isinstance(stmt.value, ast.Tuple)
                and len(stmt.value.elts) == 2 for stmt in inner.body)
    ]
    if len(transforms) != 1:
        return None
    transform = transforms[0]
    result = next(
        stmt.value.elts[0] for stmt in transform.body
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Tuple)
    )
    used = {
        item.id for item in ast.walk(result) if isinstance(item, ast.Name)
    }
    options = [
        (name_a, name_d)
        for name_a in constants for name_d in constants
        if name_a != name_d and {name_a, name_d} <= used
        and (constants[name_a]*xy[0]**2 + xy[1]**2 - 1
             - constants[name_d]*xy[0]**2*xy[1]**2) % modulus == 0
    ]
    if len(options) != 1:
        return None
    return options[0], result, tuple(arg.arg for arg in transform.args.args)


def _curve_order(fn, generator, modulus, alpha, delta):
    setters = [
        node for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "set_order" and len(node.args) == 1
    ]
    if len(setters) != 1:
        return None
    try:
        group_size = _static_integer(setters[0].args[0])
    except ValueError:
        return None
    for cofactor in (16, 8, 4, 2, 1):
        if group_size % cofactor:
            continue
        order = group_size // cofactor
        if order.bit_length() < 120:
            continue
        point = _multiply(_point(generator, modulus), order,
                          modulus, alpha, delta)
        if point[0] % modulus == 0 and (point[1]-point[2]) % modulus == 0:
            return order
    return None


def _curve_spec(tree):
    for fn in (item for item in tree.body if isinstance(item, ast.FunctionDef)):
        context = _curve_field(fn)
        if context is None:
            continue
        p, field_alias, assignments = context
        constants = _curve_constants(assignments, field_alias, p)
        generator = _curve_generator(fn, field_alias)
        if generator is None:
            continue
        converter, coords = generator
        converted = _curve_conversion(fn, converter, constants, coords, p)
        if converted is None:
            continue
        field_names, expression, parameter_names = converted
        alpha, delta = (constants[name] for name in field_names)
        order = _curve_order(fn, coords, p, alpha, delta)
        if order is not None:
            return (p, alpha, delta, coords, order, expression,
                    parameter_names, field_names)
    return None


def _masked_call_names(expression, lambdas):
    if not (isinstance(expression, ast.BinOp)
            and isinstance(expression.op, ast.Add)
            and isinstance(expression.left, ast.Call)
            and isinstance(expression.left.func, ast.Name)):
        return None
    first = expression.left.func.id
    right = expression.right
    if not (isinstance(right, ast.Call) and len(right.args) == 2
            and isinstance(right.args[0], ast.Call)
            and isinstance(right.args[0].func, ast.Name)):
        return None
    second = right.args[0].func.id
    if first == second or first not in lambdas or second not in lambdas:
        return None
    return first, second


def _hash_scheme(tree):
    lambdas = {
        name: value for name, value in _assignments(tree).items()
        if isinstance(value, ast.Lambda) and isinstance(value.body, ast.Call)
        and len(value.body.args) == 4
        and isinstance(value.body.args[-1], ast.Constant)
        and isinstance(value.body.args[-1].value, bytes)
    }
    if len(lambdas) != 3:
        return None
    for fn in (item for item in tree.body if isinstance(item, ast.FunctionDef)):
        code = ast.unparse(fn)
        if not all(marker in code for marker in (
            "secrets.randbelow", "xor(", ".hex()",
        )):
            continue
        for expression in _assignments(fn).values():
            names = _masked_call_names(expression, lambdas)
            if names is None:
                continue
            first, second = names
            third = next(name for name in lambdas if name not in names)
            return tuple(
                lambdas[name].body.args[3].value
                for name in (first, second, third)
            )
    return None


def _ctr_nonce(tree):
    aes = [
        item for item in ast.walk(tree)
        if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)
        and item.func.attr == "new" and any(
            isinstance(value, ast.Attribute) and value.attr == "MODE_CTR"
            for value in ast.walk(item)
        )
    ]
    if len(aes) != 1:
        return None
    return next(
        (keyword.value.value for keyword in aes[0].keywords
         if keyword.arg == "nonce"
         and isinstance(keyword.value, ast.Constant)
         and isinstance(keyword.value.value, bytes)),
        None,
    )


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
        nonce = _ctr_nonce(tree)
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


def _secret_byte_count(tree) -> int | None:
    assignments = _assignments(tree)
    calls = [
        node.args[0] for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "token_bytes" and len(node.args) == 1
    ]
    lengths = []
    for expr in calls:
        if not (isinstance(expr, ast.BinOp)
                and isinstance(expr.op, ast.FloorDiv)
                and isinstance(expr.left, ast.Name)
                and isinstance(expr.right, ast.Constant)
                and expr.right.value == 8
                and expr.left.id in assignments):
            continue
        try:
            length_bits = _static_integer(assignments[expr.left.id])
        except ValueError:
            continue
        if 64 <= length_bits <= 512 and length_bits % 8 == 0:
            lengths.append(length_bits // 8)
    return lengths[0] if len(lengths) == 1 else None


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
    key_bytes = _secret_byte_count(tree)
    if key_bytes is None:
        return None
    return MaskedSignature(p, a, d, G, order, transform, params,
                           field_names, *scheme, *hash_parameters, key_bytes, *kdf)


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


def _public_and_ciphertext(lines):
    public, ciphertext = None, None
    for line in lines[:6]:
        record = line.partition("=")[2].strip()
        if record.startswith("(") and record.endswith(")"):
            try:
                point = ast.literal_eval(record)
            except (SyntaxError, ValueError):
                continue
            if (type(point) is tuple and len(point) == 2
                    and all(type(value) is int for value in point)):
                public = point
        elif re.fullmatch(r"[a-fA-F0-9]{2,4096}", record):
            ciphertext = bytes.fromhex(record)
    return public, ciphertext


def _parse_signature_rows(source: str):
    try:
        values = ast.literal_eval(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    if not isinstance(values, list) or not 2 <= len(values) <= MAX_PAIRS:
        return None
    signatures = []
    for element in values:
        if not (isinstance(element, tuple) and len(element) == 2
                and isinstance(element[0], str)
                and type(element[1]) is int and element[1] >= 0
                and 2 <= len(element[0]) <= 4096):
            return None
        try:
            signatures.append((bytes.fromhex(element[0]), element[1]))
        except ValueError:
            return None
    return tuple(signatures)


def _read_output(document: Document, key_bytes: int):
    if len(document.text) > 15000000:
        return None
    lines = document.text.splitlines()
    public, ciphertext = _public_and_ciphertext(lines)
    if public is None or ciphertext is None:
        return None
    for line in lines:
        candidate = line.strip()
        if candidate.startswith("[("):
            signatures = _parse_signature_rows(candidate)
            if signatures and any(len(r) > key_bytes for r, _ in signatures):
                return public, ciphertext, signatures
    return None


def _valid_recovery_data(scheme, point, signatures):
    p, a, d = scheme.field, scheme.a, scheme.d
    x, y = point
    return (
        0 <= x < p and 0 <= y < p
        and (a*x*x + y*y - 1 - d*x*x*y*y) % p == 0
        and all(0 <= z < scheme.subgroup_order for _, z in signatures)
        and len({len(r) for r, _ in signatures}) == 1
    )


def _instances_for_source(source, scheme, documents):
    for record in documents:
        if source.path == record.path or source.scope != record.scope:
            continue
        parsed = _read_output(record, scheme.key_bytes)
        if parsed is None:
            continue
        public, ciphertext, signatures = parsed
        if _valid_recovery_data(scheme, public, signatures):
            yield RecoveryInstance(scheme, public, ciphertext, signatures)


def extract_instance(documents: Sequence[Document]) -> RecoveryInstance | None:
    candidates = []
    for source in documents:
        scheme = _source_model(source)
        if scheme is not None:
            candidates.extend(_instances_for_source(source, scheme, documents))
    return candidates[0] if len(candidates) == 1 else None


def _masked_message(scheme, r, z, byte_width, tables, expand):
    """Recover a single candidate by reversing the source-defined mask."""
    p, a, d = scheme.field, scheme.a, scheme.d
    challenge = int.from_bytes(
        expand(r, byte_width, scheme.signature_hash), "big",
    )
    point = _linear_combination(z, challenge, tables, p, a, d)
    if point[2] % p == 0:
        return None
    inverse = pow(point[2], -1, p)
    affine = (point[0]*inverse % p, point[1]*inverse % p)
    values = {
        scheme.field_parameter_names[0]: a,
        scheme.field_parameter_names[1]: d,
        scheme.coordinate_names[0]: affine[0],
        scheme.coordinate_names[1]: affine[1],
    }
    try:
        coordinate = _field_eval(scheme.transform, values, p)
        masked = bytes(left ^ right for left, right in zip(
            coordinate.to_bytes(byte_width, "big"), r, strict=True,
        ))
    except (OverflowError, ValueError, ZeroDivisionError):
        return None
    first_length = byte_width - scheme.key_bytes
    prefix, tail = masked[:first_length], masked[first_length:]
    derived = expand(prefix, scheme.key_bytes, scheme.f2)
    key = bytes(x ^ y for x, y in zip(tail, derived, strict=True))
    if expand(key, first_length, scheme.f1) == prefix:
        return key
    return None


def _decrypt_key(scheme: MaskedSignature, key_material: bytes,
                 ciphertext: bytes) -> str:
    try:
        import bcrypt
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise RuntimeError(
            "Install cipher dependencies: python -m pip install bcrypt pycryptodome"
        ) from exc
    key = bcrypt.kdf(
        password=key_material, salt=scheme.kdf_salt,
        desired_key_bytes=scheme.kdf_length, rounds=scheme.kdf_rounds,
    )
    plaintext = AES.new(key, AES.MODE_CTR, nonce=scheme.nonce).decrypt(
        ciphertext,
    )
    try:
        result = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("recovered AES plaintext is not UTF-8") from exc
    if not re.search(r"\w{2,32}\{[^\r\n{}]{1,256}\}", result):
        raise ValueError("verified candidate does not decrypt to a CTF flag")
    return result


def recover_flag(documents: Sequence[Document], progress=print) -> str:
    instance = extract_instance(documents)
    if instance is None:
        raise ValueError("no source-verified reversible masked EC signature corpus")
    scheme = instance.scheme
    byte_width = len(instance.signatures[0][0])
    if byte_width <= scheme.key_bytes or byte_width > 256:
        raise ValueError("unsupported message recovery encoding")
    def expand(data, length, domain):
        return _expand_sha256(
            data, length, domain, scheme.separator,
            scheme.counter_width, scheme.counter_byteorder,
        )
    tables = _tables(
        scheme.generator, instance.public_point, scheme.subgroup_order,
        scheme.field, scheme.a, scheme.d,
    )
    for index, (r, z) in enumerate(instance.signatures):
        material = _masked_message(scheme, r, z, byte_width, tables, expand)
        if material is None:
            continue
        progress(
            f"[MASKED-EC-SIGNATURE] Verified candidate {index+1}/"
            f"{len(instance.signatures)}"
        )
        return _decrypt_key(scheme, material, instance.ciphertext)
    raise RuntimeError("no signature candidate passed the independent message hash check")
