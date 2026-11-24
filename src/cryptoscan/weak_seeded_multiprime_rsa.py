"""Weak-seed factor recovery for RSA, with partial CRT reconstruction.

Analyze Python ASTs, never execute challenge code. When some factors of an RSA
modulus come from deterministic PRNGs initialized with low-entropy seeds,
regenerate candidate primes and confirm exact divisibility by the public N.
The product of discovered factors need only EXCEED the known plaintext bound:
the full RSA modulus does not have to be factored.
"""
from __future__ import annotations

import ast
import math
import random
import re
from dataclasses import dataclass
from typing import Sequence

from .parser import Document
from .source_units import parse_python

_MAX_SOURCE = 1_000_000
_MAX_OUTPUT = 2_000_000
_MAX_PRIME_BITS = 1024
_MAX_SEED_BITS = 16
_MAX_ATTEMPTS = 4096
_DEFAULT_SEEDS = 4096
_FLAG_SHAPE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,31}\{[^{}\r\n]{1,256}\}")
_HEX = re.compile(r"(?<![\w])0[xX][0-9a-fA-F]+(?![\w])")


@dataclass(frozen=True)
class WeakSeededRSA:
    modulus: int
    ciphertext: int
    exponent: int
    message_bytes: int
    prime_bits: int
    sample_method: str
    odd_mask: int
    first_seed_bits: int
    last_seed_bits: int


def _name(node):
    return node.id if isinstance(node, ast.Name) else None


def _apply_op(op, a, b):
    if isinstance(op, ast.Add):
        return a + b
    if isinstance(op, ast.Sub):
        return a - b
    if isinstance(op, ast.Pow) and b <= 32:
        return a**b
    if isinstance(op, ast.LShift) and b <= 32:
        return a << b
    if isinstance(op, ast.BitOr):
        return a | b
    return None


def _integer(node, definitions, seen=frozenset()):
    """Bounded integer-expression interpreter; never eval source text."""
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value if 0 <= node.value <= 1 << 20 else None
    if isinstance(node, ast.Name) and node.id in definitions and node.id not in seen:
        return _integer(definitions[node.id], definitions, seen | {node.id})
    if not isinstance(node, ast.BinOp):
        return None
    a = _integer(node.left, definitions, seen)
    b = _integer(node.right, definitions, seen)
    if a is None or b is None:
        return None
    out = _apply_op(node.op, a, b)
    if out is None:
        return None
    return out if 0 <= out <= 1 << 20 else None


def _definitions(nodes):
    names = {}
    for node in nodes:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            names.setdefault(node.targets[0].id, []).append(node.value)
    return {key: values[0] for key, values in names.items() if len(values) == 1}


def _imports(tree):
    modules, functions = {}, {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules[alias.asname or alias.name] = alias.name
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                functions[alias.asname or alias.name] = (node.module, alias.name)
    return modules, functions


def _origin(func, modules, functions):
    if isinstance(func, ast.Name):
        return functions.get(func.id, (None, func.id))
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return modules.get(func.value.id, func.value.id), func.attr
    return None, None


def _bounded_seed(node, argument, modules, functions, definitions=None,
                  seen=frozenset()):
    """Recognize bounded seeds, including intermediate source aliases."""
    if (isinstance(node, ast.Name) and definitions is not None
            and node.id in definitions and node.id not in seen):
        return _bounded_seed(
            definitions[node.id], argument, modules, functions,
            definitions, seen | {node.id},
        )
    if not (isinstance(node, ast.Call) and len(node.args) == 1):
        return False
    module, name = _origin(node.func, modules, functions)
    if module not in ("secrets", None) or name not in ("randbelow", "randbits"):
        return False
    value = node.args[0]
    if name == "randbits":
        return _name(value) == argument
    if (isinstance(value, ast.BinOp)
            and _name(value.right) == argument
            and isinstance(value.left, ast.Constant)):
        return (isinstance(value.op, ast.Pow) and value.left.value == 2
                or isinstance(value.op, ast.LShift) and value.left.value == 1)
    return False


def _rng_allocation(statement, argument, modules, imports, definitions):
    """Return (target, bounded_seed) for `x = random.Random(...)`, else None."""
    if not (isinstance(statement, ast.Assign) and len(statement.targets) == 1):
        return None
    target = _name(statement.targets[0])
    value = statement.value
    if not (target and isinstance(value, ast.Call)):
        return None
    module, name = _origin(value.func, modules, imports)
    if not (module in ("random", None) and name == "Random" and len(value.args) <= 1):
        return None
    bounded = bool(value.args) and _bounded_seed(
        value.args[0], argument, modules, imports, definitions)
    return target, bounded


def _is_bounded_reseed(node, allocated, argument, modules, imports, definitions):
    return (isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _name(node.func.value) in allocated
            and node.func.attr == "seed"
            and len(node.args) == 1
            and _bounded_seed(node.args[0], argument, modules, imports,
                              definitions))


def _seeded_rng(function, modules, imports):
    if not function.args.args:
        return None
    argument = function.args.args[0].arg
    allocated, seeded_at = set(), {}
    local_definitions = _definitions(function.body)
    for statement in function.body:
        allocation = _rng_allocation(
            statement, argument, modules, imports, local_definitions)
        if allocation:
            allocated.add(allocation[0])
            if allocation[1]:
                seeded_at[allocation[0]] = statement.lineno
        for node in ast.walk(statement):
            if _is_bounded_reseed(node, allocated, argument, modules, imports,
                                  local_definitions):
                name = _name(node.func.value)
                seeded_at[name] = min(seeded_at.get(name, node.lineno), node.lineno)
    if len(seeded_at) != 1:
        return None
    rng = next(iter(seeded_at))
    return rng, seeded_at[rng]


def _power_of_two_expr_bits(node, definitions):
    left = _integer(node.left, definitions)
    right = _integer(node.right, definitions)
    if right is not None and 1 <= right <= _MAX_PRIME_BITS:
        if left == 2 and isinstance(node.op, ast.Pow):
            return right
        if left == 1 and isinstance(node.op, ast.LShift):
            return right
    return None


def _power_of_two_bits(node, definitions):
    if isinstance(node, ast.BinOp):
        bits = _power_of_two_expr_bits(node, definitions)
        if bits is not None:
            return bits
    if isinstance(node, ast.Constant) and type(node.value) is int:
        value = node.value
        if value > 0 and (value & (value - 1)) == 0:
            return value.bit_length() - 1
    return None


def _split_mask(node, definitions):
    """Split `expr | constant` into (mask, expr); (0, node) otherwise."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        if (v := _integer(node.right, definitions)) is not None:
            return v, node.left
        if (v := _integer(node.left, definitions)) is not None:
            return v, node.right
    return 0, node


def _rng_sample_bits(node, rng, definitions):
    """Return (bits, method) for a single-argument call on the seeded RNG."""
    if not (isinstance(node, ast.Call) and len(node.args) == 1
            and isinstance(node.func, ast.Attribute)
            and _name(node.func.value) == rng):
        return None
    method = node.func.attr
    if method == "getrandbits":
        return _integer(node.args[0], definitions), method
    if method in ("_randbelow", "randrange"):
        return _power_of_two_bits(node.args[0], definitions), method
    return None


def _inherit_draw(node, mask, rng, definitions, seen, allow_even_intermediate):
    returned = _prime_draw(
        definitions[node.id], rng, definitions, seen | {node.id},
        allow_even_intermediate=bool(mask & 1) or allow_even_intermediate,
    )
    if returned is None:
        return None
    bits, method, inherited_mask = returned
    combined_mask = mask | inherited_mask
    if (combined_mask & 1 or allow_even_intermediate) and combined_mask.bit_length() <= bits:
        return bits, method, combined_mask
    return None


def _prime_draw(node, rng, definitions, seen=frozenset(), *,
                allow_even_intermediate=False):
    # Resolve the call that supplies a prime candidate through local
    # assignments, but do not interpret code or follow cyclic definitions.
    if isinstance(node, ast.Name) and node.id in definitions and node.id not in seen:
        return _prime_draw(
            definitions[node.id], rng, definitions, seen | {node.id},
            allow_even_intermediate=allow_even_intermediate,
        )
    mask, node = _split_mask(node, definitions)
    if (isinstance(node, ast.Name) and node.id in definitions and node.id not in seen):
        return _inherit_draw(node, mask, rng, definitions, seen,
                             allow_even_intermediate)
    sampled = _rng_sample_bits(node, rng, definitions)
    if sampled is None:
        return None
    bits, method = sampled
    if (bits is None or not 32 <= bits <= _MAX_PRIME_BITS
            or (not mask & 1 and not allow_even_intermediate)
            or mask.bit_length() > bits):
        return None
    return bits, method, mask


def _primality_checked_names(function, modules, imports):
    names = set()
    for node in ast.walk(function):
        if not (isinstance(node, ast.Call) and len(node.args) == 1):
            continue
        module, predicate = _origin(node.func, modules, imports)
        if predicate in ("isPrime", "isprime") and module in (
                None, "Crypto.Util.number", "sympy", "sympy.ntheory.primetest"):
            if (name := _name(node.args[0])) is not None:
                names.add(name)
    return names


def _returns_name(function, target):
    return any(
        isinstance(node, ast.Return) and _name(node.value) == target
        for node in ast.walk(function)
    )


def _prime_generator(function, modules, imports, definitions):
    configured = _seeded_rng(function, modules, imports)
    if configured is None:
        return None
    rng, seed_line = configured
    prime_vars = _primality_checked_names(function, modules, imports)
    draws = []
    local_definitions = _definitions(ast.walk(function))
    # A candidate target can have multiple assignments; its sampling
    # expression is identified only by exact PRNG data flow.
    for node in ast.walk(function):
        if (isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and (target := _name(node.targets[0])) in prime_vars
                and node.lineno > seed_line):
            draw = _prime_draw(node.value, rng, {**definitions, **local_definitions})
            if draw:
                draws.append((target, draw))
    if len(draws) != 1:
        return None
    target, draw = draws[0]
    if not _returns_name(function, target):
        return None
    return draw


def _len_operand_size(length, number, message, definitions):
    if (isinstance(length, ast.Call)
            and isinstance(length.func, ast.Name)
            and length.func.id == "len"
            and len(length.args) == 1
            and _name(length.args[0]) == message):
        size = _integer(number, definitions)
        if size is not None and 1 <= size <= 4096:
            return size
    return None


def _message_length(tree, message, definitions):
    sizes = set()
    for node in ast.walk(tree):
        if (not isinstance(node, ast.Assert)
                or not isinstance(node.test, ast.Compare)
                or len(node.test.ops) != 1
                or not isinstance(node.test.ops[0], ast.Eq)
                or len(node.test.comparators) != 1):
            continue
        for length, number in (
            (node.test.left, node.test.comparators[0]),
            (node.test.comparators[0], node.test.left),
        ):
            size = _len_operand_size(length, number, message, definitions)
            if size is not None:
                sizes.add(size)
    return next(iter(sizes)) if len(sizes) == 1 else None


def _plaintext_secret(plain, modules, imports):
    """Name of the bytes variable converted to an integer, else None."""
    module, conversion = _origin(plain.func, modules, imports)
    if (conversion == "bytes_to_long"
            and module in (None, "Crypto.Util.number")
            and len(plain.args) == 1):
        return _name(plain.args[0])
    if (isinstance(plain.func, ast.Attribute)
            and _name(plain.func.value) == "int"
            and plain.func.attr == "from_bytes"
            and len(plain.args) == 2
            and isinstance(plain.args[1], ast.Constant)
            and plain.args[1].value == "big"):
        return _name(plain.args[0])
    return None


def _encryption(tree, modulus, definitions, modules, imports):
    """Find a source-defined plaintext-to-integer RSA encryption operation."""
    candidates = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "pow"
                and len(node.args) == 3
                and _name(node.args[2]) == modulus):
            continue
        plain = node.args[0]
        if not isinstance(plain, ast.Call):
            continue
        secret = _plaintext_secret(plain, modules, imports)
        exponent = _integer(node.args[1], definitions)
        if secret and exponent and exponent > 1 and exponent % 2:
            candidates.append((secret, exponent))
    return candidates[0] if len(candidates) == 1 else None


def _prime_generators(tree, modules, imports, definitions):
    generators = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            if (result := _prime_generator(node, modules, imports, definitions)):
                generators[node.name] = result
    return generators


def _product_comprehension(node, modules, imports, generators):
    """Match `N = prod(gen(i) for i in range(a, b))`; return (modulus, generator, loop)."""
    if not (isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and len(node.value.args) == 1
            and isinstance(node.value.args[0], (ast.GeneratorExp, ast.ListComp))):
        return None
    origin, product = _origin(node.value.func, modules, imports)
    if product != "prod" or origin not in (None, "math"):
        return None
    generator = node.value.args[0]
    if (len(generator.generators) != 1
            or not isinstance(generator.elt, ast.Call)
            or not isinstance(generator.elt.func, ast.Name)
            or generator.elt.func.id not in generators
            or len(generator.elt.args) != 1):
        return None
    loop = generator.generators[0]
    if not (isinstance(loop.target, ast.Name)
            and _name(generator.elt.args[0]) == loop.target.id
            and isinstance(loop.iter, ast.Call)
            and isinstance(loop.iter.func, ast.Name)
            and loop.iter.func.id == "range"
            and len(loop.iter.args) == 2):
        return None
    return node.targets[0].id, generator, loop


def _is_len_of(stop, message):
    return (isinstance(stop, ast.Call)
            and isinstance(stop.func, ast.Name)
            and stop.func.id == "len"
            and len(stop.args) == 1
            and _name(stop.args[0]) == message)


def _source_profile(source):
    if len(source) > _MAX_SOURCE:
        return None
    tree = parse_python(Document("source", source, None))
    if tree is None:
        return None
    definitions = _definitions(tree.body)
    modules, imports = _imports(tree)
    generators = _prime_generators(tree, modules, imports, definitions)
    profiles = []
    for node in tree.body:
        matched = _product_comprehension(node, modules, imports, generators)
        if matched is None:
            continue
        modulus, generator, loop = matched
        start = _integer(loop.iter.args[0], definitions)
        encryption = _encryption(tree, modulus, definitions, modules, imports)
        if start is None or start < 0 or start > 16 or encryption is None:
            continue
        message, exponent = encryption
        length = _message_length(tree, message, definitions)
        if (length is None or length <= start
                or not _is_len_of(loop.iter.args[1], message)):
            continue
        prime_bits, method, mask = generators[generator.elt.func.id]
        profiles.append((exponent, length, prime_bits, method, mask,
                         start, length - 1))
    return profiles[0] if len(profiles) == 1 else None


def _public_values(text):
    if len(text) > _MAX_OUTPUT:
        return None
    values = _HEX.findall(text)
    if len(values) != 2:
        return None
    modulus, ciphertext = (int(value, 16) for value in values)
    if (modulus.bit_length() < 256 or modulus.bit_length() > 131072
            or not 0 <= ciphertext < modulus):
        return None
    return modulus, ciphertext


def extract_instance(documents: Sequence[Document]) -> WeakSeededRSA | None:
    matches = []
    for source in documents:
        profile = _source_profile(source.text)
        if profile is None:
            continue
        for output in documents:
            if output.scope != source.scope or output.path == source.path:
                continue
            public = _public_values(output.text)
            if public is not None:
                matches.append(WeakSeededRSA(
                    public[0], public[1], *profile,
                ))
    return matches[0] if len(matches) == 1 else None


def _prime_from_seed(seed, bits, method, mask):
    try:
        from Crypto.Util.number import isPrime
    except ImportError:
        from sympy import isprime as isPrime
    rng = random.Random(seed)
    for _ in range(_MAX_ATTEMPTS):
        if method == "getrandbits":
            sample = rng.getrandbits(bits)
        elif method == "_randbelow":
            sample = rng._randbelow(1 << bits)
        elif method == "randrange":
            sample = rng.randrange(1 << bits)
        else:
            raise ValueError("unsupported deterministic PRNG sampling")
        prime = sample | mask
        if isPrime(prime):
            return prime
    raise RuntimeError("prime sampling exceeded bounded work limit")


def _crt(primes, residues):
    plaintext, modulus = 0, 1
    for prime, residue in zip(primes, residues, strict=True):
        plaintext += modulus * (
            (residue - plaintext) * pow(modulus, -1, prime) % prime
        )
        modulus *= prime
        plaintext %= modulus
    return plaintext, modulus


def recover_details(instance: WeakSeededRSA, *, max_seeds=_DEFAULT_SEEDS):
    """Factor only as much as is required to prove full plaintext uniqueness."""
    if not 1 <= max_seeds <= (1 << 20):
        raise ValueError("seed search budget must lie between 1 and 2**20")
    possible = 1 << min(instance.last_seed_bits, _MAX_SEED_BITS)
    budget = min(possible, max_seeds)
    discovered = {}
    combined = 1
    bound = 1 << (8 * instance.message_bytes)
    for seed in range(budget):
        prime = _prime_from_seed(
            seed, instance.prime_bits, instance.sample_method, instance.odd_mask,
        )
        if (prime in discovered or instance.modulus % prime
                or math.gcd(instance.exponent, prime - 1) != 1):
            continue
        discovered[prime] = seed
        combined *= prime
        if combined > bound:
            break
    if combined <= bound:
        raise RuntimeError(
            "insufficient verified factors for unique CRT plaintext: "
            f"{combined.bit_length()} bits obtained, "
            f"{8 * instance.message_bytes} required; "
            f"search budget {budget}"
        )
    factors = tuple(discovered)
    residues = [
        pow(instance.ciphertext, pow(instance.exponent, -1, p - 1), p)
        for p in factors
    ]
    plaintext, crt_modulus = _crt(factors, residues)
    if not 0 <= plaintext < bound or crt_modulus <= bound:
        raise RuntimeError("CRT plaintext does not satisfy the source bound")
    if pow(plaintext, instance.exponent, crt_modulus) != (
            instance.ciphertext % crt_modulus):
        raise RuntimeError("partial RSA re-encryption certificate failed")
    decoded = plaintext.to_bytes(instance.message_bytes, "big").decode("utf-8")
    if not _FLAG_SHAPE.fullmatch(decoded):
        raise RuntimeError("recovered plaintext is not verified CTF text")
    return decoded, {
        "factor_count": len(factors),
        "crt_bits": crt_modulus.bit_length(),
        "plaintext_bound_bits": instance.message_bytes * 8,
        "last_seed": seed,
        "reencryption_verified": True,
    }


def recover_flag(documents: Sequence[Document], *, max_seeds=_DEFAULT_SEEDS):
    model = extract_instance(documents)
    if model is None:
        raise ValueError("no source-verified weak-seeded RSA instance")
    return recover_details(model, max_seeds=max_seeds)[0]
