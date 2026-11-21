"""Synthetic, filename-independent tests for reducible-ring GLP signatures.

No challenge source code, real public key, service endpoint or flag is stored.
"""
from __future__ import annotations

import ast
import hashlib
import random
import socket
import threading
from pathlib import Path

import pytest

from cryptoscan.parser import Document
from cryptoscan.reducible_ring_signature import (
    _cyclic_product, _pack, _unpack, extract_instance, forge_signature,
    recover_flag,
)
from cryptoscan.unramified_ring_oracle import _sage_worker_command


def invented_source(q=257, degree=60, width=2):
    return f'''
import random
from hashlib import sha256
from Crypto.Util.number import long_to_bytes

modulus = {q}
limit = 100
tolerance = 2
dimension = {degree}
base = PolynomialRing(Zmod(modulus), name="v")
v = base.gen()
relation = v**dimension - 1
quotient = base.quotient(relation, "v")
v = quotient.gen()

def draw(radius):
    return sum(random.randint(-radius, radius) * v**i
               for i in range(dimension))

def hash_poly(poly, message):
    digest = sha256()
    for i in range(dimension):
        digest.update(long_to_bytes(int(poly[i]), {width}))
    digest.update(message)
    return digest.digest()

def bits_as_poly(digest):
    value = int.from_bytes(digest, "big")
    return sum(((1 << i) & value != 0) * v**i for i in range(dimension))

def create_key(public):
    first = draw(1)
    second = draw(1)
    visible = public * first + second
    return (first, second), visible

def authenticate(message, keys, public, visible):
    first, second = keys
    while True:
        x1, x2 = draw(limit), draw(limit)
        challenge = bits_as_poly(hash_poly(public*x1+x2, message))
        z1 = first*challenge+x1
        z2 = second*challenge+x2
        if all(min(z1[i], modulus-z1[i]) <= limit-tolerance
               for i in range(dimension)):
            return z1, z2, challenge

def check(message, proof, visible, public):
    x1, x2, challenge = proof
    if any(min(x1[i], modulus-x1[i]) > limit-tolerance
           for i in range(dimension)):
        return False
    check_hash = bits_as_poly(hash_poly(
        public*x1+x2-visible*challenge, message
    ))
    return check_hash == challenge

def serialize(poly):
    return b"".join(long_to_bytes(int(poly[i]), {width})
                    for i in range(dimension))

if __name__ == "__main__":
    task = b"synthetic task"
    print(f"first_enc = {{first_enc.hex()}}")
    print(f"second_enc = {{second_enc.hex()}}")
    a = bytes.fromhex(input("first = "))
    b = bytes.fromhex(input("second = "))
    c = bytes.fromhex(input("challenge = "))
    if check(task, (a, b, c), visible, public):
        print("DEMO{{mock}}")
'''


def test_renamed_source_fields_and_nonstandard_extension():
    instance = extract_instance([
        Document("something.opaque", invented_source(), None),
    ])
    assert instance is not None
    assert instance.dimension == 60
    assert instance.modulus == 257
    assert instance.secret_bound == 1
    assert instance.message == b"synthetic task"
    assert instance.public_labels == ("first_enc", "second_enc")
    assert instance.prompt_labels == ("first = ", "second = ", "challenge = ")
    assert instance.encoding_width == 2


def test_rejects_noncyclic_and_nonsmall_private_key():
    source = invented_source()
    assert extract_instance([
        Document("random.txt", source.replace(
            "v**dimension - 1", "v**dimension + 1",
        ), None),
    ]) is None
    assert extract_instance([
        Document("random.txt", source.replace(
            "second = draw(1)", "second = draw(7)",
        ), None),
    ]) is None


def _toy_keys():
    rng = random.Random(8381)
    n, q = 60, 257
    a = [rng.randrange(q) for _ in range(n)]
    secret = [rng.choice((-1, 0, 1)) % q for _ in range(n)]
    error = [rng.choice((-1, 0, 1)) % q for _ in range(n)]
    public_t = [(x + y) % q for x, y in zip(
        _cyclic_product(a, secret, q), error, strict=True,
    )]
    return a, public_t, secret, error


def test_cyclic_convolution_hash_and_short_signature():
    instance = extract_instance([Document("profile", invented_source(), None)])
    assert instance is not None
    a, t, secret, error = _toy_keys()
    proof = forge_signature(instance, a, t, secret, error)
    z1, z2, challenge = [
        _unpack(value, instance.dimension, instance.encoding_width)
        for value in proof
    ]
    tested = [
        (x + y - z) % instance.modulus for x, y, z in zip(
            _cyclic_product(a, z1, instance.modulus), z2,
            _cyclic_product(t, challenge, instance.modulus), strict=True,
        )
    ]
    assert tested == [0] * instance.dimension
    digest = hashlib.sha256(
        _pack(tested, instance.encoding_width) + instance.message,
    ).digest()
    bits = int.from_bytes(digest, "big")
    assert challenge == [
        (bits >> i) & 1 for i in range(instance.dimension)
    ]
    assert all(min(v, instance.modulus - v) <= instance.short_bound - instance.slack
               for v in z1 + z2)


def test_rejects_bogus_private_key():
    instance = extract_instance([Document("profile", invented_source(), None)])
    a, t, _, error = _toy_keys()
    with pytest.raises(ValueError, match="public equation"):
        forge_signature(instance, a, t, [0] * 60, error)


def test_tcp_protocol_is_source_driven(monkeypatch):
    import cryptoscan.reducible_ring_signature as module

    instance = extract_instance([Document("anonymous", invented_source(), None)])
    a, t, secret, error = _toy_keys()
    left, right = socket.socketpair()
    problems = []

    class FakeWorker:
        def __init__(self, name):
            assert name == "sage_reducible_ring_worker.py"

        def ask(self, request):
            assert request["modulus"] == instance.modulus
            return {"secret": secret, "error": error}

        def close(self):
            pass

    def server():
        try:
            with right:
                right.sendall(
                    b"first_enc = " + _pack(a, 2).hex().encode() + b"\n"
                    + b"second_enc = " + _pack(t, 2).hex().encode() + b"\n"
                )
                input_stream = right.makefile("rb", buffering=0)
                for prompt in instance.prompt_labels:
                    right.sendall(prompt.encode())
                    response = input_stream.readline().strip()
                    if len(response) != 2 * instance.dimension * instance.encoding_width:
                        raise RuntimeError("malformed synthetic proof")
                right.sendall(b"DEMO{synthetic_only}\n")
        except BaseException as exc:
            problems.append(exc)

    monkeypatch.setattr(module, "_SageWorker", FakeWorker)
    monkeypatch.setattr(module.socket, "create_connection", lambda *a, **kw: left)
    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    recovered = recover_flag(
        [Document("unrelated_script.dat", invented_source(), None)],
        "127.0.0.1", 1010, timeout=5,
    )
    thread.join(timeout=2)
    assert not problems
    assert recovered == "DEMO{synthetic_only}"


def test_worker_has_no_source_execution_and_is_python_parseable():
    path = Path(__file__).resolve().parents[1] / "src" / "cryptoscan"
    worker = path / "sage_reducible_ring_worker.py"
    source = worker.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert any(isinstance(node, ast.FunctionDef) and node.name == "_recover"
               for node in tree.body)
    assert "exec(" not in source
    assert "eval(" not in source
    with pytest.raises(ValueError, match="unsupported Sage worker"):
        _sage_worker_command("unexpected_sage_worker.py")


def test_cli_dispatches_general_source_to_ring_solver(tmp_path, monkeypatch, capsys):
    import cryptoscan.cli as cli

    source = tmp_path / "unnamed_signature.data"
    source.write_text(invented_source(), encoding="utf-8")
    assert cli.main([str(source), "--no-assist"]) == 0
    report = capsys.readouterr().out
    assert "short-secret signature over a reducible cyclic" in report

    invocations = []

    def fake_solver(documents, host, port, *, timeout):
        invocations.append((host, port, timeout))
        assert extract_instance(documents) is not None
        return "DEMO{synthetic_dispatch}"

    monkeypatch.setattr(cli, "recover_reducible_glp_flag", fake_solver)
    status = cli.main([
        str(source), "--solve", "--host", "127.0.0.1",
        "--port", "1010", "--timeout", "120",
    ])
    assert status == 0
    assert invocations == [("127.0.0.1", 1010, 120.0)]
    assert "FLAG: DEMO{synthetic_dispatch}" in capsys.readouterr().out


def test_variable_small_secret_bounds_are_derived_from_source():
    source = invented_source().replace(
        "first = draw(1)", "first = draw(2)",
    ).replace(
        "second = draw(1)", "second = draw(2)",
    )
    instance = extract_instance([Document("not_a_sage_file.dat", source, None)])
    assert instance is not None
    assert instance.secret_bound == 2

    rng = random.Random(82)
    n, q = instance.dimension, instance.modulus
    public = [rng.randrange(q) for _ in range(n)]
    secret = [rng.randrange(-2, 3) % q for _ in range(n)]
    noise = [rng.randrange(-2, 3) % q for _ in range(n)]
    published = [
        (x + y) % q for x, y in zip(
            _cyclic_product(public, secret, q), noise, strict=True,
        )
    ]
    proof = forge_signature(instance, public, published, secret, noise)
    assert len(proof) == 3
    assert all(len(value) == n * instance.encoding_width * 2
               for value in proof)


def test_unsupported_high_degree_component_is_not_auto_dispatched():
    # A prime ring dimension can have a cyclotomic factor too large for
    # the available embedded-CVP reduction; retain only the hypothesis.
    source = invented_source(degree=419)
    assert extract_instance([Document("large_unknown_file", source, None)]) is None
