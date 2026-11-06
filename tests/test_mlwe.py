"""Generic Sage MLWE reduction/distinguisher tests; no challenge-specific flag."""
import base64
import gzip
import json
import random

import pytest

from cryptoscan.mlwe import (
    MLWEContext, classify_capture, distinguish_mlwe,
    recognize_weak_mlwe_ring,
)
from cryptoscan.mlwe_workflow import classify_file, play_ctf_tcp
from cryptoscan.parser import Document
from cryptoscan.scanner import scan

PARAMETERS = """
RING_RANK = 32
q = 104729
k, l = 4, 3
eta = 2
Fq = GF(q)
base_ring.<x> = Fq[]
Rq.<X> = base_ring.quotient_ring(x^RING_RANK - 1)
"""
GENERATOR = """
is_mlwe = rng.getrandbits(1)
A = random_matrix(Rq, k, l)
s = rnd_vec(Rq, l, eta)
e = rnd_vec(Rq, k, eta)
t = A*s + e
r = random_vector(Rq, k)
"""


def documents(parameters=PARAMETERS):
    return [
        Document("samples/parameters.sage", parameters, None, "samples", "p"),
        Document("samples/utils.sage", GENERATOR, None, "samples", "u"),
    ]


def generated_samples(seed=15):
    r = random.Random(seed)
    q, rank, rows, cols = 104729, 32, 4, 3
    matrix = [
        [[r.randrange(q) for _ in range(rank)] for _ in range(cols)]
        for _ in range(rows)
    ]
    secret = [[r.randint(-2, 2) for _ in range(rank)] for _ in range(cols)]
    error = [[r.randint(-2, 2) for _ in range(rank)] for _ in range(rows)]
    observed = [
        [
            (
                sum(
                    matrix[i][j][k] * secret[j][(pos - k) % rank]
                    for j in range(cols) for k in range(rank)
                ) + error[i][pos]
            ) % q
            for pos in range(rank)
        ]
        for i in range(rows)
    ]
    uniform = [[r.randrange(q) for _ in range(rank)] for _ in range(rows)]
    return matrix, observed, uniform


def encode(name, obj):
    data = gzip.compress(json.dumps(obj, separators=(",", ":")).encode())
    return name + " = '" + base64.b64encode(data).decode() + "'"


def transcript(matrix, vector):
    return encode("sanitize_mat(A)", matrix) + "\n" + encode("sanitize_vec(t)", vector)


def test_finding_from_sage_source_not_from_challenge_name():
    found = recognize_weak_mlwe_ring(documents())
    assert len(found) == 1
    assert (found[0].modulus, found[0].rows, found[0].columns, found[0].rank) == (
        104729, 4, 3, 32
    )
    report = scan(documents())
    assert any(item.rule == "MLWE-REDUCIBLE-RING-QUOTIENT" for item in report)


def test_safe_quotient_modulus_is_not_flagged():
    source = PARAMETERS.replace("x^RING_RANK - 1", "x^RING_RANK + 1")
    assert recognize_weak_mlwe_ring(documents(source)) == []


def test_mlwe_and_uniform_are_separable_with_same_params():
    ctx = recognize_weak_mlwe_ring(documents())[0]
    matrix, mlwe, uniform = generated_samples()
    assert classify_capture(transcript(matrix, mlwe), ctx).answer == 1
    assert classify_capture(transcript(matrix, uniform), ctx).answer == 0


def test_capture_file_classification(tmp_path):
    ctx = recognize_weak_mlwe_ring(documents())[0]
    matrix, mlwe, _ = generated_samples()
    path = tmp_path / "challenge_output.txt"
    path.write_text(transcript(matrix, mlwe))
    output = []
    assert classify_file(str(path), ctx, output.append) == 1
    assert "Internal modular consistency: PASS" in "\n".join(output)


def test_modified_or_oversized_input_is_rejected():
    ctx = recognize_weak_mlwe_ring(documents())[0]
    matrix, mlwe, _ = generated_samples()
    with pytest.raises(ValueError, match="capture needs"):
        classify_capture("only some unrelated text", ctx)
    broken = transcript(matrix, mlwe).replace("sanitize_vec(t)", "unknown")
    with pytest.raises(ValueError, match="capture needs"):
        classify_capture(broken, ctx)


def test_source_parameters_are_used_not_hardcoded():
    source = PARAMETERS.replace("RING_RANK = 32", "RING_RANK = 64").replace(
        "q = 104729", "q = 1000003"
    )
    ctx = recognize_weak_mlwe_ring(documents(source))[0]
    assert (ctx.rank, ctx.modulus) == (64, 1000003)


def test_network_mode_only_uses_user_host(monkeypatch):
    ctx = recognize_weak_mlwe_ring(documents())[0]
    matrix, sample, _ = generated_samples()
    capture = transcript(matrix, sample).encode() + b"\nMLWE (1) or not (0) ?\n> "
    observed = []
    class FakeSocket:
        def __init__(self):
            self.chunks = [capture, b"Well played, challenge complete", b""]
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, value):
            pass
        def recv(self, size):
            return self.chunks.pop(0)
        def sendall(self, data):
            observed.append(data)
    calls = []
    def connect(address, timeout):
        calls.append(address)
        return FakeSocket()
    monkeypatch.setattr("cryptoscan.mlwe_workflow.socket.create_connection", connect)
    output = []
    play_ctf_tcp("ctf.example", 12345, ctx, output.append, max_rounds=2)
    assert calls == [("ctf.example", 12345)]
    assert observed == [b"1\n"]
    assert "challenge complete" in "\n".join(output)
