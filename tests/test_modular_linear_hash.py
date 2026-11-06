"""Regression tests for source-driven modular hash inversion, not challenge solutions."""
import random

from cryptoscan.modular_linear_hash import (
    find_linear_hash_data, recognize_linear_hash, recover_small_alphabet_vectors,
    solve_linear_hash,
)
from cryptoscan.parser import Document
from cryptoscan.scanner import scan


def challenge_documents(secret="a1b2c3d4e5f60718", seed=2026):
    rows, columns, modulus, block_size = 48, 50, 256, 16
    source = """
from utils import sanitize, get_a
from re import match
FLAG = getenv("FLAG", "TEST{0000000000000000}")
assert bool(match(r'^TEST\\{[0-9a-f]+\\}$', FLAG))
FLAG = FLAG.strip("TEST{}")
assert len(FLAG) == 16
k, l = 48, 50
n = 256
Zn = Zmod(n)
def hash(msg):
    msg = msg.encode()
    msg = sanitize(msg, l)
    x = vector(Zn, msg)
    A = Matrix(Zn, k, l, get_a())
    return bytes(A*x)
"""
    utility = """
BLOCK_LEN = 16
def btq(a):
    a = sum(ai*256**i for i,ai in enumerate(a))
    charset = [-2, -1, 0, 1, 2]
    res = []
    while a > 0:
        res.append(charset[a % len(charset)])
        a //= len(charset)
    return res
def sanitize(a, l):
    a = pad(a, BLOCK_LEN)
    out = b"\\x00"*BLOCK_LEN
    for i in range(0, len(a), BLOCK_LEN):
        out = xor(out, a[i:i+BLOCK_LEN])
    return btq(out)[:l]
"""
    generator = random.Random(seed)
    matrix = [
        [generator.randrange(modulus) for _ in range(columns)]
        for _ in range(rows)
    ]
    payload = bytes(ord(character) ^ block_size for character in secret)
    number = int.from_bytes(payload, "little")
    alphabet = [-2, -1, 0, 1, 2]
    digits = []
    for _ in range(columns):
        digits.append(alphabet[number % len(alphabet)])
        number //= len(alphabet)
    digest = bytes(
        sum(a * b for a, b in zip(row, digits)) % modulus for row in matrix
    ).hex()
    return [
        Document("trial/chal.sage", source, None, "trial", "source"),
        Document("trial/utils.py", utility, None, "trial", "utility"),
        Document("trial/A.txt", repr(matrix), None, "trial", "matrix"),
        Document("trial/output.txt", digest, None, "trial", "output"),
    ]


def test_recovers_unique_flag_from_unrelated_generated_matrix():
    docs = challenge_documents()
    context = recognize_linear_hash(docs)
    assert len(context) == 1
    assert context[0].modulus == 256
    assert context[0].rows == 48
    result = solve_linear_hash(docs, context[0])
    assert result.recovered == ("TEST{a1b2c3d4e5f60718}",)
    assert result.verified
    finding = next(item for item in scan(docs) if item.rule == "LINEAR-HASH-SMALL-ALPHABET")
    assert finding.recovery_status == "flag-recovered"
    assert finding.solver["result_hex"] == "TEST{a1b2c3d4e5f60718}".encode().hex()


def test_different_data_produces_different_secret():
    docs = challenge_documents(secret="0123456789abcdef", seed=77)
    context = recognize_linear_hash(docs)[0]
    assert solve_linear_hash(docs, context).recovered == ("TEST{0123456789abcdef}",)


def test_not_rsa_despite_zmod_n_and_matrix():
    findings = scan(challenge_documents())
    assert "RSA-SMALL-FACTOR" not in {item.rule for item in findings}


def test_small_alphabet_linear_system_is_source_derived():
    docs = challenge_documents()
    context = recognize_linear_hash(docs)[0]
    data = find_linear_hash_data(docs, context)
    assert data is not None
    matrix, digest = data
    candidates, rank = recover_small_alphabet_vectors(
        matrix, digest, context.modulus, context.alphabet,
    )
    assert rank >= 46
    assert len(candidates) == 1


def test_unrelated_matrix_is_not_misidentified_as_linear_hash():
    docs = challenge_documents()
    source = docs[0].text.replace("Zmod(n)", "GF(n)")
    other = [Document(docs[0].path, source, None, "trial", "replaced")] + docs[1:]
    assert recognize_linear_hash(other) == []


def test_wrong_hash_output_does_not_claim_flag():
    docs = challenge_documents()
    corrupted = [
        Document(doc.path, "00" * 48, None, doc.scope, doc.digest)
        if doc.path.endswith("output.txt") else doc
        for doc in docs
    ]
    ctx = recognize_linear_hash(corrupted)[0]
    result = solve_linear_hash(corrupted, ctx)
    assert not result.recovered


def test_bounded_free_variable_search():
    matrix = [[1, 0, 0, 0, 0, 0, 0, 0]]
    try:
        recover_small_alphabet_vectors(matrix, b"\x01", 256, (-2, -1, 0, 1, 2), max_guesses=10)
    except ValueError as exc:
        assert "free-variable search" in str(exc)
    else:
        raise AssertionError("expected bounded-search guard")
