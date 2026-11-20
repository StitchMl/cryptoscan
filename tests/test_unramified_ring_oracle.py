"""Synthetic structure tests for unramified ring evaluation recognition.

These tests do not embed any CTF challenge files, flags or parameters.
"""
import ast
from pathlib import Path

from cryptoscan.parser import Document
from cryptoscan.unramified_ring_oracle import _integers, extract_instance


def invented_source(k=4, degrees=None):
    if degrees is None:
        degrees = [2, 4]
    return f'''
import secrets
def construct(k, degrees):
    base = Zmod(2^k)
    residue = GF(2)
    for count in degrees:
        polynomials = residue["b"]
        minimum = polynomials.gen()^count + polynomials(1)
        if minimum.is_irreducible():
            residue = polynomials.quo(minimum)
            base = base["a"].quo(base["a"].gen()^count + 1)
    return base

def evaluate(poly, point):
    return point.parent()["x"](poly)(x=point)

def challenge(precision, degrees):
    tower = construct(precision, degrees)
    flat = construct(precision, [prod(degrees)])
    polynomial = [secrets.randbelow(3) - 1 for _ in range(15)]
    print(tower)
    print(flat)
    input("coordinates: ")
    print(evaluate(polynomial, tower(1)))

if __name__ == "__main__":
    challenge({k}, {degrees})
'''


def test_recognizes_unrelated_symbol_names_and_ring_dimensions():
    source = invented_source()
    model = extract_instance([Document("new_protocol.sage", source, None)])
    assert model is not None
    assert model.rounds == ((4, (2, 4)),)


def test_rejects_non_algebraic_oracle_source():
    text = invented_source().replace("residue = polynomials.quo(minimum)",
                                    "residue = minimum")
    assert extract_instance([Document("new_protocol.sage", text, None)]) is None


def test_rejects_unsupported_huge_ring():
    model = extract_instance([Document("big.sage", invented_source(12, [8, 8, 8]), None)])
    assert model is None


def test_rejects_malformed_coordinates():
    assert _integers("1,2,3", 3) == [1, 2, 3]
    import pytest
    with pytest.raises(ValueError):
        _integers("1,2", 3)
    with pytest.raises(ValueError):
        _integers("1,nope,3", 3)


def test_sage_worker_parses_as_python_without_loading_sage():
    worker = Path(__file__).resolve().parents[1] / "src" / "cryptoscan" / "sage_ring_iso_worker.py"
    tree = ast.parse(worker.read_text(encoding="utf-8"))
    assert any(isinstance(node, ast.FunctionDef) and node.name == "safe_expression"
               for node in tree.body)
