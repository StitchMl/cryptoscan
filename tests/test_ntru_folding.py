"""Algebraic property tests for NTRU folding on independent parameters."""
import random

import pytest

from cryptoscan.ntru_folding import (
    circulant_rows, decrypt_with_private_key, fold_lattice_basis, fold_poly,
)
from cryptoscan.ntru_lattice import cyclic_mul
from test_ntru_lattice import synthetic


@pytest.mark.parametrize("n,d", [(16, 2), (16, 4), (32, 8), (64, 16)])
def test_folding_is_a_ring_homomorphism(n, d):
    rng = random.Random(n * 211 + d)
    a = [rng.randint(-9, 9) for _ in range(n)]
    b = [rng.randint(-9, 9) for _ in range(n)]
    original = cyclic_mul(a, b, 127)
    folded = cyclic_mul(fold_poly(a, d, 127), fold_poly(b, d, 127), 127)
    assert fold_poly(original, d, 127) == folded


def test_folded_key_decryption_on_independent_synthetic_instance():
    n, p, q, df, dg, _, h, ct, plaintext, f = synthetic(n=16, seed=83)
    assert decrypt_with_private_key(f, h, ct, p, q, df, dg) == plaintext
    altered = f[:]
    altered[0] ^= 1
    assert decrypt_with_private_key(altered, h, ct, p, q, df, dg) is None


def test_fold_lattice_accepts_independent_initial_and_lift_shapes():
    h = [1, 2, 3, 4]
    rows, d = fold_lattice_basis(h, 127)
    assert d == 4 and len(rows) == 8
    assert all(len(row) == 8 for row in rows)
    lifted, half = fold_lattice_basis(h, 127, [1, 0])
    assert half == 2 and all(len(row) == 4 for row in lifted)


def test_invalid_folding_divisor_is_rejected():
    with pytest.raises(ValueError):
        fold_poly([1, 2, 3], 2)


def test_cyclic_key_rotations_share_one_equivalence_class():
    from cryptoscan.ntru_folding import _canonical_rotation
    key = (0, 1, 1, 0, 1, 0, 0, 2)
    assert {_canonical_rotation(key[i:] + key[:i]) for i in range(len(key))} == {
        _canonical_rotation(key)
    }
