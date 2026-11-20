"""Synthetic pairing confirmation protocol recognition and forgery identities."""
from __future__ import annotations

import ast
import random
from pathlib import Path

from cryptoscan.parser import Document
from cryptoscan.pairing_confirmation import extract_instance
from cryptoscan.unramified_ring_oracle import _sage_worker_command


def _invented_source():
    """A made-up protocol sharing the vulnerable algebra, not a challenge file."""
    return """
from hashlib import sha256
class BN:
    def __init__(self):
        self.p = 1019
        self.b = 7
        self.k = 12
        Fp2.<z> = GF(self.p^2)
        self.eps = 9*z + 4
        self.h = 13
        self.t = self.EFp.trace_of_frobenius()

    def e(self, P, Q):
        return P.ate_pairing(Q, 13, self.k, self.t, self.p)

class Pkg:
    def H0(self, uid):
        seed = sha256(uid.encode())
        return self.curve.h * self.curve.EFp2.lift_x(seed)

class Member:
    def proof(self, **kwargs):
        self.x, self.y = self.rng(), self.rng()
        self.y_inv = 1/self.y
        C = self.x * self.y * self.sig['R']
        pair0 = self.curve.e(self.sig['R'], self.sig['S'])
        pair1 = self.curve.e(self.Q, self.sig['Qid'])
        pair2 = self.curve.e(self.P_G1, self.sig['Qid'])
        pair3 = self.curve.e(self.sig['R'] + self.Q, self.P_G2)
        return pair0, pair1, pair2, pair3, self.H(self.sig['m']), r ^ self.y_inv, t ^ self.x

    def respond(self, C):
        return self.curve.e(C, self.P_G2)

pkg = PKG()
try:
    handle = input('handle: ')
    if handle == 'root':
        raise ValueError('reserved')
    target = f'Authentication for {handle} is required.'
    signature = input('signature: ')
    m = input('message: ')
    claimed = input('signer: ')
    print('C = ...')
    response = input('proof values: ')
    match True, claimed, m == target:
        case True, 'root', True:
            print('success')
except Exception:
    pass
"""


def test_source_derived_parameters_and_no_service_specific_values():
    source = _invented_source()
    result = extract_instance([Document("generic_pairing.sage", source, None)])
    assert result is not None
    assert result.prime == 1019
    assert result.curve_b == 7
    assert result.twist_coefficient == (9, 4)
    assert result.embedding_degree == 12
    assert result.identity == "root"
    assert result.message_template == "Authentication for {handle} is required."
    assert result.signature_prompt == "signature: "
    assert result.response_prompt == "proof values: "


def test_rejects_proof_without_product_challenge():
    altered = _invented_source().replace(
        "C = self.x * self.y * self.sig['R']",
        "C = self.x * self.sig['R']",
    )
    assert extract_instance([Document("candidate.sage", altered, None)]) is None


def test_rejects_unrelated_source_and_ambiguous_matches():
    source = _invented_source()
    valid = Document("one.sage", source, None)
    assert extract_instance([Document("unrelated.sage", "print(123)", None)]) is None
    assert extract_instance([valid, Document("two.sage", source, None)]) is None


def test_bilinear_forgery_identity_mod_group_order():
    """All pairings are represented by products of source-group exponents."""
    rng = random.Random(8128)
    order = 1019
    for _ in range(50):
        u, secret, identity, message_hash, x, y = (
            rng.randrange(1, order) for _ in range(6)
        )
        public = u
        public_q = secret * u % order
        public_p2 = u
        r_point = public_q
        sig_s = (identity + message_hash * public_p2) % order
        challenge = x * y * r_point % order

        def pair(a, b):
            return a * b % order

        r = pair(challenge, public_p2)
        t = (pair(public_q, public_p2) - pair(public, identity)) % order
        lhs0 = x * pair(r_point, sig_s) % order
        rhs0 = (x * pair(public_q, identity)
                + message_hash * pow(y, -1, order) * r) % order
        lhs1 = (pow(y, -1, order) * r
                + x * t + x * pair(public, identity)) % order
        rhs1 = x * pair((r_point + public_q) % order, public_p2) % order
        assert lhs0 == rhs0
        assert lhs1 == rhs1


def test_pairing_worker_is_safe_to_parse_without_sage():
    path = (Path(__file__).resolve().parents[1] / "src" / "cryptoscan"
            / "sage_pairing_confirmation_worker.py")
    code = path.read_text(encoding="utf-8")
    module = ast.parse(code)
    assert any(isinstance(node, ast.ClassDef) and node.name == "PairingProof"
               for node in module.body)


def test_worker_dispatch_rejects_unknown_worker_filename():
    import pytest
    with pytest.raises(ValueError, match="unsupported Sage worker"):
        _sage_worker_command("arbitrary.py")
