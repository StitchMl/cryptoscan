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


def test_synthetic_pairing_dialogue_without_sage(monkeypatch):
    """Exercise the TCP handshake using invented points and a fake worker."""
    import json
    import socket
    import threading
    import cryptoscan.pairing_confirmation as module

    events = []
    failure = []
    left, right = socket.socketpair()

    class FakeWorker:
        def __init__(self, name):
            assert name == "sage_pairing_confirmation_worker.py"

        def ask(self, message):
            events.append(message)
            if message["mode"] == "begin":
                return {"signature": [[1, 2], ["a", "b"]]}
            return {"response": ["z", "w"]}

        def close(self):
            events.append({"mode": "closed"})

    def service():
        try:
            with right, right.makefile("rwb", buffering=0) as channel:
                channel.write(
                    b"Public parameters\n"
                    + json.dumps({"P_G1": [1, 2], "Q": [3, 4],
                                  "P_G2": ["a+1", "a+2"]}).encode()
                    + b"\nhandle: "
                )
                username = channel.readline().decode().strip()
                if username != "cryptoscan_participant":
                    raise RuntimeError("incorrect synthetic username")
                channel.write(b"Private key preview\nsignature: ")
                signature = json.loads(channel.readline())
                if signature != [[1, 2], ["a", "b"]]:
                    raise RuntimeError("incorrect synthetic signature")
                channel.write(b"message: ")
                message = channel.readline().decode().strip()
                if message != "Authentication for cryptoscan_participant is required.":
                    raise RuntimeError("incorrect synthetic target message")
                channel.write(b"signer: ")
                if channel.readline().strip() != b"root":
                    raise RuntimeError("incorrect synthetic target identity")
                channel.write(b"C = [5,6]\nproof values: ")
                if json.loads(channel.readline()) != ["z", "w"]:
                    raise RuntimeError("incorrect synthetic pairing responses")
                channel.write(b"TST{synthetic_test_only}\n")
        except BaseException as exc:
            failure.append(exc)

    monkeypatch.setattr(module, "_SageWorker", FakeWorker)
    monkeypatch.setattr(module.socket, "create_connection", lambda *a, **kw: left)
    thread = threading.Thread(target=service, daemon=True)
    thread.start()
    result = module.recover_flag(
        [Document("sample.sage", _invented_source(), None)],
        "127.0.0.1", 7, timeout=5.0,
    )
    thread.join(timeout=3.0)
    assert not failure
    assert result == "TST{synthetic_test_only}"
    assert events[0]["identity"] == "root"
    assert events[1] == {"mode": "challenge", "point": [5, 6]}
    assert events[-1] == {"mode": "closed"}


def test_pairing_recognition_is_not_bound_to_a_sage_filename():
    model = extract_instance([Document("binary_protocol.snapshot", _invented_source(), None)])
    assert model is not None
    assert model.identity == "root"


def test_pairing_detector_infers_renamed_protocol_constructor_and_message():
    source = _invented_source()
    for old, new in (
        ("pkg = PKG()", "factory = PKG()"),
        ("handle = input(", "participant = input("),
        ("{handle}", "{participant}"),
        ("target = f'", "verifier_message = f'"),
        ("m == target", "m == verifier_message"),
    ):
        source = source.replace(old, new)
    model = extract_instance([Document("anonymous.bundle", source, None)])
    assert model is not None
    assert model.username_variable == "participant"
    assert model.message_template == "Authentication for {participant} is required."
