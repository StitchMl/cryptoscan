"""Tests for source-proven Fischlin first-hit witness discrimination."""
import hashlib
import json
import random

from cryptoscan.fischlin_workflow import (
    _ro, identify_simulated_branch, recover_flag, supported_source
)
from cryptoscan.parser import Document
from cryptoscan.scanner import scan

P = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
Q = (P-1)//2

SOURCE = """
from hashlib import sha512
def Totally_a_random_oracle(a0,a1,e,e0,e1,z0,z1):
    ROstep = sha512(b'my')
    ROstep.update(str(a0).encode())
    ROstep.update(str(z1).encode())
    return ROstep
def fischlin_proof(w0,w1,y0,y1,b):
    t = 2**10
    B = 6
    for e in range(t):
        e_b = e ^ e_sim
        z_b = (r_b + e_b*w_b) % q
        if res < 2**(512-B):
            break
def gen_round():
    pass
attempts = 2**4
for round in range(64):
    print("which witness do you want to see?")
    print("do you think you can guess my witness? (y,n)")
"""


def sample(seed, b):
    rng = random.Random(seed)
    w0, w1 = [rng.randrange(1, Q) for _ in range(2)]
    y0, y1 = pow(2, w0, P), pow(2, w1, P)
    r = rng.randrange(Q)
    a_real = pow(2, r, P)
    e_sim = rng.randrange(1 << 511)
    z_sim = rng.randrange(Q)
    sim = 1-b
    a_sim = pow(pow((y0,y1)[sim], e_sim, P), -1, P) * pow(2,z_sim,P) % P
    for e in range(1024):
        e_real = e ^ e_sim
        z_real = (r + e_real * (w0,w1)[b]) % Q
        a0,a1 = ((a_sim,a_real) if b else (a_real,a_sim))
        e0,e1 = ((e_sim,e_real) if b else (e_real,e_sim))
        z0,z1 = ((z_sim,z_real) if b else (z_real,z_sim))
        if _ro(a0,a1,e,e0,e1,z0,z1) < 2**506:
            break
    return dict(a0=a0,a1=a1,e=e,e0=e0,e1=e1,z0=z0,z1=z1), w0


def test_first_hit_signal_never_false_positive():
    decisions = 0
    for seed in range(40):
        for real_branch in (0,1):
            proof, w0 = sample(seed, real_branch)
            answer = identify_simulated_branch(proof, w0, 0, Q)
            assert answer is None or answer == real_branch
            if answer is not None:
                decisions += 1
    assert decisions >= 5


def test_source_fingerprint_and_scanner():
    doc = Document("chal.py", SOURCE, None)
    assert supported_source([doc])
    assert "FISCHLIN-FIRST-HIT-WITNESS-LEAK" in {f.rule for f in scan([doc])}
    assert not supported_source([Document("safe.py", "import hashlib\n", None)])


def test_tcp_workflow_handles_64_rounds_with_verified_decisions(monkeypatch):
    import cryptoscan.fischlin_workflow as workflow

    class FakeConnection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("example.test", 3583)
            self.guesses = 0
            self.sent = []
        def until_one(self, markers):
            if markers == (b"which witness do you want to see?", b"you didn't guess the right witness"):
                return b"which witness do you want to see?", markers[0]
            if markers == (b"do you think you can guess my witness? (y,n)", b"you didn't guess the right witness"):
                return (b'w0 = 12\nhere is your fishlin transcript\n' +
                        json.dumps(dict(a0=1,a1=2,e=0,e0=1,e1=1,z0=1,z1=2)).encode() +
                        b'\ndo you think you can guess my witness? (y,n)'), markers[0]
            if markers == (b"which witness did the prover use?",):
                return b"which witness did the prover use?", markers[0]
            assert self.sent[-1] == "1"
            self.guesses += 1
            if self.guesses == 64:
                return b"well done, you distinguished all the witnesses!", markers[1]
            return b"round: 1\nwhich witness do you want to see?", markers[0]
        def send(self, value):
            self.sent.append(str(value))
        def read_tail(self):
            return b"\nb'crypto{mock_verified_flag}'\n"
        def close(self):
            pass

    monkeypatch.setattr(workflow, "_Connection", FakeConnection)
    monkeypatch.setattr(workflow, "identify_simulated_branch",
                        lambda proof, witness, index, q: 1)
    docs = [Document("chal.py", SOURCE, None),
            Document("params.py", f"p={P}\nq={Q}\ng=2\n", None)]
    flag = recover_flag(docs, "example.test", 3583, progress=lambda _: None)
    assert flag == "crypto{mock_verified_flag}"


def test_fischlin_first_hit_math_supports_other_challenge_spaces_and_oracles():
    # Construct a transcript where branch zero's witness would create an
    # earlier acceptable hash, excluding branch zero as the real one.
    q, witness, nonce = 23, 3, 7
    transcript = {
        "a0": 2, "a1": 3, "e": 5,
        "e0": 2, "e1": 7,
        "z0": (nonce + 2*witness) % q,
        "z1": 9,
    }
    def synthetic_oracle(a0, a1, e, e0, e1, z0, z1):
        return 0 if e == 1 else 2**32
    result = identify_simulated_branch(
        transcript, witness, 0, q, challenge_count=16,
        acceptance_bound=2**8, random_oracle=synthetic_oracle,
    )
    assert result == 1
    assert identify_simulated_branch(
        transcript, witness, 0, q, challenge_count=16,
        acceptance_bound=2**8, random_oracle=lambda *args: 2**32,
    ) is None
