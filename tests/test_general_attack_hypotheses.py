"""Hypothesis tests for transfer to previously unseen source structures.

These signals are explicitly NOT verified vulnerabilities. They should
suggest mathematical experiments when exact protocol extraction fails.
"""
from cryptoscan.crypto_hypotheses import inspect_hypotheses
from cryptoscan.parser import Document


def families(source):
    return {hypothesis.family for hypothesis in inspect_hypotheses([
        Document("unknown_program.py", source, None),
    ])}


def test_unseen_polynomial_gcd_output_leak_is_hypothesized():
    source = """
import math as M
t = int(input("custom> "))
g = M.gcd(t**7 + 17, (t - 3)**7 + 8)
print(secret[:g])
"""
    assert "Attacker-controlled polynomial GCD information leak" in families(source)


def test_unseen_signature_distribution_is_hypothesized():
    source = """
from secrets import randbelow
def assemble(witness, order):
    first = [randbelow(1 << 256) for _ in range(7)]
    second = [randbelow(1 << 256) for _ in range(7)]
    first[witness] = (11 + witness) % order
    second[witness] = (12 + witness) % order
    return first, second
"""
    assert "Signature scalar distribution distinguishability" in families(source)


def test_unseen_quaternion_conjugation_suggests_equivalent_keys():
    source = """
import hashlib
from Crypto.Cipher import AES
omega = private**-1 * public**-1 * private
key = hashlib.sha256(str(omega).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
"""
    assert "Conjugation equivalent-key recovery" in families(source)


def test_unseen_affine_group_combination_suggests_discrete_log_check():
    source = """
E = EllipticCurve(GF(prime), [a, b])
observation = scalar_one * P + scalar_two * Q
"""
    assert "Public linear combinations over a group" in families(source)


def test_hypotheses_do_not_claim_unrelated_source_vulnerable():
    assert not families("def harmless():\n    return 42\n")


def test_hypotheses_not_promoted_to_confirmed_solver():
    source = """
import math
x = int(input("x"))
y = math.gcd(x**2 + 1, x**2 + 3)
print(secret[:y])
"""
    matched = inspect_hypotheses([Document("unknown.py", source, None)])
    assert matched
    assert not hasattr(matched[0], "recovered_flag")
