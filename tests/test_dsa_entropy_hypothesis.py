"""Source-only checks for user-seeded randomness entering DSA verification."""

from pathlib import Path

from cryptoscan.crypto_hypotheses import inspect_hypotheses
from cryptoscan.parser import Document


def _families(source):
    return {
        item.family for item in inspect_hypotheses([
            Document("unknown.py", source, None),
        ])
    }


def test_archived_unrandom_dsa_source_is_recognized():
    path = Path(__file__).parent / "fixtures" / "unrandom_dsa" / "server.py"
    assert "Predictable entropy in DSA verification" in _families(
        path.read_text(encoding="utf-8")
    )


def test_user_seeded_random_replaces_system_entropy_for_dsa_verifier():
    source = """
import os
import random
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

q = int(input("q = "))
seed = int(input("number: "), 16)
os.urandom = random.randbytes
random.seed(seed)
key = DSA.construct((y, g, p, q, x))
verifier = DSS.new(key, "fips-186-3")
verifier.verify(digest, signature)
"""
    assert "Predictable entropy in DSA verification" in _families(source)


def test_import_aliases_are_recognized_without_challenge_names():
    source = """
import os as operating
import random as generator
from Crypto.PublicKey import DSA as KeyFactory
from Crypto.Signature import DSS as SignatureFactory

chosen = int(input("entropy input: "), 16)
operating.urandom = generator.randbytes
generator.seed(chosen)
key = KeyFactory.construct((public, base, modulus, order, private))
SignatureFactory.new(key, "fips-186-3").verify(digest, signed)
"""
    assert "Predictable entropy in DSA verification" in _families(source)


def test_entropy_warning_requires_actual_replacement_and_user_seed():
    source = """
import os
import random
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

# os.urandom = random.randbytes
random.seed(123)
key = DSA.construct((y, g, p, q, x))
DSS.new(key, "fips-186-3").verify(digest, signature)
"""
    assert "Predictable entropy in DSA verification" not in _families(source)


def test_seeded_replacement_without_dsa_verification_is_not_this_signal():
    source = """
import os
import random

os.urandom = random.randbytes
random.seed(int(input("seed: ")))
"""
    assert "Predictable entropy in DSA verification" not in _families(source)
