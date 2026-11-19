"""Validate GHASH empty-message pad recovery on authentic AES-GCM tags."""
import random
import pytest

from cryptoscan.gcm_hidden_growth import (
    identify_growth_prefix, recover_empty_gcm_tag_candidates,
)


def test_recover_empty_tag_candidates_from_real_gcm_growth():
    AES = pytest.importorskip("Crypto.Cipher.AES")
    rng = random.Random(1245)
    key = bytes(range(16))
    nonce = b"0123456789ab"
    ecb = AES.new(key, AES.MODE_ECB)
    h = int.from_bytes(ecb.encrypt(bytes(16)), "big")
    expected_pad = int.from_bytes(ecb.encrypt(nonce + bytes.fromhex("00000001")), "big")

    aad, plaintext = rng.randbytes(12), rng.randbytes(12)

    def tag():
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        cipher.encrypt(plaintext)
        return cipher.digest()

    tags = [tag()]
    choices = (1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1)
    for choice in choices:
        if choice:
            plaintext += rng.randbytes(12)
        else:
            aad += rng.randbytes(12)
        tags.append(tag())

    assert identify_growth_prefix(h, tags) == choices[:6]
    candidates = recover_empty_gcm_tag_candidates(h, tags)
    assert expected_pad in candidates
    assert 1 <= len(candidates) <= 1024


def test_reject_missing_growth_transcript():
    with pytest.raises(ValueError):
        recover_empty_gcm_tag_candidates(1, [b"0"*16])
