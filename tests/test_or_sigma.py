"""Independent Schnorr OR-proof tests with small synthetic groups.

No copied CTF artifact, public parameters, witness, or flag.
"""
import secrets

import pytest

from cryptoscan.or_sigma import (
    OrSchnorr, Transcript, extract_witness, first_round, respond, simulate, verify,
)


@pytest.mark.parametrize("branch", (0, 1))
def test_correctness_and_hvzk(branch):
    p, q, g = 23, 11, 2
    for _ in range(32):
        witnesses = (secrets.randbelow(q), secrets.randbelow(q))
        publics = tuple(pow(g, w, p) for w in witnesses)
        model = OrSchnorr(p, q, g, publics, branch, witnesses[branch])
        initial, randomizer = first_round(model, 3)
        challenge = secrets.randbelow(8)
        assert verify(p, g, publics, respond(model, initial, randomizer, challenge), challenge)
        assert verify(p, g, publics, simulate(p, q, g, publics, challenge, 3), challenge)


@pytest.mark.parametrize("branch", (0, 1))
def test_special_soundness(branch):
    p, q, g = 23, 11, 2
    witness, randomizer = 7, 4
    publics = [pow(g, 2, p), pow(g, 9, p)]
    publics[branch] = pow(g, witness, p)
    publics = tuple(publics)
    fake = 1 - branch
    e_fake, z_fake = 3, 8
    a = [0, 0]
    a[branch] = pow(g, randomizer, p)
    a[fake] = pow(g, z_fake, p) * pow(pow(publics[fake], e_fake, p), -1, p) % p
    proofs = []
    for challenge in (4, 6):
        e, z = [0, 0], [0, 0]
        e[fake], z[fake] = e_fake, z_fake
        e[branch] = challenge ^ e_fake
        z[branch] = (randomizer + e[branch] * witness) % q
        proofs.append(Transcript(tuple(a), tuple(e), tuple(z)))
    assert extract_witness(p, q, g, publics, 4, proofs[0], 6, proofs[1]) == witness


def test_invalid_rewind_rejected():
    transcript = Transcript((2, 2), (1, 0), (3, 4))
    with pytest.raises(ValueError):
        extract_witness(23, 11, 2, (2, 4), 1, transcript, 2, transcript)
