from __future__ import annotations

import math
from decimal import Decimal, localcontext

from cryptoscan.hint_factor_rsa import extract_instance, recover_flag
from cryptoscan.parser import Document


SOURCE = """
from Crypto.Util.number import getPrime
p = getPrime(40)
q = getPrime(40)
n = p*q
scale = 1048576
hint = int(scale*sqrt(p) + scale*sqrt(q))
for b in bits:
    c.append(pow(x, 1337+b, n) * pow(r, 2674, n) % n)
"""


def _documents() -> list[Document]:
    p, q = 549755813911, 2199023255579
    n, scale = p * q, 1 << 20
    with localcontext() as context:
        context.prec = 100
        hint = int(Decimal(scale) * (Decimal(p).sqrt() + Decimal(q).sqrt()))
    x = 2
    while not (pow(x, (p - 1) // 2, p) == p - 1
               and pow(x, (q - 1) // 2, q) == q - 1):
        x += 1
    bits = "0100000101000010"
    ciphertexts = [
        pow(x, 1337 + int(bit), n) * pow(1, 2674, n) % n
        for bit in bits
    ]
    output = f"hint = {hint}\nscale = {scale}\nn = {n}\nc = {ciphertexts}\n"
    return [Document("source.py", SOURCE, None),
            Document("output.txt", output, None)]


def test_extract_and_recover_square_root_hint():
    documents = _documents()
    instance = extract_instance(documents)
    assert instance is not None
    assert instance.scale == 1 << 20
    assert recover_flag(documents) == "AB"
