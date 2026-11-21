"""Synthetic bounded EC-ElGamal OT tests; no challenge fixtures or secrets."""
import ast

from cryptoscan.bounded_ot import _selection, extract_instance
from cryptoscan.parser import Document


def synthetic_source(first="alpha", second="beta", choice="vote"):
    return f'''
import json
from Crypto.PublicKey.ECC import EccPoint
from Crypto.Random import random
p = 101
q = 11
Gx = 1
Gy = 2
class Encryption:
    def from_pt(self, value): return EccPoint(Gx, Gy)
    def __add__(self, other): return self
    def __rmul__(self, other): return self
    def __sub__(self, other): return self

def exchange():
    data = json.loads(input("Encrypted choice: "))
    {choice} = Encryption()
    {first} = random.randint(2, 5)
    {second} = random.randint(7, 10)
    response = {first} * (1-{choice}) + {second} * {choice}
    answer = json.loads(input("Recovered values: "))
    return response, answer

def get_key():
    key = json.loads(input("Chosen public key: "))
    return EccPoint(key["Hx"], key["Hy"])

def run():
    get_key()
    for _ in range(5):
        exchange()
'''


def test_detects_renamed_selector_and_message_bounds():
    model = extract_instance([Document("unseen.py", synthetic_source(), None)])
    assert model is not None
    assert (model.low0, model.high0, model.low1, model.high1) == (2, 5, 7, 10)
    assert model.rounds == 5
    assert model.prompts == (
        "Chosen public key: ", "Encrypted choice: ", "Recovered values: ",
    )


def test_checked_selector_is_not_classified_as_exploitable():
    source = synthetic_source().replace(
        "response = alpha", "assert vote in (0, 1)\n    response = alpha",
    )
    assert extract_instance([Document("unseen.py", source, None)]) is None


def test_reordered_homomorphic_selector_recognized():
    expr = ast.parse("result = y*c + x*(1-c)").body[0].value
    assert _selection(expr) == ("x", "y", "c")


def test_no_arbitrary_python_source_execution():
    source = synthetic_source() + '\nraise RuntimeError("never execute scanned sources")\n'
    assert extract_instance([Document("unseen.py", source, None)]) is not None

def test_chosen_ciphertext_recovers_independent_message_pairs():
    """Use randomized curve keys and pairs, without public challenge fixtures."""
    from Crypto.PublicKey import ECC
    from cryptoscan.bounded_ot import BoundedOT, _parameters, _recover_reply
    import json

    key = ECC.generate(curve="P-256")
    generator = key.pointQ
    order = int(ECC._curves["P-256"].order)
    instance = BoundedOT("", int(generator.x), int(generator.y), 0, order,
                         0, 9, 0, 9, 8, ("key:", "choice:", "answer:"))
    secret, table, _, chosen = _parameters(instance, generator)
    assert secret != 1
    H = secret * generator
    choice_R = ECC.EccPoint(chosen["Rx"], chosen["Ry"])
    choice_S = ECC.EccPoint(chosen["Sx"], chosen["Sy"])
    for m0 in range(10):
        for m1 in range(10):
            # Model the EC-ElGamal OT homomorphic response with independent
            # rerandomization. The expected messages are not hardcoded.
            nonce = (m0 + 7) * 11 + m1 + 1
            R = nonce * generator + ((m1 - m0) % order) * choice_R
            S = nonce * H + m0 * generator + ((m1 - m0) % order) * choice_S
            response = json.dumps({"Rx": int(R.x), "Ry": int(R.y),
                                   "Sx": int(S.x), "Sy": int(S.y)})
            class Reply:
                def line(self):
                    return response

            assert _recover_reply(Reply(), ECC.EccPoint, secret, table) == (m0, m1)


def test_bounded_ot_resolver_accepts_renamed_data_file():
    model = extract_instance([Document("generic_payload.unknown", synthetic_source(), None)])
    assert model is not None
    assert model.rounds == 5
