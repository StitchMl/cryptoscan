"""Synthetic Groth16 ticket tests: no challenge material or endpoints."""
from __future__ import annotations

import json
import math
import socket
import threading

import pytest

from cryptoscan.groth16_ticket import (
    BASE_FIELD, FQ2_B, SCALAR_FIELD, _add, _compress, _decompress, _mul,
    _scalar_mul, extract_instance, recover_flag, rerandomize_proof,
)
from cryptoscan.parser import Document

# Public BN254 standard generator, unrelated to any ticket service.
G1 = (1, 2)
G2 = (
    (10857046999023057135944570762232829481370756359578518086990519993285655852781,
     11559732032986387107991004021392285783925812861821192530917403151452391805634),
    (8495653923123431417604973247489272438418190587263600148770280649306958101930,
     4082367875863433681332203403145435568316851327593401208105741076214120093531),
)


def _synthetic_rust_sources():
    proof_source = """
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
struct Store { spent: HashSet<[u8; 32]> }
struct Ticket { pub proof: String }
fn proof(bytes: Vec<u8>) {
    Groth16::<Bn254>::prove();
    Groth16::<Bn254>::verify();
    Proof::<Bn254>::deserialize(&bytes);
    self.digest.serialize(&mut ser);
    proof.serialize(&mut ser);
    let id = blake2::Blake2b::digest(&ser);
    self.spent.insert(id);
}
"""
    economy_source = """
const BALANCE: i64 = 6;
let mut balance: i64 = BALANCE;
const COST_OF_FLAG: i64 = 3 * BALANCE;
const COST_OF_TICKET: i64 = 1;
const VALUE_OF_TICKET: i64 = 2;
match event {
    Request::BuyTicket => { balance -= COST_OF_TICKET; Response::Ticket(ticket) }
    Request::Redeem => { balance += VALUE_OF_TICKET; Response::GoodTicket }
    Request::BuyFlag => {
        if balance >= COST_OF_FLAG { Response::Flag(message) }
    }
}
"""
    return (Document("protocol.rs", proof_source, None),
            Document("economy.rs", economy_source, None))


def _synthetic_proof():
    a = _scalar_mul(G1, 7)
    b = _scalar_mul(G2, 11)
    c = _scalar_mul(G1, 13)
    return (_compress(a, 1) + _compress(b, 2) + _compress(c, 1)).hex()


def test_source_recognition_general_economy():
    model = extract_instance(_synthetic_rust_sources())
    assert model is not None
    assert (model.starting_balance, model.ticket_cost,
            model.redemption_value, model.flag_cost) == (6, 1, 2, 18)
    assert model.redemptions_needed == 7


def test_rejects_weakly_related_protocol_without_proof_hash():
    first, second = _synthetic_rust_sources()
    source = first.text.replace("proof.serialize(&mut ser)", "// omitted")
    assert extract_instance([Document(first.path, source, None), second]) is None


def test_rejects_no_redeem_bounty_or_ambiguous_instance():
    first, second = _synthetic_rust_sources()
    broken = second.text.replace("balance += VALUE_OF_TICKET",
                                 "balance -= VALUE_OF_TICKET")
    assert extract_instance([first, Document(second.path, broken, None)]) is None
    assert extract_instance([first, first, second]) is None


def test_bn254_standard_g1_g2_generators_are_on_curve():
    assert G1[1]**2 % BASE_FIELD == (G1[0]**3 + 3) % BASE_FIELD
    assert _mul(G2[1], G2[1]) == _add(
        _mul(_mul(G2[0], G2[0]), G2[0]), FQ2_B,
    )


@pytest.mark.parametrize("scale", [1, 2, 3, 7, 19, 31])
def test_pairing_invariant_scalar_rerandomization(scale):
    raw = _synthetic_proof()
    altered = rerandomize_proof(raw, scale)
    original = bytes.fromhex(raw)
    derived = bytes.fromhex(altered)
    assert len(derived) == 128
    assert derived[96:] == original[96:]
    a = _decompress(derived[:32], 1)
    b = _decompress(derived[32:96], 2)
    assert a == _scalar_mul(G1, 7*scale)
    assert b == _scalar_mul(G2, (11*pow(scale, -1, SCALAR_FIELD)) % SCALAR_FIELD)
    assert 7*scale*(11*pow(scale, -1, SCALAR_FIELD)) % SCALAR_FIELD == 77


def test_variants_are_distinct_and_canonically_round_trip():
    proof = _synthetic_proof()
    variants = {rerandomize_proof(proof, value) for value in range(1, 18)}
    assert len(variants) == 17
    assert proof in variants
    for sample in variants:
        data = bytes.fromhex(sample)
        assert _compress(_decompress(data[:32], 1), 1) == data[:32]
        assert _compress(_decompress(data[32:96], 2), 2) == data[32:96]


def test_invalid_proof_or_scalar_rejected():
    with pytest.raises(ValueError):
        rerandomize_proof("bad", 2)
    sample = _synthetic_proof()
    with pytest.raises(ValueError):
        rerandomize_proof(sample, SCALAR_FIELD)
    with pytest.raises(ValueError):
        rerandomize_proof("00"*128, 2)


def test_full_synthetic_tcp_ticket_lifecycle(monkeypatch):
    import cryptoscan.groth16_ticket as module

    original = _synthetic_proof()
    valid = {rerandomize_proof(original, scale) for scale in range(1, 8)}
    left, right = socket.socketpair()
    problems = []

    def server():
        balance, spent = 6, set()
        try:
            with right:
                reader = right.makefile("rb")
                right.sendall(b'{"Hello":"Synthetic ticket system"}\n')
                while True:
                    line = reader.readline()
                    if not line:
                        break
                    command = json.loads(line)
                    if command == "BuyTicket":
                        balance -= 1
                        response = {"Ticket": {"proof": original}}
                    elif isinstance(command, dict) and "Redeem" in command:
                        proof = command["Redeem"]["proof"]
                        if proof in valid and proof not in spent:
                            spent.add(proof)
                            balance += 2
                            response = "GoodTicket"
                        else:
                            response = "BadTicket"
                    elif command == "BuyFlag":
                        response = ({"Flag": "DEMO{synthetic_redeem}"} if balance >= 18
                                    else "LolTooPoor")
                    else:
                        response = "BadTicket"
                    right.sendall(json.dumps(response).encode() + b"\n")
        except BaseException as error:
            problems.append(error)

    monkeypatch.setattr(module.socket, "create_connection",
                        lambda *args, **kwargs: left)
    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    result = recover_flag(_synthetic_rust_sources(), "127.0.0.1", 1)
    thread.join(timeout=4)
    assert not problems
    assert result == "DEMO{synthetic_redeem}"


def test_groth16_replay_matches_content_without_rs_extensions():
    first, second = _synthetic_rust_sources()
    docs = [
        Document("arbitrary_document.txt", first.text, None),
        Document("ticket_economy.backup", second.text, None),
    ]
    model = extract_instance(docs)
    assert model is not None
    assert model.redemptions_needed == 7
