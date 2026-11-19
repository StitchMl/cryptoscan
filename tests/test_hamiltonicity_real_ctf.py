"""Full original CryptoHack Hamiltonicity input regression.

The CTF source is parsed statically, not imported or executed. Independent
cryptographic verification confirms that fresh commitments satisfy the
published public graph and its Fiat-Shamir challenge.
"""
from pathlib import Path

from cryptoscan.fiat_shamir_grinding import (
    grind_pedersen_graph_opening, iterated_graph_hash,
    verify_pedersen_graph_opening,
)
from cryptoscan.hamiltonicity_workflow import extract_instance
from cryptoscan.parser import collect_documents
from cryptoscan.scanner import scan


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "fiat_shamir_hamiltonicity"
ACTUAL_GRAPH = [
    [0, 0, 1, 0, 0],
    [1, 0, 0, 0, 0],
    [0, 1, 0, 0, 0],
    [0, 0, 0, 0, 1],
    [0, 0, 0, 1, 0],
]


def test_original_cryptohack_files_are_recognized():
    documents = collect_documents([str(FIXTURE_DIR)])
    assert len(documents) == 3
    instance = extract_instance(documents)
    assert instance is not None
    assert instance.graph == ACTUAL_GRAPH
    assert instance.rounds == 128
    assert instance.pedersen_params[0].bit_length() >= 1000
    assert instance.prompt == b"send fiat shamir proof: "
    findings = [f for f in scan(documents)
                if f.rule == "FIAT-SHAMIR-GRINDABLE-CHALLENGE"]
    assert len(findings) == 1
    assert findings[0].recovery_status == "validation-only"


def test_original_cryptohack_parameters_accept_local_grinding():
    instance = extract_instance(collect_documents([str(FIXTURE_DIR)]))
    assert instance is not None
    fs_state = b""
    for _ in range(4):
        commitment, opening, result, tries = grind_pedersen_graph_opening(
            instance.graph, instance.pedersen_params, fs_state,
            max_trials=256)
        assert tries > 0
        assert result[-1] & 1 == 0
        assert verify_pedersen_graph_opening(
            commitment, opening, instance.graph, instance.pedersen_params)
        assert iterated_graph_hash(commitment, fs_state,
                                   instance.pedersen_params) == result
        fs_state = result
