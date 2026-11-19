"""Regression for a batch Fiat-Shamir proof with ambiguous integer encoding.

Uses the upstream CryptoHack server and helper source as unexecuted fixtures.
The solver contains no target flag, port number, or graph coefficients.
"""
import json
from pathlib import Path

from cryptoscan.cli import main
from cryptoscan.fiat_shamir_batch import (
    _select_commitments, extract_instance, recover_flag,
)
from cryptoscan.fiat_shamir_encoding import (
    construct_equivocal_pedersen_graph, decimal_transcript,
    resegment_row, verify_equivocal_graph_proof,
)
from cryptoscan.fiat_shamir_grinding import iterated_graph_hash
from cryptoscan.parser import Document, collect_documents
from cryptoscan.scanner import scan


FIXTURE = Path(__file__).parent / "fixtures" / "fiat_shamir_hamiltonicity2"


def documents():
    return collect_documents([str(FIXTURE)])


def _valid_cycle_commitments(instance):
    collision = construct_equivocal_pedersen_graph(
        instance.graph, instance.pedersen_params,
    )
    assert decimal_transcript(collision.zero_matrix) == decimal_transcript(collision.one_matrix)
    assert verify_equivocal_graph_proof(
        collision.zero_matrix, collision.zero_opening,
        collision.one_matrix, collision.one_opening,
        instance.graph, instance.pedersen_params,
    )
    return collision


def test_original_hamiltonicity2_source_is_recognized_as_batch_not_grinding():
    docs = documents()
    assert len(docs) == 3
    instance = extract_instance(docs)
    assert instance is not None
    assert instance.rounds == 128
    assert instance.graph == [
        [0, 0, 1, 0, 0], [1, 0, 0, 0, 0], [0, 1, 0, 0, 0],
        [0, 0, 0, 0, 1], [0, 0, 0, 1, 0],
    ]
    assert instance.prompt == b"send fiat shamir proof: "
    found = {finding.rule for finding in scan(docs)}
    assert "FIAT-SHAMIR-AMBIGUOUS-TRANSCRIPT" in found
    assert "FIAT-SHAMIR-GRINDABLE-CHALLENGE" not in found


def test_zero_and_cycle_proofs_are_distinct_but_hash_identical():
    instance = extract_instance(documents())
    assert instance is not None
    collision = _valid_cycle_commitments(instance)
    assert collision.zero_matrix != collision.one_matrix
    assert len(collision.cycle) == len(instance.graph)
    assert all(collision.zero_matrix[i][j] != 0 for i in range(5) for j in range(5))
    payloads, bits = _select_commitments(
        collision, instance.rounds, instance.pedersen_params,
    )
    assert len(payloads) == len(bits) == 128
    state = b""
    for payload in payloads:
        state = iterated_graph_hash(payload["A"], state, instance.pedersen_params)
    actual = format(int.from_bytes(state, "big"), "b")[-128:].zfill(128)
    assert actual == "".join(map(str, bits))
    assert any(bits) and not all(bits)


def test_noncanonical_commits_are_checked_modulo_prime():
    instance = extract_instance(documents())
    assert instance is not None
    collision = _valid_cycle_commitments(instance)
    p = instance.pedersen_params[0]
    assert any(value > p for row in collision.zero_matrix for value in row)
    # A delimiter makes the two matrices distinguishable.
    assert repr(collision.zero_matrix) != repr(collision.one_matrix)


def test_nonmatching_row_resegmentation_returns_none():
    assert resegment_row([14, 24, 3], fixed_entry=99999999, target_index=1) is None


def test_changed_graph_labeling_and_pedersen_base_still_supported():
    instance = extract_instance(documents())
    assert instance is not None
    graph = instance.graph
    permutation = [1, 2, 3, 4, 0]
    new_graph = [[graph[permutation[i]][permutation[j]]
                  for j in range(len(graph))] for i in range(len(graph))]
    p, q, h1, h2 = instance.pedersen_params
    alternate = (p, q, pow(h1, 3, p), h2)
    alternate_collision = construct_equivocal_pedersen_graph(
        new_graph, alternate, max_representatives=16,
    )
    assert verify_equivocal_graph_proof(
        alternate_collision.zero_matrix, alternate_collision.zero_opening,
        alternate_collision.one_matrix, alternate_collision.one_opening,
        new_graph, alternate,
    )


def test_batch_protocol_waits_until_all_proofs_before_verifying(monkeypatch):
    import cryptoscan.fiat_shamir_batch as batch

    docs = documents()
    instance = extract_instance(docs)
    assert instance is not None

    class FakeConnection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("example.test", 34597)
            self.payloads = []

        def until(self, marker):
            assert marker == instance.prompt
            assert len(self.payloads) < instance.rounds
            return marker

        def send(self, message):
            self.payloads.append(json.loads(message))

        def rest(self):
            assert len(self.payloads) == instance.rounds
            chain = b""
            for proof in self.payloads:
                chain = iterated_graph_hash(
                    proof["A"], chain, instance.pedersen_params,
                )
            bits = format(int.from_bytes(chain, "big"), "b")[-instance.rounds:].zfill(instance.rounds)
            for proof, bit in zip(self.payloads, bits):
                assert bit in ("0", "1")
                if bit == "0":
                    perm, openings = proof["z"]
                    assert sorted(perm) == list(range(len(instance.graph)))
                    for i, row in enumerate(proof["A"]):
                        for j, commitment in enumerate(row):
                            value, randomness = openings[i][j]
                            assert value == instance.graph[perm[i]][perm[j]]
                            p, q, h1, h2 = instance.pedersen_params
                            assert commitment % p == pow(h1, value, p) * pow(h2, randomness, p) % p
                else:
                    edges, randomnesses = proof["z"]
                    assert len(edges) == len(instance.graph)
                    assert sorted(u for u, v in edges) == list(range(len(instance.graph)))
                    for index, ((u, v), randomizer) in enumerate(zip(edges, randomnesses)):
                        assert edges[(index + 1) % len(edges)][0] == v
                        p, q, h1, h2 = instance.pedersen_params
                        assert proof["A"][u][v] % p == h1 * pow(h2, randomizer, p) % p
            return b"checking round 127\naccepted\nb'crypto{mock_verified_by_remote}'\n"

        def close(self):
            pass

    monkeypatch.setattr(batch, "_Connection", FakeConnection)
    assert recover_flag(docs, "example.test", 34597, progress=lambda _: None) == (
        "crypto{mock_verified_by_remote}"
    )


def test_missing_range_validation_prevents_false_positive():
    src = (FIXTURE / "hamiltonicity.py").read_text()
    hardened = src.replace(
        "assert len(G) == N, \"G has wrong size\"",
        "assert len(G) == N, \"G has wrong size\"\n"
        "    assert all(isinstance(x, int) and 0 <= x < P for row in G for x in row)",
    )
    docs = [
        Document("chal.py", (FIXTURE / "chal.py").read_text(), None),
        Document("hamiltonicity.py", hardened, None),
    ]
    assert extract_instance(docs) is None
