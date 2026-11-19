"""General Fiat-Shamir grinding regression and graph proof TCP integration."""
import hashlib
import json

import pytest

from cryptoscan.fiat_shamir_grinding import (
    grind_challenge, grind_pedersen_graph_opening, iterated_graph_hash,
    verify_pedersen_graph_opening,
)
from cryptoscan.hamiltonicity_workflow import extract_instance, recover_flag
from cryptoscan.parser import Document
from cryptoscan.scanner import scan


# Deliberately different graph, parameters, round count, and filenames from
# the original CTF. The graph has no Hamiltonian cycle.
GRAPH = [[0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1], [0, 0, 0, 0]]
PARAMS = (23, 11, 4, 9)

CHALLENGE = '''
from helper import hash_committed_graph, open_graph, permute_graph, testcycle
import json
numrounds = 20
LocalTest = False
if LocalTest:
    G = [[0, 1], [1, 0]]
else:
    G = [[0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1], [0, 0, 0, 0]]
FS_state = b""
for i in range(numrounds):
    payload = json.loads(input(b"send fiat shamir proof: "))
    A = payload["A"]
    z = payload["z"]
    FS_state = hash_committed_graph(A, FS_state, comm_params)
    challenge = FS_state[-1] & 1
    if challenge:
        cycle, openings = z
        if not testcycle(A, N, cycle, openings):
            exit()
    else:
        permutation, openings = z
        G_permuted = open_graph(A, N, openings)
        G_test = permute_graph(G, N, permutation)
        if G_permuted == G_test:
            print("accepted")
        else:
            exit()
'''
HELPER = '''
from hashlib import sha256
P = 23
q = 11
h1 = 4
h2 = 9
comm_params = P, q, h1, h2
def hash_committed_graph(G, state, comm_params):
    fs_state = sha256(str(comm_params).encode())
    fs_state.update(state)
    first_message = "".join([str(x) for xs in G for x in xs])
    fs_state.update(first_message.encode())
    return fs_state.digest()
'''


def docs():
    return [Document("challenge.py", CHALLENGE, None),
            Document("helper.py", HELPER, None)]


def test_generic_grinding_independent_of_graphs():
    counter = 0
    def propose():
        nonlocal counter
        counter += 1
        return counter, {"nonce": counter}
    commitment, opening, state, trials = grind_challenge(
        b"",
        propose,
        lambda item, previous: hashlib.sha256(previous + str(item).encode()).digest(),
        lambda digest: digest[-1] % 4 == 0,
        max_trials=512,
    )
    assert state[-1] % 4 == 0
    assert opening == {"nonce": commitment}
    assert trials == commitment


def test_grind_nonhamiltonian_graph_for_multiple_rounds():
    state = b""
    for _ in range(20):
        commitments, proof, next_state, attempts = grind_pedersen_graph_opening(
            GRAPH, PARAMS, state, max_trials=256)
        assert 1 <= attempts <= 256
        assert next_state[-1] & 1 == 0
        assert next_state == iterated_graph_hash(commitments, state, PARAMS)
        assert verify_pedersen_graph_opening(commitments, proof, GRAPH, PARAMS)
        state = next_state
    commitments[0][0] ^= 1
    assert not verify_pedersen_graph_opening(commitments, proof, GRAPH, PARAMS)


def test_detect_fiat_shamir_grinding_from_source_semantics():
    instance = extract_instance(docs())
    assert instance is not None
    assert instance.rounds == 20
    assert instance.graph == GRAPH
    assert instance.pedersen_params == PARAMS
    assert instance.prompt == b"send fiat shamir proof: "
    findings = [f for f in scan(docs()) if f.rule == "FIAT-SHAMIR-GRINDABLE-CHALLENGE"]
    assert len(findings) == 1
    assert findings[0].recovery_status == "validation-only"


def test_reject_non_grindable_challenge():
    changed = CHALLENGE.replace("FS_state[-1] & 1", "FS_state[-1] & 3")
    assert extract_instance([Document("no.py", changed, None), docs()[1]]) is None


def test_solver_completes_all_rounds_with_real_graph_proofs(monkeypatch):
    import cryptoscan.hamiltonicity_workflow as workflow

    class FakeServer:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("example.test", 14635)
            self.state = b""
            self.count = 0
            self.buffer = b""
        def until(self, marker):
            if marker == b"send fiat shamir proof: ":
                return marker
            assert marker == b"accepted\n"
            assert self.buffer == b"accepted\n"
            self.buffer = b""
            return marker
        def send(self, message):
            payload = json.loads(message.decode())
            commitments, opening = payload["A"], payload["z"]
            self.state = iterated_graph_hash(commitments, self.state, PARAMS)
            assert self.state[-1] & 1 == 0
            assert verify_pedersen_graph_opening(commitments, opening, GRAPH, PARAMS)
            self.count += 1
            self.buffer = b"accepted\n"
        def rest(self):
            assert self.count == 20
            return b"You've convinced me!\n" + repr(b"crypto{local_mock_flag}").encode() + b"\n"
        def close(self):
            pass

    monkeypatch.setattr(workflow, "_Connection", FakeServer)
    result = recover_flag(docs(), "example.test", 14635, progress=lambda _: None)
    assert result == "crypto{local_mock_flag}"


def test_no_fabricated_flag_after_accepted_rounds(monkeypatch):
    import cryptoscan.hamiltonicity_workflow as workflow
    class FakeServer:
        def __init__(self, *args): pass
        def until(self, marker): return marker
        def send(self, message): pass
        def rest(self): return b"no flag disclosed"
        def close(self): pass
    monkeypatch.setattr(workflow, "_Connection", FakeServer)
    with pytest.raises(RuntimeError, match="did not return"):
        recover_flag(docs(), "example.test", 14635, progress=lambda _: None)
