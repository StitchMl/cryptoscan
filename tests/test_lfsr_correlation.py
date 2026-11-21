"""General source-driven LFSR fast correlation benchmarks."""
from pathlib import Path
from dataclasses import replace
import random

from cryptoscan.lfsr_correlation import (
    lfsr_bits, low_weight_trinomials, polynomial_remainders, solve_gf2,
)
from cryptoscan.stream_combiner_workflow import (
    StreamCipherInstance, parse_stream_combiner, recognize_stream_cipher,
    recover_stream_cipher, pack_bits, unpack_bits,
)
from cryptoscan.parser import Document, collect_documents
from cryptoscan.scanner import scan
from cryptoscan.cli import main


FIXTURE = Path(__file__).parent / "fixtures" / "lfsr_correlation"
SAMPLE_FLAG = b"hitcon{independent_lfsr_recovery_regression}"


def _fixture_documents():
    return collect_documents([str(FIXTURE)])


def _test_stream(model, states, length):
    streams = {}
    for i, seed in enumerate(states):
        clocks = model.clocks[i]
        bits = lfsr_bits(seed, model.masks[i], model.degree, length * clocks)
        streams[i] = [
            sum(bits[t * clocks + j] for j in range(clocks)) & 1
            for t in range(length)
        ]
    return [model.mix([streams[i][t] for i in range(len(states))])
            for t in range(length)]


def test_sparse_multiples_are_derived_not_hardcoded():
    instance = recognize_stream_cipher(_fixture_documents())[0]
    model = instance.model
    pairs = [low_weight_trinomials(mask, model.degree, maximum_degree=1024)
             for mask in model.masks]
    assert not pairs[0]
    assert pairs[1]
    assert pairs[2]
    assert not pairs[3]
    for index in (1, 2):
        a, b = pairs[index][0]
        values = polynomial_remainders(model.masks[index], model.degree, a + 1)
        assert values[0] ^ values[b] ^ values[a] == 0


def test_full_original_hyper_stream_recovers_and_validates_flag():
    matches = recognize_stream_cipher(_fixture_documents())
    assert len(matches) == 1
    recovered = recover_stream_cipher(matches[0], progress=lambda _: None)
    assert recovered == "hitcon{larger_states_is_still_no_match_of_fast_correlation_attacks!}"


def test_random_seeds_and_renamed_symbols():
    source = (FIXTURE / "chall.py").read_text()
    altered = source.replace("MASK2", "FEEDBACK_B").replace(
        "self.lfsr2", "self.random_register_b"
    ).replace("y = ", "alpha = ").replace("1 * y", "1 * alpha")
    model = parse_stream_combiner(altered, "unseen_source.py")
    assert model is not None
    rng = random.Random(20261119)
    states = [rng.getrandbits(model.degree) for _ in model.masks]
    length = 4096 * 8 + len(SAMPLE_FLAG) * 8
    stream = _test_stream(model, states, length)
    initial = pack_bits(stream[:4096 * 8])
    hidden = bytes(a ^ b for a, b in zip(
        SAMPLE_FLAG, pack_bits(stream[4096 * 8:]), strict=True))
    output = Document("unseen_output.txt", initial.hex() + "\n" + hidden.hex(), None)
    found = recognize_stream_cipher([Document("unseen_source.py", altered, None), output])
    assert found
    assert recover_stream_cipher(found[0], progress=lambda _: None) == SAMPLE_FLAG.decode()


def test_short_inputs_do_not_enable_unsupported_solver():
    source = (FIXTURE / "chall.py").read_text()
    docs = [Document("a.py", source, None),
            Document("b.txt", "0011\n22\n", None)]
    assert recognize_stream_cipher(docs) == []


def test_full_source_produces_finding_and_cli_flag(capsys):
    docs = _fixture_documents()
    assert "LFSR-FAST-CORRELATION-STREAM-LEAK" in {f.rule for f in scan(docs)}
    assert main([str(FIXTURE), "--solve", "--no-color"]) == 0
    assert "FLAG: hitcon{" in capsys.readouterr().out


def test_binary_field_solver_rejects_inconsistency():
    assert solve_gf2([(1, 0), (1, 1)], 1) is None
    assert solve_gf2([(1, 1), (2, 1)], 2) == 3


def test_lfsr_recognizer_does_not_require_python_suffix():
    from dataclasses import replace
    original = _fixture_documents()
    alternate = [replace(doc, path=f"anon_{index}.data")
                 for index, doc in enumerate(original)]
    models = recognize_stream_cipher(alternate)
    assert len(models) == 1
