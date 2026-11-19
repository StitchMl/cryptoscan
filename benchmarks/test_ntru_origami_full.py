"""End-to-end NTRU folding benchmark on the original public Origami corpus.

Run this test only in the optional native-BKZ benchmark workflow.
It invokes the same public, generic solver used by cryptoscan --solve;
the expected string is a test assertion, not a solver constant.
"""
from pathlib import Path

from cryptoscan.ntru_auto import recover_flag
from cryptoscan.parser import collect_documents

FIXTURE = Path(__file__).parent / "fixtures" / "ntru_origami"


def test_original_ntru_key_recovery_with_native_bkz():
    documents = collect_documents([str(FIXTURE)])
    flag = recover_flag(
        documents,
        backend="fplll",
        bkz=20,
        initial_degree=64,
        timeout_seconds=900,
        progress=print,
    )
    assert flag == "NNS{k33p_f0ld1ng_4nd_f0ld1ng_l1k3_4n_0r1g4m1_m4st3r}"
