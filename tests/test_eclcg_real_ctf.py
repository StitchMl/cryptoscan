"""Real HITCON ECLCG regression using the original public challenge artifacts."""
from pathlib import Path
import pytest

from cryptoscan.eclcg_workflow import extract_instance, recover_flag
from cryptoscan.parser import collect_documents

FIXTURE = Path(__file__).parent / "fixtures" / "eclcg"
EXPECTED = "hitcon{it_is_all_LLL_all_the_way_down?_always_have_been_:)}"


def test_hitcon_eclcg_original_artifacts():
    pytest.importorskip("flint")
    pytest.importorskip("Crypto")
    docs = collect_documents([str(FIXTURE / "chall.py"), str(FIXTURE / "output.txt")])
    instance = extract_instance(docs)
    assert instance is not None
    assert len(instance.messages) == len(instance.signatures) == 17
    assert recover_flag(docs, progress=lambda _: None) == EXPECTED
