"""CODEGATE TCP orchestration tests with a deterministic in-memory protocol."""
from pathlib import Path
import hashlib
import pytest

import cryptoscan.gcm_hidden_live as live
from cryptoscan.parser import collect_documents


SOURCE = Path(__file__).parent / "fixtures" / "gcm_hidden_state" / "chall.py"
NONCE = b"ABCDEFGHIJKLMNOPQRST"
POW_VALUE = 1234
POW_BANNER = (
    b"md5(str(n).encode() + b'ABCDEFGHIJKLMNOPQRST').hexdigest() = "
    + hashlib.md5(str(POW_VALUE).encode() + NONCE).hexdigest().encode()
    + b"\nInput the decimal result of n within range(2**26): "
)


def test_real_codegate_source_is_recognized():
    from cryptoscan.gcm_hidden_state import recognize_gcm_tag_oracle
    from cryptoscan.scanner import scan
    docs = collect_documents([str(SOURCE)])
    result = recognize_gcm_tag_oracle(docs)
    assert len(result) == 1
    assert result[0].timeout_seconds == 20
    assert result[0].pow_difficulty == 26
    assert "GCM-HIDDEN-STATE-TAG-ORACLE" in {f.rule for f in scan(docs)}


def test_pow_and_ansi_flag_parser():
    assert live._solve_pow(POW_BANNER) == POW_VALUE
    assert live._read_flag(b"\x1b[92mCODEGATE{mock_solution}\x1b[0m") == "CODEGATE{mock_solution}"
    assert live._read_flag(b"wrong tag") is None


def test_verified_flag_requires_actual_remote_reply(monkeypatch):
    docs = collect_documents([str(SOURCE)])
    records = []

    class FakeConnection:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("example.test", 2762)
            self.requests = 0

        def until(self, marker):
            if marker == b"): ":
                return POW_BANNER
            return marker

        def send(self, data):
            records.append(data)

        def tags(self, count):
            self.requests += 1
            assert count in (151, 7, 5)
            return [b"\0"*16 for _ in range(count)]

        def rest(self):
            return b"\x1b[95mCODEGATE{mock_verified_flag}\x1b[0m"

        def close(self):
            pass

    monkeypatch.setattr(live, "_Connection", FakeConnection)
    monkeypatch.setattr(live, "recover_ghash_key_from_u1_tag_differences",
                        lambda diffs: 100)
    monkeypatch.setattr(live, "identify_growth_prefix",
                        lambda h, tags: (1, 1, 1, 0, 0, 0))
    monkeypatch.setattr(live, "recover_empty_gcm_tag_candidates",
                        lambda h, tags: {0xABCD})
    assert live.recover_flag(docs, "example.test", 2762,
                             max_sessions=1, max_growth_trials=1,
                             progress=lambda _: None) == "CODEGATE{mock_verified_flag}"
    assert records[0] == b"1234\n"
    assert records[-1] == f"{0xABCD:032x}\n".encode()


def test_solver_does_not_fabricate_unverified_flag(monkeypatch):
    docs = collect_documents([str(SOURCE)])
    class FakeConnection:
        def __init__(self, host, port, timeout):
            pass
        def until(self, marker):
            return POW_BANNER if marker == b"): " else marker
        def send(self, data):
            pass
        def tags(self, count):
            return [b"\0"*16 for _ in range(count)]
        def rest(self):
            return b"nope"
        def close(self):
            pass

    monkeypatch.setattr(live, "_Connection", FakeConnection)
    monkeypatch.setattr(live, "recover_ghash_key_from_u1_tag_differences", lambda _: 100)
    monkeypatch.setattr(live, "identify_growth_prefix", lambda *args: (1,1,1,0,0,0))
    monkeypatch.setattr(live, "recover_empty_gcm_tag_candidates", lambda *args: {0xABCD})
    with pytest.raises(RuntimeError, match="No remotely verified flag"):
        live.recover_flag(docs, "example.test", 2762,
                          max_sessions=1, max_growth_trials=1, progress=lambda _: None)
