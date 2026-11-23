"""End-to-end regression for the generic chosen-plaintext Jacobian solver.

Synthetic state coefficients are derived from independent valid Mumford
divisors on fresh random hyperelliptic curves. A mocked TCP server
supplies ciphertexts; no known challenge flag, modulus or state is stored.
"""
from __future__ import annotations

import json
import socket
import struct
from dataclasses import replace

import pytest

from cryptoscan.hyperelliptic_live import (
    analyze_transcript, collect_oracle, derive_flag_candidates,
    investigate, source_input_prompt,
)
from cryptoscan.hyperelliptic_state_leak import extract_instance
from cryptoscan.parser import Document
from test_hyperelliptic_state_leak import _valid_observations, fresh_source


def _fixture(genus=3, prime=1019, *, flag=b"LAB{a}"):
    source = fresh_source(
        genus=genus, coefficient_type="H", fixed_multiplier=43,
        known=b" trail",
    )
    document = Document("new_source.sage", source, None)
    profile = extract_instance([document])
    assert profile is not None
    assert profile.prime == prime
    polynomial, divisors = _valid_observations(
        prime, genus, seed=143+genus,
    )
    states = [
        struct.pack("<" + "H"*(2*genus), *u[:-1], *v)
        for u,v in divisors
    ]
    stream = b"".join(states)
    plaintext = flag + profile.known_plaintext_suffix
    key = stream[:len(plaintext)]
    ciphertext = bytes(x ^ y for x,y in zip(plaintext, key))
    return [document], profile, polynomial, stream, ciphertext, flag


def test_full_curve_and_flag_recovery_on_unseen_synthetic_divisors():
    docs, profile, polynomial, stream, ciphertext, flag = _fixture()
    result = analyze_transcript(stream, ciphertext, profile)
    assert result.recovered_flag == flag.decode()
    assert result.candidates == 1
    assert result.polynomial == tuple(polynomial)
    assert result.states == 4
    assert result.report()["status"] == "flag-recovered"


def test_longer_flag_produces_certified_partial_curve_only():
    docs, profile, polynomial, stream, _, flag = _fixture()
    longer = b"LAB{aa}"
    ciphertext = bytes(
        x ^ y for x,y in zip(
            longer + profile.known_plaintext_suffix, stream,
        )
    )
    result = analyze_transcript(stream, ciphertext, profile)
    assert result.polynomial == tuple(polynomial)
    assert result.recovered_flag is None
    assert result.report()["status"] == "partial"
    assert "full first Mumford v" in result.explanation


def test_inconsistent_known_plaintext_rejects_nonfield_v():
    docs, profile, polynomial, stream, ciphertext, flag = _fixture()
    # If every word of v is larger than the finite field, it is not
    # a valid source-compatible divisor.
    tampered = bytearray(ciphertext)
    tampered[profile.genus*profile.coefficient_bytes:] = b"\xff"*6
    candidates, reason = derive_flag_candidates(
        bytes(tampered), polynomial, profile,
    )
    assert not candidates


def test_prompt_derived_from_source_ast_not_a_known_challenge_string():
    docs, *_ = _fixture()
    assert source_input_prompt(docs) == "New ciphertext oracle: "


class FakeJacobianService:
    def __init__(self, prompt, ciphertext, stream):
        self.prompt = prompt.encode()
        self.ciphertext = ciphertext
        self.stream = stream
        self.buffer = bytearray(ciphertext.hex().encode()+b"\n"+self.prompt)
        self.requests = []
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, value):
        self.timeout = value

    def recv(self, limit):
        if not self.buffer:
            raise socket.timeout()
        block = self.buffer[:limit]
        del self.buffer[:limit]
        return bytes(block)

    def sendall(self, payload):
        self.requests.append(payload)
        assert payload.endswith(b"\n")
        assert bytes.fromhex(payload[:-1].decode()) == b"\x00"*len(self.stream)
        self.buffer.extend(self.stream.hex().encode()+b"\n"+self.prompt)


def test_tcp_capture_full_investigation_and_verified_solver(monkeypatch):
    import cryptoscan.hyperelliptic_live as live
    from cryptoscan.cli import main

    docs, profile, polynomial, stream, ciphertext, flag = _fixture()
    services = []
    def connect(*args, **kwargs):
        srv = FakeJacobianService(
            source_input_prompt(docs), ciphertext, stream,
        )
        services.append(srv)
        return srv
    monkeypatch.setattr(live.socket, "create_connection", connect)
    first = investigate(docs, "localhost", 39003)
    assert first.recovered_flag == flag.decode()
    assert first.polynomial == tuple(polynomial)
    assert services[-1].requests == [
        b"00"*(len(stream)) + b"\n",
    ]


def test_cli_investigate_json_is_one_document(tmp_path, monkeypatch, capsys):
    import cryptoscan.hyperelliptic_live as live
    from cryptoscan.cli import main

    docs, profile, polynomial, stream, ciphertext, flag = _fixture()
    path = tmp_path/"unknown.sage"
    path.write_text(docs[0].text, encoding="utf-8")
    monkeypatch.setattr(
        live.socket, "create_connection",
        lambda *args, **kwargs: FakeJacobianService(
            source_input_prompt(docs), ciphertext, stream,
        ),
    )
    assert main([
        str(path), "--investigate", "--format", "json",
        "--host", "example.invalid", "--port", "39003",
    ]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == 1
    assert result["investigation"]["status"] == "flag-recovered"
    assert result["investigation"]["recovered_flag"] == flag.decode()
    assert result["investigation"]["curve_polynomial"] == [
        str(c) for c in polynomial
    ]


def test_cli_solve_uses_verification_and_never_networks_during_planning(
        tmp_path, monkeypatch, capsys):
    import cryptoscan.hyperelliptic_live as live
    from cryptoscan.cli import main

    docs, profile, polynomial, stream, ciphertext, flag = _fixture()
    path = tmp_path/"unknown.sage"
    path.write_text(docs[0].text, encoding="utf-8")
    calls = []
    def connect(*args, **kwargs):
        calls.append(1)
        return FakeJacobianService(
            source_input_prompt(docs), ciphertext, stream,
        )
    monkeypatch.setattr(live.socket, "create_connection", connect)
    assert main([
        str(path), "--plan-attacks", "--format", "json",
        "--host", "example.invalid", "--port", "39003",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(
        item["status"] == "applicable"
        and item["family"] == "Jacobian Mumford known-plaintext divisor recovery"
        for item in report["attack_plan"]
    )
    assert not calls
    assert main([
        str(path), "--solve",
        "--host", "example.invalid", "--port", "39003",
    ]) == 0
    assert calls == [1]
    assert "FLAG: LAB{a}" in capsys.readouterr().out


def test_investigate_requires_explicit_authorized_endpoint(tmp_path):
    from cryptoscan.cli import main
    docs, *_ = _fixture()
    path = tmp_path/"sample.sage"
    path.write_text(docs[0].text, encoding="utf-8")
    with pytest.raises(SystemExit):
        main([str(path), "--investigate"])
