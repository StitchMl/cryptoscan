"""Regression checks for evidence-driven cross-family CTF workflows."""
from types import SimpleNamespace

from cryptoscan.guided import (
    cbc_iv_workflow,
    existing_verified_result,
    rsa_factors_workflow,
    selected_finding_workflow,
)
from cryptoscan.assistant import assistant_session


def feed(*answers):
    sequence = iter(answers)
    return lambda _prompt: next(sequence)


def finding(rule, solver, status="payload-ready"):
    return SimpleNamespace(rule=rule, recovery_status=status, solver=solver)


def test_rsa_factor_workflow_proves_reencryption():
    output = []
    # 61*53=3233, phi=3120, e=17, d=2753, ciphertext for integer 65 is 2790.
    rsa_factors_workflow(feed("61", "53", "17", "2790"), output.append)
    lines = "\n".join(output)
    assert "Computed modulus n: 3233" in lines
    assert "Computed private exponent d: 2753" in lines
    assert "Recovered plaintext (UTF-8): A" in lines
    assert "re-encryption" not in lines or "PASS" in lines


def test_rsa_rejects_bad_exponent():
    output = []
    rsa_factors_workflow(feed("61", "53", "3120", "2790"), output.append)
    assert "not invertible" in "\n".join(output)


def test_rsa_rejects_same_factor():
    output = []
    rsa_factors_workflow(feed("61", "61", "17", "2790"), output.append)
    assert "distinct primes" in "\n".join(output)


def test_cbc_iv_workflow_and_algebraic_check():
    output = []
    iv = bytes(16)
    original = b"A" * 16
    desired = b"B" * 16
    cbc_iv_workflow(feed(iv.hex(), original.hex(), desired.hex()), output.append)
    assert "Modified IV (hex): " + ("03" * 16) in "\n".join(output)
    assert "Local XOR proof: PASS" in "\n".join(output)


def test_cbc_length_mismatch_fails_safely():
    output = []
    cbc_iv_workflow(feed("00" * 16, "41" * 16, "42" * 4), output.append)
    assert "equal 8/16-byte lengths" in "\n".join(output)


def test_verified_solver_shows_result_without_new_inputs():
    output = []
    assert existing_verified_result(
        finding("RSA-E3-EXACT-ROOT", {"kind": "integer_root", "result_hex": "4142", "result_int": "16706"}),
        output.append,
    )
    assert "Recovered bytes (UTF-8): AB" in "\n".join(output)


def test_validation_only_never_claims_verified_payload():
    output = []
    assert not existing_verified_result(
        finding("NONCE-CONSTANT", {"kind": "source_guidance"}, "validation-only"),
        output.append,
    )
    assert not output


def test_known_prime_rsa_finding_is_interactive():
    output = []
    selected_finding_workflow(
        finding("RSA-SHARED-PRIME", {"kind": "rsa_shared_prime", "p": "61", "q1": "53"}),
        feed("y", "61", "53", "17", "2790"), output.append,
    )
    assert "Recovered plaintext (UTF-8): A" in "\n".join(output)


def test_assistant_standalone_menu_supports_more_than_cookie():
    output = []
    assistant_session(read=feed("f", "61", "53", "17", "2790", "q"), write=output.append)
    assert "Computed private exponent d: 2753" in "\n".join(output)


def test_unverified_rsa_root_does_not_invent_plaintext():
    output = []
    selected_finding_workflow(
        finding("RSA-E3-EXACT-ROOT", {"kind": "source_guidance"}, "validation-only"),
        write=output.append,
    )
    assert "No verified RSA plaintext yet" in "\n".join(output)
