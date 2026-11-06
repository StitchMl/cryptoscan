"""Independent regression tests for overlapping-counter GCM workflow."""
import json

from cryptoscan.gcm_overlap_detector import counter_overlap_lines
from cryptoscan.gcm_overlap_math import compute_counter_overlap_candidates, ghash
from cryptoscan.gcm_overlap_workflow import find_overlap_recipe, guided_overlap_workflow
from cryptoscan.parser import Document
from cryptoscan.scanner import scan


CUSTOM_GCM = """
class GCM:
    def encrypt(self, P, A=b""):
        J = self.iv + b"suffix"
        C = self.gctr(J, P)
        T = self.build_tag(C, A, J)
        return C, T

    def build_tag(self, C, A, J):
        S = self.ghash(C, self.H)
        return self.gctr(J, S)
"""

AUTHENTICATED_CODEC = """
from json import dumps, loads
from gcm import GCM
IV = b"constant"

def issue(key, identity, level):
    gcm = GCM(key, IV)
    plaintext = dumps({"identity": identity, "level": level}).encode()
    ct, tag = gcm.encrypt(plaintext)
    return ";".join([ct.hex(), tag.hex()])

def verify(key, token):
    gcm = GCM(key, IV)
    ct, tag = [bytes.fromhex(x) for x in token.split(";")]
    pt, valid = gcm.decrypt(ct, tag)
    if loads(pt.decode())["level"] != "captain":
        return False
    if not valid:
        return False
    return True
"""


def documents(codec=AUTHENTICATED_CODEC, implementation=CUSTOM_GCM):
    return [
        Document("sample/crypto.py", codec, None, "sample", "a"),
        Document("sample/gcm/gcm.py", implementation, None, "sample", "b"),
    ]


def test_counter_overlap_found_but_incremented_ctr_is_not():
    assert counter_overlap_lines(CUSTOM_GCM)
    fixed = CUSTOM_GCM.replace("self.gctr(J, P)", "self.gctr(self.inc(J), P)")
    assert not counter_overlap_lines(fixed)


def test_scan_reports_overlap_finding():
    findings = scan(documents())
    assert any(item.rule == "GCM-COUNTER-OVERLAP" for item in findings)


def test_source_recipe_recognizes_renamed_fields_and_authenticated_verifier():
    docs = documents()
    findings = scan(docs)
    finding = next(item for item in findings if item.rule == "GCM-COUNTER-OVERLAP")
    recipe = find_overlap_recipe(docs, finding.location)
    assert recipe is not None
    assert recipe.plaintext_fields == ("identity", "level")
    assert recipe.required_values == (("level", "captain"),)


def test_no_recipe_if_verifier_does_not_require_target():
    other = AUTHENTICATED_CODEC.replace('["level"] != "captain"', '["another"] != "captain"')
    docs = documents(codec=other)
    findings = scan(docs)
    finding = next(item for item in findings if item.rule == "GCM-COUNTER-OVERLAP")
    assert find_overlap_recipe(docs, finding.location) is None


def test_math_recovers_valid_tag_without_hardcoded_cookie():
    original = json.dumps({"identity": "example", "level": "visitor"}).encode()
    desired = json.dumps({"level": "captain"}).encode()
    stream = bytes((i * 29 + 47) % 256 for i in range(len(original)))
    ciphertext = bytes(a ^ b for a, b in zip(original, stream))
    h = int.from_bytes(bytes.fromhex("a80140b1c49ec35833901ae6ddba2b12"), "big")
    mask = int.from_bytes(stream[:16], "big")
    tag = (ghash(h, ciphertext) ^ mask).to_bytes(16, "big")
    candidates = compute_counter_overlap_candidates(
        ciphertext.hex() + ";" + tag.hex(), original, desired
    )
    assert candidates
    assert any(
        int.from_bytes(bytes.fromhex(item.token.split(";")[1]), "big")
        == ghash(h, bytes.fromhex(item.token.split(";")[0])) ^ mask
        for item in candidates
    )


def test_workflow_asks_for_observed_values_without_ai():
    old = json.dumps({"identity": "example", "level": "visitor"}).encode()
    stream = bytes((i * 17 + 19) % 256 for i in range(len(old)))
    ciphertext = bytes(a ^ b for a, b in zip(old, stream))
    h = int.from_bytes(bytes.fromhex("bc9036f80ed7a2180ceeeab62788bd15"), "big")
    tag = (ghash(h, ciphertext) ^ int.from_bytes(stream[:16], "big")).to_bytes(16, "big")
    docs = documents()
    finding = next(item for item in scan(docs) if item.rule == "GCM-COUNTER-OVERLAP")
    data = iter(["example", "visitor", ciphertext.hex() + ";" + tag.hex()])
    output = []
    guided_overlap_workflow(finding, docs, lambda _prompt: next(data), output.append)
    text = "\n".join(output)
    assert "Computed" in text
    assert "candidate(s)" in text
    assert "captain" in text


def test_malformed_token_is_rejected():
    try:
        compute_counter_overlap_candidates("not-a-cookie", b"a" * 32, b"b" * 16)
    except ValueError as exc:
        assert "expected ciphertext" in str(exc)
    else:
        assert False
