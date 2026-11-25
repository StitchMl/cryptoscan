"""Source-derived detection of RSA factors sharing a digit sequence."""
import json

import pytest

from cryptoscan.parser import Document
from cryptoscan.rsa_reused_digits import extract_instance, source_profile
from cryptoscan.scanner import scan


def _corpus(base=3, *, alias=False):
    imports = (
        "import random as rng\nfrom gmpy2 import digits as repr_digits, "
        "is_prime as prime_test"
        if alias else "import random\nimport gmpy2"
    )
    draw = "rng.getrandbits" if alias else "random.getrandbits"
    digits = "repr_digits" if alias else "gmpy2.digits"
    prime = "prime_test" if alias else "gmpy2.is_prime"
    source = f"""
{imports}
exponent = 65537
radix = {base}
while True:
    left = {draw}(192)
    right = int({digits}(left, radix), 10)
    if not {prime}(left): continue
    if not {prime}(right): continue
    break
modulus = left * right
payload = pow(message, exponent, modulus)
"""
    # The public values need not be a stored challenge factorization:
    # matching is only a source and transcript association.
    output = "n = 123456789012345678901234567890123456789\ne = 65537\nc = 42\n"
    return [Document("generator.py", source, None),
            Document("public.log", output, None)]


@pytest.mark.parametrize("base", [2, 3, 5, 8, 10])
@pytest.mark.parametrize("alias", [False, True])
def test_general_base_and_import_aliases(base, alias):
    docs = _corpus(base, alias=alias)
    profile = source_profile(docs[0])
    assert profile is not None
    assert profile.source_base == base
    assert profile.target_base == 10
    assert profile.prime_bits == 192
    instance = extract_instance(docs)
    assert instance is not None
    assert instance.modulus == 123456789012345678901234567890123456789
    findings = [item for item in scan(docs) if item.rule == "RSA-REUSED-BASE-DIGITS"]
    assert len(findings) == 1
    assert findings[0].evidence["public_modulus_matched"] is True


def test_source_alone_is_reported_without_a_transcript():
    findings = [item for item in scan(_corpus()[:1])
                if item.rule == "RSA-REUSED-BASE-DIGITS"]
    assert len(findings) == 1
    assert findings[0].evidence["public_modulus_matched"] is False
    assert findings[0].recovery_status == "validation-only"


@pytest.mark.parametrize("change", [
    lambda s: s.replace("int(gmpy2.digits(left, radix), 10)", "random.getrandbits(192)"),
    lambda s: s.replace("radix = 3", "radix = 12"),
    lambda s: s.replace("if not gmpy2.is_prime(right): continue", "pass"),
    lambda s: s.replace("modulus = left * right", "modulus = left * other"),
    lambda s: s.replace("payload = pow(message, exponent, modulus)", "payload = message"),
    lambda s: s.replace("int(gmpy2.digits(left, radix), 10)",
                        "int(gmpy2.digits(left, radix), 2)"),
])
def test_unrelated_or_unproven_constructions_are_rejected(change):
    docs = _corpus()
    docs[0] = Document("generator.py", change(docs[0].text), None)
    assert source_profile(docs[0]) is None


def test_scopes_and_ambiguous_transcripts_do_not_join():
    docs = _corpus()
    assert extract_instance([docs[0], Document("other/public.log", docs[1].text,
                                               None, "other")]) is None
    assert extract_instance([*docs, Document("second.log", docs[1].text,
                                             None)]) is None


@pytest.mark.parametrize("draw,import_line", [
    ("secrets.randbits", "import secrets"),
    ("getPrime", "from Crypto.Util.number import getPrime"),
])
def test_independent_prime_draw_implementations(draw, import_line):
    docs = _corpus()
    source = docs[0].text.replace("import random", import_line)
    source = source.replace("random.getrandbits", draw)
    assert source_profile(Document("variant.py", source, None)) is not None


@pytest.mark.parametrize("source_base,target_base", [(2, 16), (12, 20), (30, 36)])
def test_distinct_target_radices(source_base, target_base):
    docs = _corpus(source_base)
    source = docs[0].text.replace("), 10)", f"), {target_base})")
    profile = source_profile(Document("other_radix.py", source, None))
    assert profile is not None
    assert profile.source_base == source_base
    assert profile.target_base == target_base


def test_original_source_shape_and_public_transcript():
    source = """
import random
import gmpy2
e = 0x10001
with open('flag.txt', 'rb') as f:
    m = f.read()
m = int.from_bytes(m, 'big')
while True:
    p = random.getrandbits(256)
    q = int(gmpy2.digits(p, 3))
    if not gmpy2.is_prime(p): continue
    if not gmpy2.is_prime(q): continue
    if (p-1) % e == 0: continue
    if (q-1) % e == 0: continue
    break
n = p * q
c = pow(m, e, n)
"""
    public = (
        "n = 12189464288007059657184858632825479990912616419482466046617619319388181010121359489739982536798361842485210016303524715395474637570227926791570158634811951043352789232959763417380155972853016696908995809240738171081946517881643416715486249\n"
        "e = 65537\n"
        "c = 10093874086170276546167955043813453195412484673031739173390677430603113063707524122014352886564777373620029541666833142412009063988439640569778321681605225404251519582850624600712844557011512775502356036366115295154408488005375252950048742"
    )
    instance = extract_instance([Document("source.py", source, None),
                                 Document("public.txt", public, None)])
    assert instance is not None
    assert instance.source_base == 3
    assert instance.prime_bits == 256


def test_cli_plans_offline_solver(tmp_path, capsys):
    from cryptoscan.cli import main

    for doc in _corpus(7):
        (tmp_path / doc.path).write_text(doc.text, encoding="utf-8")
    assert main([str(tmp_path), "--plan-attacks", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(item["rule"] == "RSA-REUSED-BASE-DIGITS"
               for item in report["findings"])
    assert any(item["family"] == "RSA reused base digits"
               and item["status"] == "applicable"
               for item in report["attack_plan"])
