"""Source-driven assistant must not guess formats from unrelated CTFs."""
from types import SimpleNamespace

from cryptoscan.assistant import assistant_session
from cryptoscan.parser import Document
from cryptoscan.source_context import discover_token_recipes, linked_recipe, relevant_source


SOURCE = '''
from json import dumps, loads
from gcm import GCM, IV_LEN
IV = b"\\x00" * IV_LEN

def build_token(key, username, role):
    gcm = GCM(key, IV)
    token = dumps({"username": username, "role": role}).encode()
    ct, tag = gcm.encrypt(token)
    return ";".join([ct.hex(), tag.hex()])

def verif_token(key, token):
    gcm = GCM(key, IV)
    ct, tag = [bytes.fromhex(a) for a in token.split(";")]
    pt, is_auth = gcm.decrypt(ct, tag)
    if loads(pt.decode())["role"] != "super_admin":
        return False
    return True
'''
SAFE_SOURCE = SOURCE.replace(
    'if loads(pt.decode())["role"] != "super_admin":',
    'if not is_auth:\n        return False\n    if loads(pt.decode())["role"] != "super_admin":'
)


def docs(source=SOURCE):
    return [Document("challenge.zip!/crypto.py", source, None, "challenge", "abcd")]


def fake_finding(rule="AEAD-AUTH-RESULT-IGNORED", location="challenge.zip!/crypto.py:14"):
    return SimpleNamespace(
        rule=rule,
        location=location,
        severity="critical",
        title="Unchecked auth",
        recovery_status="validation-only",
        preconditions=[],
        playbook=[],
        solver={"kind": "source_guidance"},
    )


def test_source_recipe_derived_from_real_builder_and_verifier():
    recipes = discover_token_recipes(docs())
    assert len(recipes) == 1
    recipe = recipes[0]
    assert recipe.fields == ("username", "role")
    assert recipe.ignore_authentication
    assert linked_recipe(fake_finding(), recipes) == recipe


def test_checked_tag_does_not_produce_recipe():
    assert discover_token_recipes(docs(SAFE_SOURCE)) == []


def test_unrelated_finding_cannot_use_token_recipe():
    recipe = discover_token_recipes(docs())
    assert linked_recipe(fake_finding("HASH-WEAK"), recipe) is None
    assert linked_recipe(fake_finding(location="unrelated.py:14"), recipe) is None


def test_unrelated_source_or_missing_builder_not_detected():
    assert discover_token_recipes([Document("crypto.py", "def foo():\n    pass", None)]) == []
    assert discover_token_recipes(docs(SOURCE.replace('";".join([ct.hex(), tag.hex()])', 'ct.hex()'))) == []


def test_source_line_is_grounded():
    line = SOURCE.splitlines().index('    pt, is_auth = gcm.decrypt(ct, tag)') + 1
    contexts = relevant_source(fake_finding(location=f"challenge.zip!/crypto.py:{line}"), docs())
    assert len(contexts) == 1
    assert contexts[0].function == "verif_token"
    assert "decrypt" in contexts[0].excerpt


def test_assistant_uses_source_recipe_and_rejects_insufficient_known_bytes():
    output = []
    choices = iter([
        "1", "y", "demo", "guest", "00;"+ "00"*16,
        "super_admin", "", "q",
    ])
    finding = fake_finding()
    assistant_session([finding], lambda _prompt: next(choices), output.append, docs())
    report = "\n".join(output)
    assert "Source-verified token construction" in report
    assert "Cannot derive token from current evidence" in report
    assert "Password is NOT a token plaintext field" in report


def test_no_documents_disables_recipe():
    output = []
    assistant_session([fake_finding()], lambda _prompt: "q", output.append)
    assert "No analyzed source loaded" in "\n".join(output)
