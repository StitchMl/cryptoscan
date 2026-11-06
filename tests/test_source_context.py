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
    assert recipe.required_fields == ("role",)
    assert recipe.required_values == (("role", "super_admin"),)
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


def test_assistant_uses_minimal_required_fields_from_source():
    output = []
    original_hex = (
        "afbbb704b5f8af60f155aa7dfe5c9ec7b5e91228430226bd1f382815e044f6f4daf7d18412"
    )
    tag = "a2f8064887d8e6529fe3df5058058418"
    choices = iter(["1", "y", "demo", "guest", original_hex + ";" + tag, "q"])
    finding = fake_finding()
    assistant_session([finding], lambda _prompt: next(choices), output.append, docs())
    report = "\n".join(output)
    assert "Verifier-required fields: role" in report
    assert 'Minimal plaintext: {"role": "super_admin"}' in report
    assert (
        "afbbb018bcefe33bbc12fb32ae1b88fdb9e25d6d0d0229;" + tag
    ) in report
    assert "Cannot derive token" not in report


def test_no_documents_disables_recipe():
    output = []
    assistant_session([fake_finding()], lambda _prompt: "q", output.append)
    assert "No analyzed source loaded" in "\n".join(output)


def test_renamed_functions_still_recognized():
    alternate = SOURCE.replace("build_token", "issue_session").replace("verif_token", "check_session")
    recipes = discover_token_recipes(docs(alternate))
    assert len(recipes) == 1
    assert recipes[0].build.function == "issue_session"
    assert recipes[0].verify.function == "check_session"


def test_different_gcm_iv_is_not_an_approved_recipe():
    changed = SOURCE.replace("gcm = GCM(key, IV)", "gcm = GCM(key, OTHER_IV)", 1)
    assert discover_token_recipes(docs(changed)) == []


def test_non_default_json_serialization_is_not_assumed():
    changed = SOURCE.replace("}).encode()", "}, separators=(',', ':')).encode()")
    assert discover_token_recipes(docs(changed)) == []


def test_verifier_reading_multiple_fields_produces_no_unjustified_minimization():
    changed = SOURCE.replace(
        'if loads(pt.decode())["role"] != "super_admin":',
        'if loads(pt.decode())["role"] != "super_admin" or loads(pt.decode())["username"] != "admin":',
    )
    assert discover_token_recipes(docs(changed)) == []


def test_verifier_with_non_boolean_success_does_not_claim_recipe():
    changed = SOURCE.replace('    return True', '    return loads(pt.decode())["role"]')
    assert discover_token_recipes(docs(changed)) == []


def test_arbitrary_field_and_target_are_inferred_without_role_assumptions():
    changed = SOURCE.replace('"role": role', '"level": level').replace(
        'def build_token(key, username, role):', 'def build_token(key, username, level):'
    ).replace('["role"] != "super_admin"', '["level"] != "captain"')
    recipes = discover_token_recipes(docs(changed))
    assert len(recipes) == 1
    assert recipes[0].fields == ("username", "level")
    assert recipes[0].required_values == (("level", "captain"),)
    assert recipes[0].required_fields == ("level",)
