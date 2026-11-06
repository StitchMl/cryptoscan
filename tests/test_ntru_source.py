"""Regression coverage for NTRU coefficient data vs byte-ciphertext detectors."""
import random
from cryptoscan.ntru import analyze_ntru_vectors, recognize_ntru
from cryptoscan.parser import Document
from cryptoscan.scanner import scan


def source(n=64, df=5, dg=5, dr=3, q=127):
    return f"""
n,p,q,df,dg,dr=[{n},2,{q},{df},{dg},{dr}]
R.<x> = ZZ[]
Rqn = Integers(q)[].quotient(x^n-1)
def random_poly(d):
    for i in sample(range(n),d):
        pass
def publickey_gen(f,g):
    h = Rqn(g)/Rqn(f)
    return h
def encrypt(h,m):
    r = random_poly(dr)
    c = p * h * Rqn(r) + Rqn(m)
    return c
"""


def docs(n=64, df=5, dg=5, dr=3, q=127, message_weight=17):
    src = Document("demo/source.sage", source(n, df, dg, dr, q), None, "demo", "source")
    pk = [0] * n
    pk[0] = (dg * pow(df, -1, q)) % q
    ct = [0] * n
    ct[0] = (2 * pk[0] * dr + message_weight) % q
    output = Document("demo/observations.txt", f"pk = {pk}\nct = {ct}\n", None, "demo", "output")
    return [src, output]


def test_projection_recovers_weight_mod_q_from_independent_parameters():
    documents = docs(n=64, df=5, dg=10, dr=3, message_weight=19)
    context = recognize_ntru(documents)[0]
    import ast
    output = documents[1].text.splitlines()
    public = ast.literal_eval(output[0].split("=", 1)[1])
    ciphertext = ast.literal_eval(output[1].split("=", 1)[1])
    projection = analyze_ntru_vectors(public, ciphertext, context)
    assert projection.public_relation_verified
    assert projection.public_evaluation == 2
    assert projection.message_weight_residue == 19
    assert projection.possible_weights == (19,)


def test_ntru_arrays_not_treated_as_xor_bytes_or_flag():
    randomizer = random.Random(740)
    n = 512
    q = 127
    public = [randomizer.randrange(q) for _ in range(n)]
    public[0] = (public[0] - sum(public) + 1) % q
    cipher = [randomizer.randrange(q) for _ in range(n)]
    output = Document("demo/output.txt", f"pk = {public}\nct = {cipher}\n", None, "demo", "output")
    src = Document("demo/source.sage", source(n, 35, 35, 22, q), None, "demo", "source")
    findings = scan([src, output])
    rules = {item.rule for item in findings}
    assert "NTRU-X1-HAMMING-LEAK" in rules
    assert "XOR-REPEATING-KEY" not in rules
    assert "XOR-SINGLE-BYTE" not in rules
    assert "BLOCK-ECB-REPETITION" not in rules
    ntru = next(item for item in findings if item.rule == "NTRU-X1-HAMMING-LEAK")
    assert ntru.recovery_status == "validation-only"
    assert ntru.solver["kind"] == "ntru_x1_projection"


def test_no_ntru_rule_without_source_proof():
    docs_input = docs()
    bad = docs_input[0].text.replace("p * h * Rqn(r)", "h * Rqn(r)")
    assert not recognize_ntru([
        Document("demo/source.sage", bad, None, "demo", "source")
    ])


def test_existing_xor_cryptogram_still_detected():
    from cryptoscan.parser import collect_documents
    from tempfile import TemporaryDirectory
    from pathlib import Path
    plain = b"message=flag{repeating_xor_recovered};padding=english-text"
    key = b"Secret!"
    cipher = bytes(v ^ key[i % len(key)] for i, v in enumerate(plain))
    with TemporaryDirectory() as root:
        path = Path(root) / "sample.json"
        path.write_text('{"ct": "' + cipher.hex() + '"}')
        findings = scan(collect_documents([str(path)]))
    assert "XOR-REPEATING-KEY" in {item.rule for item in findings}
