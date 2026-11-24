import pytest
from cryptoscan.parser import Document
from cryptoscan.rsa_related_key import (
    extract_instance,
    recover_message,
    source_profiles,
)
from cryptoscan.scanner import scan


def corpus(exponent):
    n = 101 * 113
    order = 100 * 112
    inverse = pow(exponent, -1, order)
    source = f"""
public = {exponent}
modulus = first * second
order = (first - 1) * (second - 1)
private = pow(public, -1, order)
alpha = pow(private, public, modulus)
beta = pow(order, public, modulus)
gamma = pow(secret, public, modulus)
"""
    output = f"modulus = {n}\nalpha = {pow(inverse, exponent, n)}\n"
    output += f"beta = {pow(order, exponent, n)}\ngamma = {pow(65, exponent, n)}\n"
    return [Document("renamed", source, None), Document("numbers", output, None)]


@pytest.mark.parametrize("exponent", [3, 11, 13, 17])
def test_recovery(exponent):
    docs = corpus(exponent)
    instance = extract_instance(docs)
    assert instance is not None
    assert recover_message(instance) == b"A"


def test_detection():
    docs = corpus(3)
    assert any(f.rule == "RSA-RELATED-KEY-MATERIAL" for f in scan(docs))


def test_source_only():
    docs = corpus(3)
    assert source_profiles(docs[0])
    assert extract_instance(docs[:1]) is None


def test_no_inverse():
    docs = corpus(3)
    source = docs[0].text.replace("pow(public, -1, order)", "pow(public, 1, order)")
    assert not source_profiles(Document("ordinary", source, None))


def test_unrelated_scope():
    docs = corpus(3)
    assert extract_instance([docs[0], Document("other", docs[1].text, None, "elsewhere")]) is None


def test_cli_large_message_and_source_only_exponent(tmp_path, capsys):
    from cryptoscan.cli import main
    from sympy import nextprime

    exponent = 3
    primes = []
    for offset in (123, 98765):
        prime = int(nextprime((1 << 1023) + offset))
        while prime % exponent != 2:
            prime = int(nextprime(prime))
        primes.append(prime)
    p, q = primes
    n = p * q
    order = (p - 1) * (q - 1)
    private = pow(exponent, -1, order)
    token = "TEST{" + "related" * 35 + "}"
    message = int.from_bytes(token.encode(), "big")
    assert message < n < message ** exponent
    source = corpus(exponent)[0].text.replace(
        "modulus = first * second",
        "first = getStrongPrime(1024, e=public)\n"
        "second = getStrongPrime(1024, e=public)\n"
        "modulus = first * second",
    )
    output = (
        f"modulus = {n}\nalpha = {pow(private, exponent, n)}\n"
        f"beta = {pow(order, exponent, n)}\n"
        f"gamma = {pow(message, exponent, n)}\n"
    )
    (tmp_path / "arbitrary.py").write_text(source, encoding="utf-8")
    (tmp_path / "arbitrary.txt").write_text(output, encoding="utf-8")
    assert main([str(tmp_path), "--format", "json"]) == 0
    assert "RSA-RELATED-KEY-MATERIAL" in capsys.readouterr().out
    assert main([str(tmp_path), "--solve"]) == 0
    assert token in capsys.readouterr().out


def test_hacktm_shape_survives_unrelated_reassignment():
    source = """
import os
from Crypto.Util.number import bytes_to_long, getStrongPrime

scratch = 1
scratch = 2
flag = os.environ.get("FLAG", "FAKEFLAG{" + "A" * 245 + "}").encode()
assert len(flag) == 255
e = 3
p = getStrongPrime(1024, e=e)
q = getStrongPrime(1024, e=e)
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
enc_d = pow(d, e, n)
enc_phi = pow(phi, e, n)
enc_flag = pow(bytes_to_long(flag), e, n)
"""
    profiles = source_profiles(Document("chall.py", source, None))
    assert len(profiles) == 1
    profile = profiles[0]
    assert profile.exponent == 3
    assert profile.modulus == "n"
    assert profile.inverse_cipher == "enc_d"
    assert profile.order_cipher == "enc_phi"
    assert profile.message_cipher == "enc_flag"


def test_reassignment_of_relevant_binding_stays_ambiguous():
    docs = corpus(3)
    source = docs[0].text.replace(
        "public = 3",
        "public = 3\npublic = 5",
    )
    assert not source_profiles(Document("ambiguous", source, None))


def test_hacktm_public_instance_end_to_end():
    """Regression for the published HackTM d-phi-enc corpus.

    This intentionally uses the real public transcript rather than only a
    synthetic toy modulus, so scanner integration and large-integer recovery
    stay covered together.
    """
    source = """\
import os
from Crypto.Util.number import bytes_to_long, getStrongPrime

flag = os.environ.get("FLAG", "FAKEFLAG{" + "A" * 245 + "}").encode()
assert len(flag) == 255
e = 3
p = getStrongPrime(1024, e=e)
q = getStrongPrime(1024, e=e)
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
enc_d = pow(d, e, n)
enc_phi = pow(phi, e, n)
enc_flag = pow(bytes_to_long(flag), e, n)
"""
    output = """\
n = 24476383567792760737445809443492789639532562013922247811020136923589010741644222420227206374197451638950771413340924096340837752043249937740661704552394497914758536695641625358888570907798672682231978378863166006326676708689766394246962358644899609302315269836924417613853084331305979037961661767481870702409724154783024602585993523452019004639755830872907936352210725695418551084182173371461071253191795891364697373409661909944972555863676405650352874457152520233049140800885827642997470620526948414532553390007363221770832301261733085022095468538192372251696747049088035108525038449982810535032819511871880097702167
enc_d = 23851971033205169724442925873736356542293022048328010529601922038597156073052741135967263406916098353904000351147783737673489182435902916159670398843992581022424040234578709904403027939686144718982884200573860698818686908312301218022582288691503272265090891919878763225922888973146019154932207221041956907361037238034826284737842344007626825211682868274941550017877866773242511532247005459314727939294024278155232050689062951137001487973659259356715242237299506824804517181218221923331473121877871094364766799442907255801213557820110837044140390668415470724167526835848871056818034641517677763554906855446709546993374
enc_phi = 3988439673093122433640268099760031932750589560901017694612294237734994528445711289776522094320029720250901589476622749396945875113134575148954745649956408698129211447217738399970996146231987508863215840103938468351716403487636203224224211948248426979344488189039912815110421219060901595845157989550626732212856972549465190609710288441075239289727079931558808667820980978069512061297536414547224423337930529183537834934423347408747058506318052591007082711258005394876388007279867425728777595263973387697391413008399180495885227570437439156801767814674612719688588210328293559385199717899996385433488332567823928840559
enc_flag = 24033688910716813631334059349597835978066437874275978149197947048266360284414281504254842680128144566593025304122689062491362078754654845221441355173479792783568043865858117683452266200159044180325485093879621270026569149364489793568633147270150444227384468763682612472279672856584861388549164193349969030657929104643396225271183660397476206979899360949458826408961911095994102002214251057409490674577323972717947269749817048145947578717519514253771112820567828846282185208033831611286468127988373756949337813132960947907670681901742312384117809682232325292812758263309998505244566881893895088185810009313758025764867
"""
    docs = [
        Document("chall.py", source, None),
        Document("output.txt", output, None),
    ]
    findings = scan(docs)
    assert any(f.rule == "RSA-RELATED-KEY-MATERIAL" for f in findings)

    instance = extract_instance(docs)
    assert instance is not None
    plaintext = recover_message(instance)
    assert plaintext.startswith(b"HackTM{")
    assert plaintext.endswith(b"}")
    assert len(plaintext) == 255


@pytest.mark.parametrize(
    "inverse_expression",
    [
        "inverse(public, order)",
        "mod_inverse(public, order)",
        "number.inverse(public, order)",
        "sympy.mod_inverse(public, order)",
    ],
)
def test_common_inverse_call_spellings(inverse_expression):
    source = corpus(3)[0].text.replace(
        "pow(public, -1, order)",
        inverse_expression,
    )
    profiles = source_profiles(Document("alternate_inverse.py", source, None))
    assert len(profiles) == 1
    assert profiles[0].exponent == 3


@pytest.mark.parametrize("exponent", [3, 11])
def test_renamed_aliases_and_integer_casts(exponent):
    docs = corpus(exponent)
    source = docs[0].text.replace(
        "private = pow(public, -1, order)",
        "power_alias = public\n"
        "power_twice = power_alias\n"
        "private = pow(power_twice, -1, order)\n"
        "private_alias = private\n"
        "order_alias = order",
    ).replace(
        "alpha = pow(private, public, modulus)",
        "alpha = int(pow(private_alias, power_twice, modulus))",
    ).replace(
        "beta = pow(order, public, modulus)",
        "beta = int(pow(order_alias, power_twice, modulus))",
    ).replace(
        "gamma = pow(secret, public, modulus)",
        "gamma = int(pow(secret, power_twice, modulus))",
    )
    renamed = [Document("unknown_program", source, None), docs[1]]
    profiles = source_profiles(renamed[0])
    assert len(profiles) == 1
    instance = extract_instance(renamed)
    assert instance is not None
    assert recover_message(instance) == b"A"
    assert any(f.rule == "RSA-RELATED-KEY-MATERIAL" for f in scan(renamed))


def test_unrelated_cast_or_cyclic_exponent_is_not_a_profile():
    source = corpus(3)[0].text
    assert not source_profiles(Document(
        "cast_before_pow", source.replace(
            "alpha = pow(private, public, modulus)",
            "alpha = int(private) ** public % modulus",
        ), None,
    ))
    assert not source_profiles(Document(
        "cyclic", source.replace("public = 3", "public = alias\nalias = public"),
        None,
    ))


