"""Metamorphic reciprocal-Rabin re-encryption fault tests.

All primes, ciphertexts and oracle responses are synthesized from fresh
parameters. Source fixtures intentionally rename functions, record fields
and wire prompts. No named CTF integers or flags are embedded.
"""
from __future__ import annotations

import json
import random
import socket

import pytest
from Crypto.Util.number import getPrime

from cryptoscan.parser import Document
from cryptoscan.reciprocal_rabin_oracle import (
    _decrypt_candidates, _encrypt, _jacobi, _records_to_factors,
    _recover_constant, _source_profile, extract_instance, recover_details,
)


def _fresh_source(bits=48, labels=("alpha","beta","gamma")):
    a,b,c = labels
    return f'''
from dataclasses import dataclass
from Crypto.Util.number import getPrime

@dataclass
class Key:
    mod: int
    multiplier: int

@dataclass
class Private:
    first: int
    second: int

@dataclass
class Sealed:
    {a}: int
    {b}: int
    {c}: int

def draw_prime(width):
    temp = getPrime(width)
    while temp % 4 != 3:
        temp = getPrime(width)
    return temp

def key_pair(width):
    first, second = draw_prime(width), draw_prime(width)
    n = first*second
    multiplier = 2
    while jacobi(multiplier, first) != -1 or jacobi(multiplier, second) != -1:
        multiplier += 1
    return Key(n, multiplier), Private(first,second)

from sympy import jacobi_symbol as jacobi

def stamp(message, public):
    z = (message + public.multiplier * pow(message,-1,public.mod)) % public.mod
    parity = jacobi(message,public.mod)
    ordering = public.multiplier * pow(message,-1,public.mod) % public.mod < message
    return Sealed(z, parity, ordering)

def inverted_quadratic(a,b,modulus):
    # Independent implementation of arithmetic in F_p[X]/(X**2-aX+b).
    def times(left, right):
        head = (left[0]*right[0] - left[1]*right[1]*b) % modulus
        tail = (left[0]*right[1] + left[1]*right[0]
                + left[1]*right[1]*a) % modulus
        return head,tail
    exponent = (modulus-1)//2
    power = (0,1)
    value = (1,0)
    while exponent:
        if exponent & 1:
            value = times(value,power)
        exponent //= 2
        if exponent:
            power = times(power,power)
    tmp = (-(value[0]-1)*pow(value[1],-1,modulus)) % modulus
    alternate = (a-tmp) % modulus
    return tmp,alternate

def chinese(x, p, y, q):
    return (x + p * ((y-x) * pow(p, -1, q) % q)) % (p*q)

def recover(payload, public, private):
    left = inverted_quadratic(payload.{a}, public.multiplier, private.first)
    right = inverted_quadratic(payload.{a}, public.multiplier, private.second)
    options = []
    for x in left:
        for y in right:
            both = chinese(x, private.first, y, private.second)
            if jacobi(both,public.mod) == payload.{b}:
                options.append(both)
    assert len(options) == 2
    options.sort()
    return options[payload.{c}]

factor_bits = {bits}
pub,secret = key_pair(factor_bits)
print("secret document:")
print(stamp(123456789,pub))
while True:
    try:
        v1,v2,v3 = map(int,input("please give three integers: ").split(","))
        item = Sealed(v1,v2,v3)
        returned = stamp(recover(item,pub,secret),pub)
        print("validated ciphertext:")
        print(returned)
    except Exception:
        print("invalid parameters")
'''


def _quadratic_root_pair(r,c,p):
    def product(left,right):
        u = (left[0]*right[0]-left[1]*right[1]*c)%p
        v = (left[0]*right[1]+left[1]*right[0]+left[1]*right[1]*r)%p
        return u,v
    power=(p-1)//2
    current=(0,1)
    result=(1,0)
    while power:
        if power & 1:
            result=product(result,current)
        power//=2
        if power:
            current=product(current,current)
    first=(-(result[0]-1)*pow(result[1],-1,p))%p
    return (first,(r-first)%p)


def _gen_instance(bits=48, seed=73):
    rng=random.Random(seed)
    def prime():
        value=getPrime(bits, randfunc=rng.randbytes)
        while value % 4 != 3:
            value=getPrime(bits, randfunc=rng.randbytes)
        return value
    p,q=prime(),prime()
    while p==q:
        q=prime()
    n=p*q
    c=2
    while _jacobi(c,p)!=-1 or _jacobi(c,q)!=-1:
        c+=1
    return p,q,c


def _simulate(r,s,t,p,q,c):
    n=p*q
    try:
        left=_quadratic_root_pair(r,c,p)
        right=_quadratic_root_pair(r,c,q)
        replies=[]
        for x in left:
            for y in right:
                m=(x+p*((y-x)*pow(p,-1,q)%q))%n
                if _jacobi(m,n)==s:
                    replies.append(m)
        assert len(replies)==2
        replies.sort()
        return _encrypt(replies[t],n,c)
    except (AssertionError,ValueError,ZeroDivisionError):
        return None


def test_source_recognizer_uses_math_roles_not_names():
    source=_fresh_source(bits=51,labels=("charge","stamp","direction"))
    profile=_source_profile(Document("unseen_oracle.py",source,None))
    if profile is None:
        import ast
        import cryptoscan.reciprocal_rabin_oracle as detector
        tree = ast.parse(source)
        encrypted = detector._reciprocal_encryption(tree)
        decrypted = detector._quadratic_decrypt(
            tree, encrypted[0] if encrypted else "unknown",
        )
        wire = detector._protocol_profile(
            tree, encrypted[0] if encrypted else "unknown",
            decrypted or "unknown",
        )
        raise AssertionError(
            f"source detector stages: encryption={encrypted!r}, "
            f"CRT={detector._crt_functions(tree)!r}, "
            f"decrypt={decrypted!r}, wire={wire!r}"
        )
    assert profile.factor_bits==51
    assert profile.ciphertext_labels == ("charge","stamp","direction")
    assert profile.input_prompt == "please give three integers: "


@pytest.mark.parametrize("bits,seed", [(31,18),(39,42),(48,73)])
def test_faulty_reencryption_recovers_both_factors_and_parameter(bits,seed):
    p,q,c=_gen_instance(bits,seed)
    observations=[]
    recovered=None
    for r in range(1,75):
        responses=[
            _simulate(r,s,t,p,q,c)
            for s in (-1,1) for t in (0,1)
        ]
        if any(item is None for item in responses):
            continue
        possible=frozenset(item[0] for item in responses)
        if len(possible)!=2:
            continue
        observations.append((r,possible))
        recovered=_records_to_factors(observations,bits-2)
        if recovered and _recover_constant(observations,recovered) is not None:
            break
    assert recovered is not None
    assert set(recovered)=={p,q}
    assert _recover_constant(observations,recovered)==c


def test_quad_reencrypt_inverse_recovers_arbitrary_secret():
    p,q,c=_gen_instance(48,777)
    n=p*q
    secret=int.from_bytes(b"LAB{ok}","big")
    assert secret<n
    ciphertext=_encrypt(secret,n,c)
    assert _decrypt_candidates(ciphertext,p,q,c)==[secret]


class SimulatedService:
    def __init__(self, profile,p,q,c,secret):
        self.profile=profile
        self.p,self.q,self.c=p,q,c
        self.calls=[]
        marker=profile.input_prompt.encode()
        self.buffer=bytearray(
            profile.ciphertext_header.encode()+b"\n"
            +self._format(_encrypt(secret,p*q,c))+marker
        )
        self.timeout=None

    def _format(self,triple):
        return b"".join(
            (name+" = "+str(value)+"\n").encode()
            for name,value in zip(self.profile.ciphertext_labels,triple)
        )

    def __enter__(self):
        return self

    def __exit__(self,*args):
        return False

    def settimeout(self,seconds):
        self.timeout=seconds

    def sendall(self,payload):
        query=tuple(map(int,payload.strip().split(b",")))
        self.calls.append(query)
        result=_simulate(*query,self.p,self.q,self.c)
        if result is None:
            text=self.profile.failure_marker.encode()+b"\n"
        else:
            text=self.profile.result_header.encode()+b"\n"+self._format(result)
        self.buffer.extend(text+self.profile.input_prompt.encode())

    def recv(self,count):
        if not self.buffer:
            raise socket.timeout()
        data=self.buffer[:count]
        del self.buffer[:count]
        return bytes(data)


def test_end_to_end_mock_tcp_with_new_oracle_names(monkeypatch):
    import cryptoscan.reciprocal_rabin_oracle as module
    source=_fresh_source()
    doc=Document("not_a_known_ctf.py",source,None)
    profile=extract_instance([doc])
    p,q,c=_gen_instance(48,789)
    secret=int.from_bytes(b"LAB{ok}","big")
    service=SimulatedService(profile,p,q,c,secret)
    monkeypatch.setattr(
        module.socket,"create_connection",lambda *args,**kw:service,
    )
    result=recover_details(
        [doc],"unreachable.invalid",5555,timeout=10,max_queries=320,
    )
    assert result.secret=="LAB{ok}"
    assert result.modulus==p*q
    assert set(result.factors)=={p,q}
    assert result.reciprocal_constant==c
    assert len(service.calls)==result.probes


def test_cli_scanner_and_plan_include_new_family(tmp_path,capsys):
    from cryptoscan.cli import main
    path=tmp_path/"unrecognized.py"
    path.write_text(_fresh_source(),encoding="utf-8")
    assert main([str(path),"--plan-attacks","--format","json",
                 "--host","example.invalid","--port","5555"])==0
    report=json.loads(capsys.readouterr().out)
    assert any(
        row["family"]=="Faulty reciprocal-Rabin CRT re-encryption oracle"
        and row["status"]=="applicable"
        for row in report["attack_plan"]
    )
    assert any(
        finding["rule"]=="RABIN-RECIPROCAL-CRT-ORACLE-FAULT"
        for finding in report["findings"]
    )


def test_rejects_oracle_without_nested_decrypt_then_encrypt():
    source=_fresh_source().replace(
        "stamp(recover(item,pub,secret),pub)",
        "stamp(123,pub)",
    )
    assert extract_instance([Document("no_decryption.py",source,None)]) is None


def test_jacobi_import_alias_and_reordered_additive_terms():
    source = _fresh_source(bits=47, labels=("rho", "chi", "selection"))
    source = source.replace(
        "from sympy import jacobi_symbol as jacobi",
        "from sympy import jacobi_symbol as arithmetic_character",
    ).replace("jacobi(", "arithmetic_character(")
    source = source.replace(
        "(message + public.multiplier * pow(message,-1,public.mod))",
        "(pow(message,-1,public.mod) * public.multiplier + message)",
    )
    profile = extract_instance([
        Document("different_group_formula.py", source, None)
    ])
    assert profile is not None
    assert profile.factor_bits == 47
    assert profile.ciphertext_labels == ("rho", "chi", "selection")


def test_named_jacobi_stub_is_not_a_cryptographic_certificate():
    source = _fresh_source()
    source = source.replace(
        "from sympy import jacobi_symbol as jacobi",
        "def jacobi(message, modulus):\n    return 1",
    )
    assert extract_instance([
        Document("wrong_quadratic_character.py", source, None)
    ]) is None


def test_unrelated_modular_inverse_and_root_pair_are_not_a_quadratic_solver():
    source = _fresh_source()
    start = source.index("def inverted_quadratic(")
    end = source.index("def chinese(", start)
    impostor = """
def inverted_quadratic(a,b,modulus):
    data = [a, b]
    reciprocal = pow(data[1], -1, modulus)
    exponent = (modulus-1)//2
    candidate = a + b*reciprocal
    alternate = (a-candidate) % modulus
    return candidate, alternate

"""
    # A superficial inverse+tuple-return detector falsely recognized this.
    source = source[:start] + impostor + source[end:]
    assert extract_instance([
        Document("not_a_quotient_root_solver.py", source, None)
    ]) is None


def test_crt_requires_both_residues_not_only_modulus_product():
    source = _fresh_source()
    source = source.replace(
        "return (x + p * ((y-x) * pow(p, -1, q) % q)) % (p*q)",
        "return x % (p*q)",
    )
    assert extract_instance([
        Document("fake_recombination.py", source, None)
    ]) is None


def test_distinct_error_message_is_control_flow_not_keyword_signature():
    source = _fresh_source().replace(
        'print("invalid parameters")',
        'print("mismatch: 0x4e! test different languages")',
    )
    profile = extract_instance([Document("new_errors.py", source, None)])
    assert profile is not None
    assert profile.failure_marker == "mismatch: 0x4e! test different languages"


def test_different_root_algorithm_gets_crt_hypothesis_not_false_verification():
    from cryptoscan.crypto_hypotheses import inspect_hypotheses

    source = _fresh_source()
    start = source.index("def inverted_quadratic(")
    end = source.index("def chinese(", start)
    alternate = """
def inverted_quadratic(r,c,p):
    # Legitimate alternative root algorithm; unlike the flawed quotient
    # exponentiation, it does not automatically imply the same fault.
    from sympy import sqrt_mod
    roots = sqrt_mod((r*r-4*c) % p, p, all_roots=True)
    return tuple((r+root)*pow(2,-1,p)%p for root in roots)

"""
    source = source[:start] + alternate + source[end:]
    doc = Document("other_quadratic_algorithm.py", source, None)
    assert extract_instance([doc]) is None
    matches = [
        item.family for item in inspect_hypotheses([doc])
    ]
    assert "CRT component-consistency and chosen-ciphertext oracle" in matches


def test_quadratic_solver_must_use_both_polynomial_coefficients():
    source = _fresh_source()
    source = source.replace(
        "head = (left[0]*right[0] - left[1]*right[1]*b) % modulus",
        "head = left[0]*right[0] % modulus",
    )
    source = source.replace(
        "+ left[1]*right[1]*a) % modulus",
        ") % modulus",
    )
    assert extract_instance([
        Document("not_a_quadratic_quotient.py", source, None)
    ]) is None


def test_explicit_root_validation_disables_faulty_crt_attack():
    source = _fresh_source()
    source = source.replace(
        "    alternate = (a-tmp) % modulus",
        "    assert (tmp*tmp-a*tmp+b) % modulus == 0\n"
        "    alternate = (a-tmp) % modulus",
    )
    assert extract_instance([
        Document("verified_quadratic_root.py", source, None)
    ]) is None


def test_root_rejection_branch_is_not_an_unchecked_fault_oracle():
    source = _fresh_source().replace(
        "    alternate = (a-tmp) % modulus",
        "    if (tmp*tmp-a*tmp+b) % modulus != 0:\n"
        "        raise ValueError('invalid quadratic root')\n"
        "    alternate = (a-tmp) % modulus",
    )
    assert extract_instance([
        Document("root_rejected_before_crt.py", source, None)
    ]) is None
