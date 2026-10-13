from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Any


FLAG_PATTERN = re.compile(rb"(?:flag|ctf|key)\{[^\r\n]{1,200}\}", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    rule: str
    title: str
    severity: str
    confidence: str
    location: str
    evidence: dict[str, Any]
    preconditions: list[str]
    attack: str
    solver: dict[str, Any]
    patch: str

    @property
    def id(self) -> str:
        body = json.dumps(
            {"rule": self.rule, "location": self.location, "evidence": self.evidence},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(body.encode()).hexdigest()[:12]

    def _verified_solver(self) -> bool:
        """Accept only rule-specific, reproducible proof as an actionable result."""
        try:
            if self.rule == "RSA-SHARED-PRIME":
                factor = int(self.evidence["gcd"])
                return factor * int(self.evidence["q1"]) == int(self.evidence["n1"]) and factor * int(self.evidence["q2"]) == int(self.evidence["n2"])
            if self.rule == "RSA-PARAMETER-LEAK":
                return self.evidence.get("factorization_verified") is True and (
                    "result_hex" not in self.solver or self.evidence.get("reencryption_verified") is True
                )
            if self.rule == "RSA-PRIVATE-EXPONENT-LEAK":
                return self.evidence.get("reencryption_verified") is True
            if self.rule == "RSA-E3-EXACT-ROOT":
                return int(self.evidence["m"]) ** 3 == int(self.evidence["c"])
            if self.rule in {"RSA-WIENER-SMALL-D", "RSA-FERMAT-CLOSE-PRIMES"}:
                factors_match = int(self.evidence["p"]) * int(self.evidence["q"]) == int(self.evidence["n"])
                return factors_match and ("result_hex" not in self.solver or self.evidence.get("reencryption_verified") is True)
            if self.rule == "RSA-COMMON-MODULUS":
                return self.evidence.get("reencryption_verified") is True
            if self.rule == "RSA-HASTAD-BROADCAST":
                return int(self.evidence["m"]) ** 3 == int(self.evidence["crt_value"])
            if self.rule == "SIGNATURE-NONCE-REUSE":
                q, r = int(self.evidence["q"]), int(self.evidence["r"])
                nonce, private = int(self.evidence["nonce_k"]), int(self.evidence["private_key_x"])
                return all(
                    (int(self.evidence[s]) * nonce - int(self.evidence[z]) - r * private) % q == 0
                    for s, z in (("s1", "z1"), ("s2", "z2"))
                )
            if self.rule == "LCG-STATE-RECOVERY":
                return self.evidence.get("recurrence_verified") is True
            if self.rule == "DH-DEGENERATE-GENERATOR":
                return int(self.evidence["g"]) % int(self.evidence["p"]) in (0, 1, int(self.evidence["p"]) - 1)
            if self.rule == "DH-SMALL-GROUP":
                return self.evidence.get("discrete_log_verified") is True
            if self.rule == "CBC-FIRST-BLOCK-BITFLIP":
                iv = bytes.fromhex(self.evidence["iv_hex"])
                known = bytes.fromhex(self.evidence["known_block_hex"])
                target = bytes.fromhex(self.evidence["target_block_hex"])
                expected = bytes(left ^ old ^ new for left, old, new in zip(iv, known, target))
                return expected.hex() == self.solver.get("modified_iv_hex")
            if self.rule in {"XOR-SINGLE-BYTE", "XOR-REPEATING-KEY"}:
                return self.evidence.get("flag_shape") is True and self.evidence.get("roundtrip_verified") is True
        except (KeyError, TypeError, ValueError):
            return False
        return False

    @property
    def recovery_status(self) -> str:
        if not self._verified_solver():
            return "validation-only"
        result_hex = self.solver.get("result_hex")
        if isinstance(result_hex, str):
            try:
                if FLAG_PATTERN.search(bytes.fromhex(result_hex)):
                    return "flag-recovered"
            except ValueError:
                pass
        return "payload-ready"

    @property
    def flag_path(self) -> str:
        if self.recovery_status == "flag-recovered":
            return "Read the recovered flag-shaped plaintext from solver.result_hex."
        if self.recovery_status == "payload-ready":
            return "Use the verified values in solver with the stated attack and preconditions to reach the flag path."
        return "Validate the preconditions against the challenge before treating this as a flag-recovery vector."

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["id"] = self.id
        result["recovery_status"] = self.recovery_status
        result["flag_path"] = self.flag_path
        return {"id": result.pop("id"), **result}
