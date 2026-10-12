from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any


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

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["id"] = self.id
        return {"id": result.pop("id"), **result}
