"""Independent verifier: reduced evidence only, no attacker hidden notes."""

from __future__ import annotations


class IndependentVerifier:
    name = "independent_verifier"

    def input_for(self, claim: str, invariant: str, artifact: str | None) -> dict[str, str | None]:
        return {
            "claim": claim,
            "invariant": invariant,
            "candidate": artifact,
            "attacker_hidden_reasoning": None,
        }
