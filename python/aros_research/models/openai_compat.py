"""Generic OpenAI-compatible local provider. Secrets stay outside sandboxes."""

from __future__ import annotations

from pydantic import BaseModel, SecretStr


class OpenAICompatConfig(BaseModel):
    base_url: str
    model: str
    api_key: SecretStr | None = None
    timeout_s: float = 60.0
    max_context: int = 8192


class OpenAICompatProvider:
    def __init__(self, config: OpenAICompatConfig) -> None:
        self.config = config

    def redacted(self) -> dict[str, str | int | float]:
        return {
            "base_url": self.config.base_url,
            "model": self.config.model,
            "api_key": "***" if self.config.api_key is not None else "",
            "timeout_s": self.config.timeout_s,
            "max_context": self.config.max_context,
        }
