from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ModelResponse:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    continuation: Any = None


class LLMProvider(ABC):
    @abstractmethod
    async def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], continuation: Any = None) -> ModelResponse: ...
