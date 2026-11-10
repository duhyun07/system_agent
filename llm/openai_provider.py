from __future__ import annotations

import json
import os
from typing import Any
from llm.base import LLMProvider, ModelResponse, ToolCall


def response_request_kwargs(model: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]], continuation: Any = None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"model": model, "max_output_tokens": 4096}
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"
    if continuation:
        kwargs["previous_response_id"] = continuation["response_id"]
        kwargs["input"] = continuation["tool_outputs"]
    else:
        kwargs["input"] = messages
    return kwargs


class OpenAIProvider(LLMProvider):
    def __init__(self, model: str, *, timeout: float = 30, retries: int = 2, client=None):
        if not model:
            raise ValueError("Set llm.openai_model in the mode configuration")
        self.model, self.timeout, self.retries = model, timeout, retries
        self._client = client

    def _get_client(self):
        if self._client is None:
            if not os.environ.get("OPENAI_API_KEY"):
                raise RuntimeError("OPENAI_API_KEY is not set")
            from openai import AsyncOpenAI
            self._client = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"], timeout=self.timeout, max_retries=self.retries)
        return self._client

    def request_kwargs(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], continuation: Any = None) -> dict[str, Any]:
        return response_request_kwargs(self.model, messages, tools, continuation)

    async def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], continuation: Any = None) -> ModelResponse:
        kwargs = self.request_kwargs(messages, tools, continuation)
        response = await self._get_client().responses.create(**kwargs)
        calls = []
        for item in response.output:
            if getattr(item, "type", None) == "function_call":
                try:
                    arguments = json.loads(item.arguments)
                except (ValueError, TypeError):
                    arguments = None
                calls.append(ToolCall(item.call_id, item.name, arguments))
        usage = getattr(response, "usage", None)
        return ModelResponse(text=getattr(response, "output_text", ""), tool_calls=calls, input_tokens=getattr(usage, "input_tokens", 0), output_tokens=getattr(usage, "output_tokens", 0), continuation={"response_id": response.id})
