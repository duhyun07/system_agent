from __future__ import annotations

import asyncio
import fcntl
import json
import os
import tempfile
from typing import Any, Callable
from urllib.parse import urlsplit
from llm.base import LLMProvider, ModelResponse, ToolCall


_LOCAL_LLM_LOCK = asyncio.Lock()


class OllamaProvider(LLMProvider):
    def __init__(self, model: str, url: str = "http://127.0.0.1:11434", timeout: float = 60, max_response_chars: int = 4_000_000, num_ctx: int | None = None, num_gpu: int | None = None):
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1") or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment or not parsed.port:
            raise ValueError("Ollama URL must be loopback")
        if num_ctx is not None and num_ctx < 1:
            raise ValueError("Ollama num_ctx must be positive")
        if num_gpu is not None and num_gpu < 0:
            raise ValueError("Ollama num_gpu must be >= 0")
        self.model, self.url, self.timeout, self.max_response_chars, self.num_ctx, self.num_gpu = model, url.rstrip("/"), timeout, max_response_chars, num_ctx, num_gpu

    async def _stream_response(self, client, payload: dict, on_thinking: Callable[[str], None]) -> dict:
        combined = {"role": "assistant", "content": "", "thinking": "", "tool_calls": []}
        final = None
        async with client.stream("POST", self.url + "/api/chat", json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line:
                    continue
                chunk = json.loads(line)
                if chunk.get("error"):
                    raise RuntimeError(f"Ollama stream error: {chunk['error']}")
                message = chunk.get("message") or {}
                thinking = message.get("thinking") or ""
                content = message.get("content") or ""
                if thinking:
                    on_thinking(thinking)
                    combined["thinking"] += thinking
                if content:
                    combined["content"] += content
                if message.get("tool_calls"):
                    combined["tool_calls"].extend(message["tool_calls"])
                if len(combined["thinking"]) + len(combined["content"]) > self.max_response_chars:
                    raise RuntimeError("Ollama streamed response exceeds configured context character limit")
                if chunk.get("done"):
                    final = chunk
        if final is None:
            raise RuntimeError("Ollama stream ended without a completion marker")
        return {**final, "message": combined}

    async def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], continuation: Any = None, *, on_thinking: Callable[[str], None] | None = None) -> ModelResponse:
        import httpx
        definitions = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}} for t in tools]
        payload = {"model": self.model, "messages": messages, "tools": definitions, "stream": on_thinking is not None}
        options: dict[str, Any] = {}
        if self.num_ctx is not None:
            options["num_ctx"] = self.num_ctx
        if self.num_gpu is not None:
            # Number of model layers to offload to the GPU. A large value offloads
            # every layer that fits in VRAM; Ollama clamps to what the GPU can hold.
            options["num_gpu"] = self.num_gpu
        if options:
            payload["options"] = options
        if on_thinking is not None:
            payload["think"] = True
        async with _LOCAL_LLM_LOCK:
            lock_path = os.path.join(tempfile.gettempdir(), f"system-agent-ollama-{os.getuid()}.lock")
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                if os.fstat(lock_fd).st_uid != os.getuid():
                    raise PermissionError("Ollama lock is owned by another user")
                while True:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        await asyncio.sleep(0.05)
                async with httpx.AsyncClient(trust_env=False, timeout=self.timeout) as client:
                    try:
                        if on_thinking is not None:
                            data = await self._stream_response(client, payload, on_thinking)
                        else:
                            response = await client.post(self.url + "/api/chat", json=payload)
                            response.raise_for_status()
                            data = response.json()
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            raise RuntimeError(f"Ollama model {self.model!r} is unavailable; run 'ollama pull {self.model}'") from exc
                        raise RuntimeError(f"Ollama returned HTTP {exc.response.status_code}") from exc
                    except httpx.RequestError as exc:
                        raise RuntimeError(f"Ollama at {self.url} is unreachable; start 'ollama serve' and check 'system-agent doctor'") from exc
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        message = data.get("message", {})
        calls = []
        for index, call in enumerate(message.get("tool_calls", [])):
            function = call.get("function", {})
            raw = function.get("arguments", {})
            try:
                arguments = json.loads(raw) if isinstance(raw, str) else raw
            except json.JSONDecodeError:
                arguments = None
            calls.append(ToolCall(str(index), function.get("name", ""), arguments))
        return ModelResponse(text=message.get("content", ""), tool_calls=calls, input_tokens=data.get("prompt_eval_count", 0), output_tokens=data.get("eval_count", 0), continuation=message)
