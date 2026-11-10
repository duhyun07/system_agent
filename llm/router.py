from __future__ import annotations

import json
from core.policy import Policy
from llm.ollama_provider import OllamaProvider
from llm.openai_provider import OpenAIProvider, response_request_kwargs
from security.disclosure_policy import DisclosurePolicy
from security.permissions import ApprovalStore


class LLMRouter:
    def __init__(self, policy: Policy, approvals: ApprovalStore, *, local=None, cloud=None):
        self.policy = policy
        self.approvals = approvals
        self.local = local or OllamaProvider(policy.ollama_model, policy.ollama_url, timeout=policy.limits.max_execution_seconds, max_response_chars=policy.limits.max_context_chars, num_ctx=policy.ollama_num_ctx, num_gpu=policy.ollama_num_gpu)
        self.cloud = cloud
        self.input_tokens = 0
        self.output_tokens = 0
        self.spent_usd = 0.0

    def active(self):
        if self.policy.mode in ("offline", "hybrid"):
            return self.local
        if self.cloud is None:
            self.cloud = OpenAIProvider(self.policy.openai_model, timeout=self.policy.request_timeout_seconds, retries=self.policy.retry_limit)
        return self.cloud

    def _check_cloud_budget(self, messages) -> None:
        if self.policy.limits.max_spend_usd <= 0:
            raise RuntimeError("Cloud spending budget is unset")
        if self.policy.openai_input_usd_per_million <= 0 or self.policy.openai_output_usd_per_million <= 0:
            raise RuntimeError("Configure positive model prices before cloud inference")
        estimated_input = max(1, len(json.dumps(messages, ensure_ascii=False)) // 3)
        if self.input_tokens + estimated_input > self.policy.limits.max_input_tokens:
            raise RuntimeError("Model input-token budget cannot cover this request")
        remaining_output = max(0, self.policy.limits.max_output_tokens - self.output_tokens)
        estimated_output = min(4096, remaining_output)
        if estimated_output <= 0:
            raise RuntimeError("Model output-token budget exhausted")
        upper = (estimated_input * self.policy.openai_input_usd_per_million + estimated_output * self.policy.openai_output_usd_per_million) / 1_000_000
        if self.spent_usd + upper > self.policy.limits.max_spend_usd:
            raise RuntimeError("Cloud spending budget cannot cover this request")

    def cloud_payload_bytes(self, task: str) -> bytes:
        if not self.policy.openai_model:
            raise RuntimeError("Configure the OpenAI model before previewing a cloud request")
        request = response_request_kwargs(self.policy.openai_model, [{"role": "user", "content": task}], [])
        return json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()

    async def complete(self, messages, tools, continuation=None, *, on_thinking=None):
        if self.policy.mode == "online":
            self._check_cloud_budget(continuation or messages)
        provider = self.active()
        if on_thinking is not None and isinstance(provider, OllamaProvider):
            result = await provider.complete(messages, tools, continuation, on_thinking=on_thinking)
        else:
            result = await provider.complete(messages, tools, continuation)
        self.input_tokens += result.input_tokens
        self.output_tokens += result.output_tokens
        if self.input_tokens > self.policy.limits.max_input_tokens or self.output_tokens > self.policy.limits.max_output_tokens:
            raise RuntimeError("Model token budget exceeded")
        if self.policy.mode == "online":
            self.spent_usd += (result.input_tokens * self.policy.openai_input_usd_per_million + result.output_tokens * self.policy.openai_output_usd_per_million) / 1_000_000
            if self.spent_usd > self.policy.limits.max_spend_usd:
                raise RuntimeError("Online spending budget exceeded")
        return result

    async def approved_cloud_task(self, task: str):
        if self.policy.mode != "hybrid":
            raise RuntimeError("Explicit cloud tasks are available only in Hybrid mode")
        payload = self.cloud_payload_bytes(task)
        self._check_cloud_budget([{"role": "user", "content": task}])
        DisclosurePolicy(self.approvals).require(payload)
        if self.cloud is None:
            self.cloud = OpenAIProvider(self.policy.openai_model, timeout=self.policy.request_timeout_seconds, retries=self.policy.retry_limit)
        result = await self.cloud.complete([{"role": "user", "content": task}], [])
        self.input_tokens += result.input_tokens
        self.output_tokens += result.output_tokens
        self.spent_usd += (result.input_tokens * self.policy.openai_input_usd_per_million + result.output_tokens * self.policy.openai_output_usd_per_million) / 1_000_000
        return result
