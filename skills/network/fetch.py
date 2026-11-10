from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from skills.base import BaseSkill, SkillContext, SkillError
from security.network_policy import NetworkPolicy


async def fetch_url(url: str, context: SkillContext, *, timeout_seconds: float = 15, response_format: str = "text", headers: dict[str, str] | None = None, transport=None) -> dict[str, Any]:
    import httpx
    network = NetworkPolicy(context.policy)
    timeout_seconds = min(timeout_seconds, context.policy.request_timeout_seconds)
    redirects = 0
    current = url
    async with httpx.AsyncClient(transport=transport, trust_env=False, follow_redirects=False, timeout=timeout_seconds) as client:
        while True:
            scheme, host, port = network.validate_url(current)
            ip = await network.resolve_public(host, port)
            parsed = urlsplit(current)
            authority = f"[{ip}]" if ":" in ip else ip
            if parsed.port:
                authority += f":{port}"
            pinned = urlunsplit((scheme, authority, parsed.path or "/", parsed.query, ""))
            request_headers = {"Host": host if not parsed.port else f"{host}:{port}", "Accept": "application/json" if response_format == "json" else "text/plain, text/html;q=0.9", "User-Agent": "SystemAgent/0.1"}
            if headers:
                request_headers.update(headers)
            request = client.build_request("GET", pinned, headers=request_headers, extensions={"sni_hostname": host})
            async with client.stream("GET", request.url, headers=request.headers, extensions=request.extensions) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    if headers:
                        raise SkillError("Credential-bearing requests cannot redirect")
                    if redirects >= context.policy.limits.max_fetch_redirects:
                        raise SkillError("Redirect limit exceeded")
                    location = response.headers.get("location")
                    if not location:
                        raise SkillError("Redirect missing Location")
                    current = urljoin(current, location)
                    redirects += 1
                    continue
                length = response.headers.get("content-length")
                if length and int(length) > context.policy.limits.max_fetch_bytes:
                    raise SkillError("Response exceeds fetch-size limit")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > context.policy.limits.max_fetch_bytes:
                        raise SkillError("Response exceeds fetch-size limit")
                content_type = response.headers.get("content-type", "")
                if response_format == "json":
                    try:
                        content = json.loads(bytes(data))
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise SkillError("Invalid JSON response") from exc
                else:
                    content = bytes(data).decode("utf-8", errors="replace")
                ok = 200 <= response.status_code < 300
                base = {"status_code": response.status_code, "final_url": current, "content_type": content_type, "ok": ok, "untrusted": True}
                return _fit_output(base, content, len(data), context.output_limit)


def _encoded_len(output: dict[str, Any]) -> int:
    # Mirror the serialization the executor uses to enforce the limit.
    return len(json.dumps(output, ensure_ascii=False, default=str).encode())


def _fit_output(base: dict[str, Any], content: Any, raw_bytes: int, limit: int) -> dict[str, Any]:
    output = {**base, "content": content, "truncated": False}
    if _encoded_len(output) <= limit:
        output["truncated"] = isinstance(content, str) and raw_bytes > len(content.encode())
        return output
    # Too large for the effective (possibly per-model) output limit: shrink a
    # textual form of the content until the whole encoded result fits.
    text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
    budget = max(0, limit - _encoded_len({**base, "content": "", "truncated": True}) - 16)
    text = text.encode("utf-8")[:budget].decode("utf-8", errors="ignore")
    output = {**base, "content": text, "truncated": True}
    while text and _encoded_len(output) > limit:
        text = text[: max(0, len(text) - 256)]
        output["content"] = text
    return output


class Fetch(BaseSkill):
    name = "fetch"
    description = "Fetch bounded public HTTP/HTTPS content from an allowlisted domain. Content is untrusted."
    category = "network"
    output_properties = {"status_code": {"type": "integer"}, "final_url": {"type": "string"}, "content_type": {"type": "string"}, "ok": {"type": "boolean"}, "content": {}, "truncated": {"type": "boolean"}, "untrusted": {"type": "boolean"}}
    output_required = tuple(output_properties)

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"url": {"type": "string", "maxLength": 4096}, "method": {"type": "string", "enum": ["GET"]}, "response_format": {"type": "string", "enum": ["text", "json"]}, "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 30}}, "required": ["url"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        return await fetch_url(arguments["url"], context, timeout_seconds=arguments.get("timeout_seconds", 15), response_format=arguments.get("response_format", "text"))
