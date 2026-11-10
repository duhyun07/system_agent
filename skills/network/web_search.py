from __future__ import annotations

import asyncio
import html as html_module
import os
import re
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode, urlsplit
from skills.base import BaseSkill, SkillContext, SkillError
from skills.network.fetch import fetch_url


class SearchProvider(ABC):
    name: str

    @abstractmethod
    async def search(self, query: str, max_results: int, context: SkillContext) -> list[dict[str, Any]]: ...


def _strip_tags(markup: str) -> str:
    return html_module.unescape(re.sub(r"<[^>]+>", "", markup)).strip()


def _decode_ddg_href(href: str) -> str | None:
    href = html_module.unescape(href)
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlsplit(href)
    if "uddg=" in (parsed.query or "") or parsed.path.endswith("/l/"):
        target = parse_qs(parsed.query).get("uddg", [None])[0]
        if target:
            return unquote(target)
    return href if href.startswith("http") else None


def _parse_ddg_html(body: str, max_results: int) -> list[dict[str, Any]]:
    """Parse DuckDuckGo's keyless HTML endpoint. Best-effort; markup is untrusted."""
    anchor_re = re.compile(r'<a\b[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S)
    snippet_re = re.compile(r'<a\b[^>]*class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>', re.S)
    snippets = snippet_re.findall(body)
    results: list[dict[str, Any]] = []
    for index, (href, title_markup) in enumerate(anchor_re.findall(body)):
        url = _decode_ddg_href(href)
        if not url:
            continue
        results.append({
            "title": _strip_tags(title_markup),
            "url": url,
            "snippet": _strip_tags(snippets[index]) if index < len(snippets) else "",
            "provider": "duckduckgo",
        })
        if len(results) >= max_results:
            break
    return results


class DuckDuckGoSearchProvider(SearchProvider):
    """Keyless web search via DuckDuckGo's HTML endpoint. No API key required."""
    name = "duckduckgo"
    endpoint = "https://html.duckduckgo.com/html/"

    async def search(self, query: str, max_results: int, context: SkillContext) -> list[dict[str, Any]]:
        url = self.endpoint + "?" + urlencode({"q": query, "kl": "wt-wt"})
        result = await fetch_url(
            url, context, timeout_seconds=10, response_format="text",
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"},
        )
        if result["status_code"] != 200:
            raise SkillError(f"Search provider returned HTTP {result['status_code']}")
        return _parse_ddg_html(result["content"], max_results)


class BraveSearchProvider(SearchProvider):
    name = "brave"

    async def search(self, query: str, max_results: int, context: SkillContext) -> list[dict[str, Any]]:
        key = os.environ.get("BRAVE_SEARCH_API_KEY")
        if not key:
            raise SkillError("BRAVE_SEARCH_API_KEY is not set")
        url = "https://api.search.brave.com/res/v1/web/search?" + urlencode({"q": query, "count": max_results})
        result = await fetch_url(url, context, timeout_seconds=10, response_format="json", headers={"X-Subscription-Token": key})
        if result["status_code"] != 200:
            raise SkillError(f"Search provider returned HTTP {result['status_code']}")
        items = result["content"].get("web", {}).get("results", [])
        return [{"title": item.get("title", ""), "url": item.get("url", ""), "snippet": item.get("description", ""), "provider": self.name} for item in items[:max_results]]


PROVIDERS: dict[str, type[SearchProvider]] = {
    DuckDuckGoSearchProvider.name: DuckDuckGoSearchProvider,
    BraveSearchProvider.name: BraveSearchProvider,
}


class WebSearch(BaseSkill):
    name = "web_search"
    description = "Search the public web (DuckDuckGo by default, no API key needed) for a query; results are untrusted candidates. Use fetch to read a result page."
    category = "network"
    output_properties = {"query": {"type": "string"}, "results": {"type": "array", "items": {"type": "object", "properties": {"title": {"type": "string"}, "url": {"type": "string"}, "snippet": {"type": "string"}, "provider": {"type": "string"}}, "required": ["title", "url", "snippet", "provider"]}}, "untrusted": {"type": "boolean"}, "local_evidence": {"type": "boolean"}}
    output_required = tuple(output_properties)
    _last_request = 0.0
    _lock = asyncio.Lock()

    def __init__(self, provider: SearchProvider | None = None):
        # An explicit provider (e.g. in tests) overrides policy-based selection.
        self._override = provider

    def _select(self, context: SkillContext) -> SearchProvider:
        if self._override is not None:
            return self._override
        factory = PROVIDERS.get(context.policy.search_provider)
        if factory is None:
            raise SkillError(f"Unknown search provider: {context.policy.search_provider}")
        return factory()

    def schema(self) -> dict[str, Any]:
        return {"type": "object", "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 600}, "max_results": {"type": "integer", "minimum": 1, "maximum": 10}}, "required": ["query"], "additionalProperties": False}

    async def execute(self, arguments: dict[str, Any], context: SkillContext) -> dict[str, Any]:
        provider = self._select(context)
        query = arguments["query"].strip()
        if not query or len(query.split()) > 75:
            raise SkillError("Query is empty or exceeds provider limits")
        async with self._lock:
            now = asyncio.get_running_loop().time()
            if now - self._last_request < 1:
                raise SkillError("Search rate limit exceeded")
            self._last_request = now
        max_results = arguments.get("max_results", 5)
        candidates = await provider.search(query, max_results, context)
        seen = set()
        results = []
        for candidate in candidates:
            url = candidate.get("url", "")
            if not url or url in seen:
                continue
            seen.add(url)
            results.append({"title": str(candidate.get("title", ""))[:300], "url": url, "snippet": str(candidate.get("snippet", ""))[:1000], "provider": provider.name})
        return {"query": query, "results": results[:max_results], "untrusted": True, "local_evidence": False}
