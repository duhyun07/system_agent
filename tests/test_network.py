import asyncio
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from core.policy import Policy
from security.audit import SkillAuditLogger
from security.network_policy import NetworkPolicy
from security.permissions import ApprovalStore, SkillPermissionManager
from skills.base import SkillContext
from skills.executor import SkillExecutor
from skills.registry import default_registry
from skills.network.web_search import WebSearch, SearchProvider, DuckDuckGoSearchProvider, _parse_ddg_html


class FakeResponse:
    def __init__(self, status=200, body=b"hello", headers=None):
        self.status_code = status
        self.body = body
        self.headers = headers or {"content-type": "text/plain"}

    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    async def aiter_bytes(self): yield self.body


class FakeClient:
    responses = []
    calls = []
    def __init__(self, **kwargs): self.kwargs = kwargs
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    def build_request(self, method, url, **kwargs): return types.SimpleNamespace(url=url, headers=kwargs["headers"], extensions=kwargs["extensions"])
    def stream(self, method, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.policy = Policy((self.root,), mode="online", allowed_domains=("example.org",))
        self.approvals = ApprovalStore()
        self.context = SkillContext(self.policy, SkillPermissionManager(self.policy, self.approvals), SkillAuditLogger(self.root / "audit"))
        self.executor = SkillExecutor(default_registry(), self.context)
        FakeClient.calls = []

    def tearDown(self): self.temp.cleanup()

    async def test_offline_allows_network_when_allowlisted(self):
        self.policy.mode = "offline"  # allowed_domains set in setUp
        self.assertIn("fetch", [x["name"] for x in self.executor.definitions()])
        self.assertTrue(self.executor.context.permissions.available(self.executor.registry.get("web_search")))

    async def test_network_denied_without_allowlist(self):
        self.policy.mode = "offline"
        self.policy.allowed_domains = ()
        self.assertFalse((await self.executor.execute("fetch", {"url": "https://example.org/"})).ok)
        self.assertFalse((await self.executor.execute("web_search", {"query": "kernel"})).ok)
        self.assertNotIn("fetch", [x["name"] for x in self.executor.definitions()])

    async def test_private_dns_and_ip_literal_rejected(self):
        network = NetworkPolicy(self.policy, resolver=lambda host, port: asyncio.sleep(0, result=["127.0.0.1"]))
        with self.assertRaises(Exception): await network.resolve_public("example.org", 443)
        with self.assertRaises(Exception): network.validate_url("http://127.0.0.1/")

    async def test_allowlisted_fetch_pins_public_ip(self):
        FakeClient.responses = [FakeResponse()]
        async def public(self, host, port): return "93.184.215.14"
        with patch.dict(sys.modules, {"httpx": types.SimpleNamespace(AsyncClient=FakeClient)}), patch.object(NetworkPolicy, "resolve_public", public):
            result = await self.executor.execute("fetch", {"url": "https://example.org/docs"})
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.output["content"], "hello")
        self.assertEqual(FakeClient.calls[0][0], "https://93.184.215.14/docs")
        self.assertEqual(FakeClient.calls[0][1]["extensions"]["sni_hostname"], "example.org")

    async def test_redirect_ssrf_denied(self):
        FakeClient.responses = [FakeResponse(302, headers={"location": "http://127.0.0.1/admin"})]
        async def public(self, host, port): return "93.184.215.14"
        with patch.dict(sys.modules, {"httpx": types.SimpleNamespace(AsyncClient=FakeClient)}), patch.object(NetworkPolicy, "resolve_public", public):
            result = await self.executor.execute("fetch", {"url": "https://example.org/docs"})
        self.assertFalse(result.ok)
        self.assertEqual(len(FakeClient.calls), 1)

    async def test_hybrid_payload_approval(self):
        self.policy.mode = "hybrid"
        args = {"url": "https://example.org/"}
        result = await self.executor.execute("fetch", args)
        self.assertFalse(result.ok)
        self.assertIn("ApprovalRequired", result.error)
        self.approvals.grant("fetch", self.executor.registry.get("fetch").approval_payload(args, self.context))
        FakeClient.responses = [FakeResponse()]
        async def public(self, host, port): return "93.184.215.14"
        with patch.dict(sys.modules, {"httpx": types.SimpleNamespace(AsyncClient=FakeClient)}), patch.object(NetworkPolicy, "resolve_public", public):
            self.assertTrue((await self.executor.execute("fetch", args)).ok)

    async def test_web_search_deduplicates_without_fetch(self):
        class FakeSearch(SearchProvider):
            name = "brave"
            async def search(self, query, max_results, context):
                item = {"title": "Doc", "url": "https://example.org/doc", "snippet": "untrusted"}
                return [item, item]
        self.executor.registry._skills["web_search"] = WebSearch(FakeSearch())
        result = await self.executor.execute("web_search", {"query": "kernel docs"})
        self.assertTrue(result.ok, result.error)
        self.assertEqual(len(result.output["results"]), 1)
        self.assertFalse(result.output["local_evidence"])

    def test_duckduckgo_parses_and_decodes_results(self):
        body = (
            '<a class="result__a" rel="nofollow" '
            'href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fgit.kernel.org%2Fpatch&rut=x">'
            'Kernel <b>patch</b></a>'
            '<a class="result__snippet" href="#">A fix for the <b>bug</b></a>'
            '<a class="result__a" href="https://lwn.net/Articles/1/">LWN</a>'
        )
        results = _parse_ddg_html(body, max_results=5)
        self.assertEqual(results[0]["url"], "https://git.kernel.org/patch")
        self.assertEqual(results[0]["title"], "Kernel patch")
        self.assertEqual(results[0]["snippet"], "A fix for the bug")
        self.assertEqual(results[0]["provider"], "duckduckgo")
        self.assertEqual(results[1]["url"], "https://lwn.net/Articles/1/")

    async def test_duckduckgo_default_provider_selected_by_policy(self):
        self.assertEqual(self.policy.search_provider, "duckduckgo")
        self.assertIsInstance(WebSearch()._select(self.context), DuckDuckGoSearchProvider)


if __name__ == "__main__": unittest.main()
