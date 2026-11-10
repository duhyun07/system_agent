import tempfile
import unittest
from pathlib import Path

from core.orchestrator import SystemAgent
from core.policy import Policy
from core.known_issues import KnownIssuesStore, CrashIndex, novelty_verdict
from core.triage_flow import run_triage, parse_crash


KASAN = (
    "BUG: KASAN: use-after-free in tls_push_record+0x6b/0x90 [tls]\n"
    "Read of size 8 at addr ffff88810a3b4e00 by task poc/321\n"
    "Call Trace:\n kasan_report+0xb8/0xf0\n tls_push_record+0x6b/0x90 [tls]\n sock_sendmsg+0x8b/0xa0\n"
)
KASAN_OTHER = (
    "BUG: KASAN: out-of-bounds in nft_do_chain+0x10/0x20 [nf_tables]\n"
    "Write of size 4 at addr ffff by task poc/9\n"
    "Call Trace:\n nft_do_chain+0x10/0x20 [nf_tables]\n ip_rcv+0x5/0x9\n"
)


class NoveltyLogicTests(unittest.TestCase):
    def test_verdict_novel_when_nothing_matches(self):
        v = novelty_verdict(parse_crash(KASAN), known_hits=[], prior_crashes=[], patch_hits=[])
        self.assertTrue(v["novel"])
        self.assertFalse(v["known"])

    def test_verdict_known_on_any_signal(self):
        parsed = parse_crash(KASAN)
        self.assertTrue(novelty_verdict(parsed, known_hits=[{"match": "signature", "fix_commit": "abc"}], prior_crashes=[], patch_hits=[])["known"])
        self.assertTrue(novelty_verdict(parsed, known_hits=[], prior_crashes=[{"signature": parsed["signature"]}], patch_hits=[])["known"])
        self.assertTrue(novelty_verdict(parsed, known_hits=[], prior_crashes=[], patch_hits=[{"commit": "deadbeef", "subject": "fix uaf"}])["known"])


class StoresTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_known_issue_matches_by_signature_and_fault(self):
        store = KnownIssuesStore(self.root)
        parsed = parse_crash(KASAN)
        store.add({"signature": parsed["signature"], "fix_commit": "abc123"})
        self.assertEqual(store.match(parsed)[0]["match"], "signature")
        store2 = KnownIssuesStore(self.root)
        store2.add({"fault_site": "tls_push_record", "cve": "CVE-2026-0001"})
        matches = {m["match"] for m in store2.match(parsed)}
        self.assertIn("fault_site", matches)

    def test_crash_index_dedup(self):
        idx = CrashIndex(self.root)
        parsed = parse_crash(KASAN)
        self.assertEqual(idx.prior_matches(parsed), [])
        self.assertTrue(idx.record(parsed, "sha1"))
        self.assertEqual(len(idx.prior_matches(parsed)), 1)
        self.assertFalse(idx.record(parsed, "sha2"))  # signature already indexed


class RunTriageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.agent = SystemAgent(Policy((self.root,), mode="offline"))

    def tearDown(self):
        self.tmp.cleanup()

    async def test_novel_then_known_and_report_written(self):
        first = await run_triage(self.agent, KASAN, source=None)
        self.assertTrue(first["verdict"]["novel"])
        self.assertEqual(first["action"], "recorded_finding_and_drafted_report")
        self.assertTrue(Path(first["report"]).is_file())
        self.assertEqual(self.agent.findings.get(first["finding_id"])["status"], "hypothesis")

        second = await run_triage(self.agent, KASAN, source=None)
        self.assertTrue(second["verdict"]["known"])
        self.assertEqual(second["action"], "known_crash_keep_searching")
        # Only the novel crash produced a finding.
        self.assertEqual(len(self.agent.findings.list()), 1)

    async def test_distinct_crash_is_novel(self):
        await run_triage(self.agent, KASAN, source=None)
        other = await run_triage(self.agent, KASAN_OTHER, source=None)
        self.assertTrue(other["verdict"]["novel"])
        self.assertEqual(len(self.agent.findings.list()), 2)

    async def test_known_issue_registry_forces_known(self):
        parsed = parse_crash(KASAN)
        KnownIssuesStore(self.root).add({"signature": parsed["signature"], "fix_commit": "abc123", "note": "submitted"})
        result = await run_triage(self.agent, KASAN, source=None)
        self.assertTrue(result["verdict"]["known"])
        self.assertEqual(len(self.agent.findings.list()), 0)


if __name__ == "__main__":
    unittest.main()
