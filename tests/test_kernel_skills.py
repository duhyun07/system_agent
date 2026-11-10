import subprocess
import tempfile
import unittest
from pathlib import Path

from core.policy import Policy
from security.audit import SkillAuditLogger
from security.permissions import ApprovalStore, SkillPermissionManager
from skills.base import SkillContext
from skills.executor import SkillExecutor
from skills.registry import default_registry


def make_kernel_tree(root: Path) -> Path:
    tree = root / "linux"
    (tree / "net" / "tls").mkdir(parents=True)
    (tree / "include" / "linux").mkdir(parents=True)
    (tree / "Makefile").write_text("VERSION = 6\nPATCHLEVEL = 12\nSUBLEVEL = 114\nEXTRAVERSION =\n")
    (tree / "Kconfig").write_text("\n")
    (tree / ".config").write_text("CONFIG_USER_NS=y\nCONFIG_KASAN=y\n# CONFIG_IO_URING is not set\n")
    (tree / "net" / "tls" / "tls_sw.c").write_text(
        "int tls_push_record(struct sock *sk)\n{\n\tkfree(ctx->buf);\n\treturn tls_do_push(sk);\n}\n\n"
        "void caller(void)\n{\n\ttls_push_record(sk);\n}\n"
    )
    return tree


class KernelSkillTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.tree = make_kernel_tree(self.root)
        self.policy = Policy((self.root, self.tree), mode="offline")
        self.approvals = ApprovalStore()
        self.audit = SkillAuditLogger(self.root / "audit.jsonl")
        self.ctx = SkillContext(self.policy, SkillPermissionManager(self.policy, self.approvals), self.audit)
        self.ex = SkillExecutor(default_registry(), self.ctx)

    def tearDown(self):
        self.temp.cleanup()

    async def test_source_search_scoped_to_subsystem(self):
        r = await self.ex.execute("kernel_source_search", {"kernel": str(self.tree), "subsystem": "net/tls", "pattern": "kfree"})
        self.assertTrue(r.ok, r.error)
        self.assertTrue(any("tls_sw.c" in m["path"] for m in r.output["matches"]))

    async def test_function_lookup_finds_definition_not_call(self):
        r = await self.ex.execute("kernel_function_lookup", {"kernel": str(self.tree), "function": "tls_push_record"})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(r.output["definitions"]), 1)
        self.assertEqual(r.output["definitions"][0]["line"], 1)

    async def test_callgraph_callers_and_callees(self):
        r = await self.ex.execute("kernel_callgraph_lookup", {"kernel": str(self.tree), "function": "tls_push_record"})
        self.assertTrue(r.ok, r.error)
        # Callers are invocation sites (not the definition line at line 1).
        self.assertTrue(any("tls_push_record(sk)" in c["excerpt"] and c["line"] != 1 for c in r.output["callers"]))
        self.assertIn("kfree", r.output["callees"])
        self.assertIn("tls_do_push", r.output["callees"])

    async def test_config_lookup_states(self):
        r = await self.ex.execute("kernel_config_lookup", {"kernel": str(self.tree), "options": ["CONFIG_USER_NS", "CONFIG_IO_URING", "CONFIG_MISSING"]})
        self.assertTrue(r.ok, r.error)
        states = {x["option"]: x["state"] for x in r.output["results"]}
        self.assertEqual(states["CONFIG_USER_NS"], "y")
        self.assertEqual(states["CONFIG_IO_URING"], "n")
        self.assertEqual(states["CONFIG_MISSING"], "unset")

    async def test_build_info_reads_version_and_config_hash(self):
        r = await self.ex.execute("kernel_build_info", {"kernel": str(self.tree)})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.output["version"], "6.12.114")
        self.assertTrue(r.output["config_sha256"])

    async def test_commit_diff_over_real_git_repo(self):
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e", "HOME": str(self.tree), "GIT_CONFIG_NOSYSTEM": "1"}
        run = lambda *a: subprocess.run(["git", "-C", str(self.tree), *a], check=True, capture_output=True, env={**env})
        run("init", "-q")
        run("add", "-A")
        run("commit", "-q", "-m", "initial")
        (self.tree / "net" / "tls" / "tls_sw.c").write_text("int tls_push_record(struct sock *sk)\n{\n\treturn 0;\n}\n")
        run("add", "-A")
        run("commit", "-q", "-m", "fix: simplify")
        r = await self.ex.execute("kernel_commit_diff", {"kernel": str(self.tree), "operation": "log", "count": 5})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(len(r.output["commits"]), 2)
        d = await self.ex.execute("kernel_commit_diff", {"kernel": str(self.tree), "operation": "diff", "base": "HEAD~1", "target": "HEAD"})
        self.assertTrue(d.ok, d.error)
        self.assertIn("tls_push_record", d.output["output"])

    async def test_vm_status_runs(self):
        r = await self.ex.execute("kernel_vm_status", {})
        self.assertTrue(r.ok, r.error)
        self.assertIn("qemu", r.output)
        self.assertIn("kvm", r.output)

    async def test_log_parse_and_dedup(self):
        log = "BUG: KASAN: use-after-free in foo+0x1/0x2\nRead of size 8 at addr ffff by task x/1\nCall Trace:\n foo+0x1/0x2\n bar+0x3/0x4\n"
        r = await self.ex.execute("kernel_log_parse", {"log": log})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.output["bug_class"], "kasan-use-after-free")
        dd = await self.ex.execute("kernel_crash_deduplicate", {"logs": [log, log, log.replace("0x1/0x2", "0x9/0xf")]})
        self.assertTrue(dd.ok, dd.error)
        self.assertEqual(dd.output["unique"], 1)  # same frames -> one group
        self.assertEqual(dd.output["total"], 3)

    async def test_test_run_is_cli_only_and_isolation_gated(self):
        # Not offered to the model.
        llm_ctx = SkillContext(self.policy, SkillPermissionManager(self.policy, self.approvals), self.audit, origin="llm")
        llm_ex = SkillExecutor(default_registry(), llm_ctx)
        self.assertNotIn("kernel_test_run", {d["name"] for d in llm_ex.definitions()})
        # Via CLI: requires approval; once approved, refuses without isolation confirmation.
        args = {"harness": "run.sh", "isolation_confirmed": False}
        denied = await self.ex.execute("kernel_test_run", args)
        self.assertFalse(denied.ok)
        self.assertIn("ApprovalRequired", denied.error)
        skill = self.ex.registry.get("kernel_test_run")
        self.approvals.grant("kernel_test_run", skill.approval_payload(args, self.ctx))
        res = await self.ex.execute("kernel_test_run", args)
        self.assertTrue(res.ok, res.error)
        self.assertFalse(res.output["executed"])
        self.assertIn("isolation", res.output["note"].lower())

    async def test_source_root_default_tree(self):
        # When no explicit kernel is given, the task source root is used.
        ctx = SkillContext(self.policy, SkillPermissionManager(self.policy, self.approvals), self.audit, source_root=self.tree)
        ex = SkillExecutor(default_registry(), ctx)
        r = await ex.execute("kernel_build_info", {})
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.output["version"], "6.12.114")


if __name__ == "__main__":
    unittest.main()
