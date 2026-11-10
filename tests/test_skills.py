import asyncio
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from core.policy import Limits, Policy
from security.audit import SkillAuditLogger
from security.permissions import ApprovalStore, SkillPermissionManager
from skills.base import SkillContext
from skills.executor import SkillExecutor
from skills.registry import default_registry


class SkillTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.policy = Policy((self.root,), limits=Limits(max_read_bytes=1000, max_write_bytes=1000, max_output_bytes=4096, max_scan_bytes=1000))
        self.approvals = ApprovalStore()
        self.audit = SkillAuditLogger(self.root / "audit.jsonl")
        self.context = SkillContext(self.policy, SkillPermissionManager(self.policy, self.approvals), self.audit)
        self.executor = SkillExecutor(default_registry(), self.context)

    def tearDown(self):
        self.temp.cleanup()

    async def call(self, name, **args):
        return await self.executor.execute(name, args)

    async def test_discovery_and_validation(self):
        names = {d["name"] for d in self.executor.definitions()}
        # 8 filesystem + 11 kernel skills; network excluded without an allowlist.
        self.assertEqual(len(self.executor.definitions()), 19)
        self.assertIn("kernel_source_search", names)
        self.assertNotIn("fetch", names)
        self.assertFalse((await self.call("read_file", path="x", extra=True)).ok)
        self.assertFalse((await self.call("unknown", path="x")).ok)

    async def test_cli_only_skill_hidden_from_model(self):
        from skills.base import SkillContext
        from skills.executor import SkillExecutor
        from security.permissions import SkillPermissionManager
        llm_ctx = SkillContext(self.policy, SkillPermissionManager(self.policy, self.approvals), self.audit, origin="llm", source_root=self.root)
        llm_exec = SkillExecutor(default_registry(), llm_ctx)
        names = {d["name"] for d in llm_exec.definitions()}
        self.assertNotIn("kernel_test_run", names)
        denied = await llm_exec.execute("kernel_test_run", {"harness": "x"})
        self.assertFalse(denied.ok)
        self.assertIn("CLI-only", denied.error)

    async def test_read_and_boundaries(self):
        (self.root / "note.txt").write_text("one\ntwo\nthree\n")
        result = await self.call("read_file", path="note.txt", start_line=2, end_line=2)
        self.assertTrue(result.ok)
        self.assertEqual(result.output["content"], "two\n")
        for path in ("../secret", "/etc/passwd", ".env", ".git/config"):
            self.assertFalse((await self.call("read_file", path=path)).ok, path)
        outside = self.root.parent / "outside.txt"
        outside.write_text("secret")
        (self.root / "link").symlink_to(outside)
        self.assertFalse((await self.call("read_file", path="link")).ok)
        (self.root / "linked_dir").symlink_to(self.root.parent, target_is_directory=True)
        self.assertFalse((await self.call("read_file", path="linked_dir/outside.txt")).ok)
        outside.unlink()

    async def test_atomic_write_edit_and_approval(self):
        created = await self.call("write_file", path="note.txt", content="old")
        self.assertTrue(created.ok)
        self.assertEqual((self.root / "note.txt").read_text(), "old")
        self.assertFalse((await self.call("write_file", path="note.txt", content="new")).ok)
        arguments = {"path": "note.txt", "old_text": "old", "new_text": "new", "expected_sha256": hashlib.sha256(b"old").hexdigest()}
        denied = await self.executor.execute("edit_file", arguments)
        self.assertFalse(denied.ok)
        self.assertIn("ApprovalRequired", denied.error)
        payload = self.executor.registry.get("edit_file").approval_payload(arguments, self.context)
        self.approvals.grant("edit_file", payload)
        edited = await self.executor.execute("edit_file", arguments)
        self.assertTrue(edited.ok, edited.error)
        self.assertEqual((self.root / "note.txt").read_text(), "new")
        self.assertIn("@@", edited.output["diff"])
        self.assertFalse((await self.executor.execute("edit_file", arguments)).ok)

    async def test_ambiguous_edit_hash_and_limits(self):
        (self.root / "note.txt").write_text("x x")
        arguments = {"path": "note.txt", "old_text": "x", "new_text": "y"}
        skill = self.executor.registry.get("edit_file")
        self.approvals.grant("edit_file", skill.approval_payload(arguments, self.context))
        self.assertFalse((await self.executor.execute("edit_file", arguments)).ok)
        self.assertEqual((self.root / "note.txt").read_text(), "x x")
        (self.root / "large").write_bytes(b"a" * 1001)
        self.assertFalse((await self.call("read_file", path="large")).ok)
        self.assertFalse((await self.call("write_file", path="more", content="a" * 1001)).ok)

    async def test_directory_search_grep_and_audit(self):
        (self.root / "a.c").write_text("KASAN value\n")
        (self.root / "binary").write_bytes(b"KASAN\x00")
        (self.root / ".env").write_text("secret")
        listing = await self.call("list_dir", path=".", recursive=True)
        self.assertTrue(listing.ok)
        self.assertNotIn(".env", [e["name"] for e in listing.output["entries"]])
        found = await self.call("search_files", root=".", pattern="*.c")
        self.assertEqual(found.output["paths"], ["a.c"])
        grep = await self.call("grep", root=".", pattern="KASAN")
        self.assertEqual(len(grep.output["matches"]), 1)
        self.assertTrue(self.audit.path.exists())
        event = json.loads(self.audit.path.read_text().splitlines()[0])
        self.assertIn("arguments_sha256", event)
        self.assertNotIn("arguments", event)

    async def test_large_listing_is_bounded_and_search_scans_past_listing_limit(self):
        large = self.root / "large"
        large.mkdir()
        for index in range(80):
            (large / f"entry-{index:03d}-{'x' * 60}.h").write_text("")
        (large / "mm.h").write_text("target\n")
        self.policy.limits.max_entries = 10
        listing = await self.call("list_dir", path="large")
        self.assertTrue(listing.ok, listing.error)
        self.assertTrue(listing.output["truncated"])
        self.assertLessEqual(len(json.dumps(listing.output, ensure_ascii=False).encode()), self.policy.limits.max_output_bytes)
        found = await self.call("search_files", root="large", pattern="mm.h")
        self.assertTrue(found.ok, found.error)
        self.assertEqual(found.output["paths"], ["large/mm.h"])
        self.assertFalse(found.output["truncated"])

    async def test_search_scan_limit_reports_truncation(self):
        folder = self.root / "search"
        folder.mkdir()
        for index in range(8):
            (folder / f"a{index}.txt").write_text("")
        (folder / "mm.h").write_text("")
        self.policy.limits.max_walk_entries = 5
        found = await self.call("search_files", root="search", pattern="mm.h")
        self.assertTrue(found.ok, found.error)
        self.assertEqual(found.output["paths"], [])
        self.assertTrue(found.output["truncated"])

    async def test_search_does_not_follow_directory_symlinks(self):
        with tempfile.TemporaryDirectory() as external:
            Path(external, "secret.h").write_text("hidden\n")
            (self.root / "linked").symlink_to(external, target_is_directory=True)
            found = await self.call("search_files", root=".", pattern="secret.h")
            self.assertTrue(found.ok, found.error)
            self.assertEqual(found.output["paths"], [])

    async def test_patch_requires_approval_and_expected_version(self):
        (self.root / "a").write_text("first")
        before = hashlib.sha256(b"first").hexdigest()
        args = {"changes": [{"path": "a", "old_text": "first", "new_text": "second", "expected_sha256": before}]}
        self.assertFalse((await self.executor.execute("apply_patch", args)).ok)
        self.approvals.grant("apply_patch", self.executor.registry.get("apply_patch").approval_payload(args, self.context))
        result = await self.executor.execute("apply_patch", args)
        self.assertTrue(result.ok, result.error)
        self.assertEqual((self.root / "a").read_text(), "second")

    async def test_overwrite_approval_is_bound_to_current_file(self):
        (self.root / "a").write_text("first")
        args = {"path": "a", "content": "replacement", "overwrite": True}
        skill = self.executor.registry.get("write_file")
        payload = skill.approval_payload(args, self.context)
        (self.root / "a").write_text("changed")
        self.approvals.grant("write_file", payload)
        result = await self.executor.execute("write_file", args)
        self.assertFalse(result.ok)
        self.assertEqual((self.root / "a").read_text(), "changed")

    async def test_regex_resource_limit(self):
        (self.root / "a.txt").write_text("a" * 900 + "!\n")
        result = await self.call("grep", root=".", pattern="(a+)+$", regex=True)
        self.assertFalse(result.ok)
        self.assertIn("timed out", result.error)

    async def test_read_output_limit_and_file_info(self):
        (self.root / "note.txt").write_text("x" * 900)
        self.policy.limits.max_output_bytes = 1200
        result = await self.call("read_file", path="note.txt")
        self.assertTrue(result.ok)
        self.assertTrue(result.output["truncated"])
        self.assertLess(len(result.output["content"].encode()), 1200)
        info = await self.call("file_info", path="note.txt", include_sha256=True)
        self.assertTrue(info.ok)
        self.assertEqual(info.output["size"], 900)

    async def test_model_file_and_grep_outputs_fit_smaller_context_limit(self):
        (self.root / "big.c").write_text("target line\n" * 1000)
        self.policy.limits.max_read_bytes = 20_000
        self.policy.limits.max_model_tool_output_bytes = 2_048
        model_context = SkillContext(self.policy, SkillPermissionManager(self.policy, self.approvals), self.audit, origin="llm", source_root=self.root)
        model_executor = SkillExecutor(default_registry(), model_context)
        read = await model_executor.execute("read_file", {"path": "big.c"})
        self.assertTrue(read.ok, read.error)
        self.assertTrue(read.output["truncated"])
        self.assertLess(read.output["end_line"], read.output["total_lines"])
        self.assertLessEqual(len(json.dumps(read.output, ensure_ascii=False).encode()), model_context.output_limit)
        matches = await model_executor.execute("grep", {"root": ".", "pattern": "target"})
        self.assertTrue(matches.ok, matches.error)
        self.assertTrue(matches.output["truncated"])
        self.assertLessEqual(len(json.dumps(matches.output, ensure_ascii=False).encode()), model_context.output_limit)

    async def test_external_authorized_root_search(self):
        with tempfile.TemporaryDirectory() as external:
            Path(external, "source.c").write_text("KASAN marker\n")
            self.policy.workspace_roots = (self.root, Path(external))
            result = await self.call("grep", root=external, pattern="KASAN")
            self.assertTrue(result.ok, result.error)
            self.assertEqual(result.output["workspace_root"], external)
            self.assertEqual(result.output["matches"][0]["path"], "source.c")


if __name__ == "__main__":
    unittest.main()
