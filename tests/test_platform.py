import tempfile
import unittest
from pathlib import Path

from core.state_machine import StateMachine, PhaseError
from core.findings import FindingsStore, new_finding
from core.provisioning import offline_readiness, is_kernel_tree
from core.policy import Policy
from adapters import kasan, kcsan


class StateMachineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sm = StateMachine(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_starts_uninitialized_and_persists(self):
        self.assertEqual(self.sm.load().phase, "UNINITIALIZED")
        self.sm.advance("ONLINE_DOCUMENTATION")
        self.assertEqual(StateMachine(Path(self.tmp.name)).load().phase, "ONLINE_DOCUMENTATION")

    def test_forward_progression(self):
        for phase in ("ONLINE_DOCUMENTATION", "ONLINE_PROVISIONING", "ENVIRONMENT_VERIFICATION", "READY_FOR_OFFLINE", "OFFLINE_RESEARCH", "LOCAL_REPORTING"):
            self.sm.advance(phase)
        self.assertEqual(self.sm.load().phase, "LOCAL_REPORTING")

    def test_offline_never_auto_returns_to_online(self):
        self.sm.advance("OFFLINE_RESEARCH")
        with self.assertRaises(PhaseError):
            self.sm.advance("ONLINE_DOCUMENTATION")
        with self.assertRaises(PhaseError):
            self.sm.advance("ONLINE_PROVISIONING")

    def test_offline_phases_can_move_among_themselves(self):
        self.sm.advance("OFFLINE_RESEARCH")
        self.sm.advance("LOCAL_REPORTING")
        self.sm.advance("OFFLINE_RESEARCH")  # reporting -> research stays offline
        self.assertEqual(self.sm.load().phase, "OFFLINE_RESEARCH")

    def test_explicit_reset_online_is_the_only_way_back(self):
        self.sm.advance("OFFLINE_RESEARCH")
        state = self.sm.reset_online()
        self.assertEqual(state.phase, "ONLINE_DOCUMENTATION")


class FindingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = FindingsStore(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_new_finding_defaults_to_hypothesis(self):
        f = new_finding(finding_id="KERNEL-LOCAL-0001", bug_class="use-after-free", subsystem="net/tls", source_file="net/tls/tls_sw.c")
        self.assertEqual(f["status"], "hypothesis")
        self.assertEqual(f["validation"]["status"], "not_tested")
        self.assertIsNone(f["validation"]["reproducible"])

    def test_cannot_mark_validated_without_reproduction(self):
        f = new_finding(finding_id="KERNEL-LOCAL-0002", bug_class="oob", subsystem="mm", source_file="mm/x.c")
        f["status"] = "validated"
        with self.assertRaises(ValueError):
            self.store.add(f)

    def test_validated_requires_reproduced(self):
        f = new_finding(finding_id="KERNEL-LOCAL-0003", bug_class="oob", subsystem="mm", source_file="mm/x.c")
        f["status"] = "validated"
        f["validation"] = {"status": "reproduced", "reproducible": True, "detail": "KASAN in VM"}
        self.assertEqual(self.store.add(f)["finding_id"], "KERNEL-LOCAL-0003")
        self.assertEqual(self.store.get("KERNEL-LOCAL-0003")["status"], "validated")

    def test_bad_id_rejected(self):
        with self.assertRaises(ValueError):
            new_finding(finding_id="bad", bug_class="x", subsystem="y", source_file="z")

    def test_crash_evidence_is_immutable(self):
        first = self.store.store_crash_evidence("BUG: KASAN: use-after-free in foo\n")
        self.assertTrue(first["stored"])
        again = self.store.store_crash_evidence("BUG: KASAN: use-after-free in foo\n")
        self.assertFalse(again["stored"])  # identical content, not rewritten
        self.assertEqual((Path(first["path"]).stat().st_mode & 0o777), 0o444)


class CrashParseTests(unittest.TestCase):
    KASAN = (
        "BUG: KASAN: use-after-free in tls_push_record+0x6b/0x90 [tls]\n"
        "Read of size 8 at addr ffff88810a3b4e00 by task poc/321\n"
        "Call Trace:\n"
        " kasan_report+0xb8/0xf0\n"
        " tls_push_record+0x6b/0x90 [tls]\n"
        " sock_sendmsg+0x8b/0xa0\n"
    )
    KCSAN = (
        "BUG: KCSAN: data-race in list_add / list_del\n"
        "write to 0xffff at list_add\n"
        "read to 0xffff at list_del\n"
        "Call Trace:\n list_add+0x10/0x40\n"
    )

    def test_kasan_fields(self):
        r = kasan.parse_report(self.KASAN)
        self.assertEqual(r["bug_class"], "kasan-use-after-free")
        self.assertEqual(r["access"], {"type": "read", "size": 8, "addr": "ffff88810a3b4e00"})
        self.assertTrue(r["fault_site"].startswith("tls_push_record"))
        self.assertIn("tls_push_record", [f["symbol"] for f in r["frames"]])

    def test_kcsan_fields(self):
        r = kcsan.parse_report(self.KCSAN)
        self.assertEqual(r["bug_class"], "kcsan-data-race")
        self.assertTrue(r["signature"].startswith("crash:"))

    def test_same_bug_same_signature(self):
        a = kasan.parse_report(self.KASAN)["signature"]
        b = kasan.parse_report(self.KASAN.replace("0x6b/0x90", "0x9c/0xf0"))["signature"]
        self.assertEqual(a, b)  # offsets stripped -> stable signature


class ReadinessTests(unittest.TestCase):
    def test_is_kernel_tree_and_blockers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "configs").mkdir()
            self.assertFalse(is_kernel_tree(root))
            # Build a minimal kernel-tree shape under a workspace root.
            tree = root / "linux"
            (tree / "include" / "linux").mkdir(parents=True)
            (tree / "Makefile").write_text("VERSION = 6\n")
            (tree / "Kconfig").write_text("\n")
            self.assertTrue(is_kernel_tree(tree))
            policy = Policy((root, tree))
            readiness = offline_readiness(policy)
            # No target manifest recorded -> blocked, with a clear fix.
            self.assertFalse(readiness["ready"])
            self.assertTrue(any("target_configuration" in b for b in readiness["blockers"]))
            self.assertIn(str(tree), readiness["kernel_trees"])


if __name__ == "__main__":
    unittest.main()
