import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cli


def make_workspace(tmp: Path) -> Path:
    """A project-shaped workspace with configs and a minimal kernel tree."""
    (tmp / "configs").mkdir()
    (tmp / "configs" / "offline.yaml").write_text(
        "llm:\n  ollama_model: qwen3:4b\n  num_ctx: 8192\n"
        "workspace_roots:\n  - .\n  - ./linux\n"
    )
    (tmp / "configs" / "skills.yaml").write_text(Path(__file__).resolve().parents[1].joinpath("configs/skills.yaml").read_text())
    (tmp / "configs" / "programs.yaml").write_text(Path(__file__).resolve().parents[1].joinpath("configs/programs.yaml").read_text())
    (tmp / "configs" / "models.yaml").write_text("offline:\n  default_model: qwen3:4b\n")
    tree = tmp / "linux"
    (tree / "include" / "linux").mkdir(parents=True)
    (tree / "net").mkdir()
    (tree / "Makefile").write_text("VERSION = 6\nPATCHLEVEL = 12\nSUBLEVEL = 114\n")
    (tree / "Kconfig").write_text("\n")
    (tmp / ".system-agent-mode").write_text("offline\n")
    return tree


class CliPlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.tree = make_workspace(self.root)
        self._cwd = os.getcwd()
        os.chdir(self.root)

    def tearDown(self):
        os.chdir(self._cwd)
        self.temp.cleanup()

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_status_reports_phase_and_blockers(self):
        code, out, _ = self.run_cli(["status"])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["phase"], "UNINITIALIZED")
        self.assertIn(str(self.tree.resolve()), data["kernel_trees"])

    def test_v8_commands_absent(self):
        # Acceptance: V8 functionality is gone from the active application.
        with self.assertRaises(SystemExit) as ctx:  # argparse rejects unknown subcommand
            self.run_cli(["research", "v8", "--source", str(self.tree)])
        self.assertEqual(ctx.exception.code, 2)
        # And no V8/chrome program remains.
        code, out, _ = self.run_cli(["programs", "list"])
        self.assertEqual({p["key"] for p in json.loads(out)}, {"kctf"})

    def test_research_start_blocks_without_target(self):
        code, out, err = self.run_cli(["research", "start", "--offline"])
        self.assertEqual(code, 1)
        self.assertIn("prerequisites", err)

    def test_research_source_requires_offline_phase(self):
        code, _, err = self.run_cli(["research", "source", "--subsystem", "net", "--source", str(self.tree)])
        self.assertEqual(code, 1)
        self.assertIn("offline research phase", err.lower())

    def test_setup_target_records_manifest_and_advances(self):
        code, out, _ = self.run_cli(["setup", "target", "select", "--instance", "lts", "--source", str(self.tree)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["instance"], "lts")
        self.assertTrue((self.root / "research" / "kernel" / "target-manifest.json").exists())
        code, out, _ = self.run_cli(["status"])
        self.assertEqual(json.loads(out)["phase"], "ONLINE_PROVISIONING")

    def test_full_setup_to_research_phase_when_ready(self):
        self.run_cli(["setup", "target", "select", "--instance", "lts", "--source", str(self.tree)])
        with patch("core.provisioning.ollama_status", return_value={"reachable": True, "status": "reachable", "models": ["qwen3:4b"], "default_model": "qwen3:4b", "default_model_present": True, "url": "http://127.0.0.1:11434"}):
            code, out, _ = self.run_cli(["setup", "verify"])
            self.assertTrue(json.loads(out)["ready"], json.loads(out)["blockers"])
            code, out, _ = self.run_cli(["research", "start", "--offline"])
            self.assertEqual(code, 0, out)
        code, out, _ = self.run_cli(["status"])
        self.assertEqual(json.loads(out)["phase"], "OFFLINE_RESEARCH")

    def test_setup_docs_requires_online_mode(self):
        code, _, err = self.run_cli(["setup", "docs"])
        self.assertEqual(code, 1)
        self.assertIn("Online provider", err)

    def test_crash_analyze_and_findings_empty(self):
        log = self.root / "crash.log"
        log.write_text("BUG: KASAN: use-after-free in foo+0x1/0x2\nRead of size 8 at addr ffff by task x/1\nCall Trace:\n foo+0x1/0x2\n")
        code, out, _ = self.run_cli(["crash", "analyze", "--input", str(log)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["parsed"]["bug_class"], "kasan-use-after-free")
        code, out, _ = self.run_cli(["findings", "list"])
        self.assertEqual(json.loads(out)["count"], 0)

    def test_skills_list_includes_kernel_and_marks_cli_only(self):
        code, out, _ = self.run_cli(["skills", "list"])
        data = {s["name"]: s for s in json.loads(out)}
        self.assertIn("kernel_source_search", data)
        self.assertTrue(data["kernel_test_run"]["cli_only"])


if __name__ == "__main__":
    unittest.main()
