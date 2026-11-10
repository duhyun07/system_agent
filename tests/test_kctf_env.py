import json
import os
import tempfile
import unittest
from pathlib import Path

from core.policy import Policy
from core.programs import ProgramRegistry
from core.kctf_env import scaffold, EXECUTABLE
from security.filesystem import atomic_write, checked_path

ROOT = Path(__file__).resolve().parents[1]


class ScaffoldTests(unittest.TestCase):
    def setUp(self):
        self.program = ProgramRegistry.load(ROOT).get("kctf")

    def test_instances_configured(self):
        self.assertIn("lts", self.program.instances)
        self.assertIn("mitigation", self.program.instances)

    def test_scaffold_produces_expected_files(self):
        files = scaffold(self.program, "lts", source="/home/pwner7/WSL2-Linux-Kernel", dest_rel="envs/kctf-lts")
        for expected in ("README.md", "FETCH.md", "run-qemu.sh", "scripts/attach-gdb.sh", "config/notes.md", "notes/fields.json", "env.json", ".gitignore"):
            self.assertIn(expected, files)

    def test_unknown_instance_rejected(self):
        with self.assertRaises(ValueError):
            scaffold(self.program, "nope", source="/x", dest_rel="envs/x")

    def test_run_script_is_safe_shell_and_boots_user_supplied_image(self):
        sh = scaffold(self.program, "lts", source="/src", dest_rel="d")["run-qemu.sh"]
        self.assertIn("set -euo pipefail", sh)
        self.assertIn("qemu-system-x86_64", sh)
        self.assertIn("BZIMAGE", sh)

    def test_never_auto_downloads_or_runs_anything(self):
        files = scaffold(self.program, "mitigation", source="/src", dest_rel="d")
        blob = "\n".join(files.values()).lower()
        # No automatic fetch of a kernel/artifact anywhere in the scaffold.
        for bad in ("curl http", "curl -", "wget http", "wget -"):
            self.assertNotIn(bad, blob)
        # Fetching is a documented MANUAL step.
        self.assertIn("does **not** fetch", files["FETCH.md"])

    def test_env_json_manifest_records_source_and_instance(self):
        manifest = json.loads(scaffold(self.program, "cos", source="/home/pwner7/k", dest_rel="d")["env.json"])
        self.assertEqual(manifest["instance"], "cos")
        self.assertEqual(manifest["source"], "/home/pwner7/k")
        self.assertEqual(manifest["program"], "kctf")

    def test_executables_listed_exist_in_scaffold(self):
        files = scaffold(self.program, "lts", source="/s", dest_rel="d")
        for name in EXECUTABLE:
            self.assertIn(name, files)

    def test_writes_through_guarded_atomic_write_into_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = Policy(workspace_roots=(Path(tmp),))
            files = scaffold(self.program, "lts", source="/s", dest_rel="envs/kctf-lts")
            for rel, content in files.items():
                target = f"envs/kctf-lts/{rel}"
                root, parts, _ = checked_path(policy, target)
                os.makedirs(root.joinpath(*parts[:-1]), exist_ok=True)
                atomic_write(policy, target, content.encode(), overwrite=False)
            base = Path(tmp) / "envs" / "kctf-lts"
            self.assertTrue((base / "run-qemu.sh").is_file())
            self.assertTrue((base / "scripts" / "attach-gdb.sh").is_file())
            self.assertTrue((base / "env.json").is_file())


if __name__ == "__main__":
    unittest.main()
