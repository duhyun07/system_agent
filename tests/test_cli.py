import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import cli
from core.progress import ConsoleProgress


class CliErrorTests(unittest.TestCase):
    def test_progress_goes_to_stderr(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            ConsoleProgress()("skill read_file 시작")
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("skill read_file 시작", stderr.getvalue())

    def test_ollama_thinking_goes_to_stderr_and_filters_control_characters(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            progress = ConsoleProgress()
            progress.thinking("inspect\x1b[31m source")
            progress.thinking_end()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("inspect[31m source", stderr.getvalue())
        self.assertNotIn("\x1b", stderr.getvalue())
        self.assertIn("Ollama thinking 종료", stderr.getvalue())

    def test_doctor_distinguishes_socket_permission_denial(self):
        output = io.StringIO()
        with patch("core.provisioning.socket.create_connection", side_effect=PermissionError("denied")), contextlib.redirect_stdout(output):
            code = cli.main(["doctor"])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["ollama"]["status"], "socket_denied")
        self.assertFalse(report["ollama"]["reachable"])

    def test_outside_workspace_has_no_traceback(self):
        script = Path(__file__).resolve().parents[1] / "cli.py"
        with tempfile.TemporaryDirectory() as workspace:
            result = subprocess.run(
                [sys.executable, str(script), "ls", "/definitely/outside/system-agent"],
                cwd=workspace, text=True, capture_output=True,
            )
        self.assertEqual(result.returncode, 1)
        combined = result.stdout + result.stderr
        self.assertIn("Path outside authorized workspaces", combined)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
