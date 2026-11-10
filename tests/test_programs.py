import contextlib
import io
import json
import unittest
from pathlib import Path

import cli
from core.programs import ProgramRegistry
from core.report_templates import blank_template, render

ROOT = Path(__file__).resolve().parents[1]


class ProgramRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = ProgramRegistry.load(ROOT)

    def test_bundled_programs_load(self):
        keys = self.registry.keys()
        self.assertIn("kctf", keys)

    def test_v8_program_is_removed(self):
        self.assertNotIn("chrome-vrp", self.registry.keys())

    def test_domains_map_to_supported_adapters(self):
        self.assertEqual(self.registry.get("kctf").domain, "kernel")

    def test_unknown_program_is_clean_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            self.registry.get("nope")
        self.assertIn("Configured programs", str(ctx.exception))

    def test_classify_known_and_alias(self):
        kctf = self.registry.get("kctf")
        self.assertEqual(kctf.classify("use-after-free").tier, "strong-primitive")
        self.assertEqual(kctf.classify("UAF").name, "use-after-free")  # alias + case

    def test_classify_unknown_is_flagged_not_crashing(self):
        kctf = self.registry.get("kctf")
        result = kctf.classify("quantum-entanglement")
        self.assertEqual(result.tier, "unknown")

    def test_triage_instructions_forbid_exploit_code(self):
        text = self.registry.get("kctf").triage_instructions()
        self.assertIn("never", text.lower() + "")
        self.assertIn("exploit", text.lower())
        self.assertIn("path:line", text)

    def test_missing_file_yields_empty_registry(self):
        empty = ProgramRegistry.load(ROOT / "tests")  # no configs/programs.yaml here
        self.assertFalse(empty)
        self.assertEqual(empty.keys(), [])


class ReportTemplateTests(unittest.TestCase):
    def setUp(self):
        self.program = ProgramRegistry.load(ROOT).get("kctf")

    def test_blank_template_lists_every_field_and_checklist(self):
        text = blank_template(self.program)
        for field in self.program.report_fields:
            self.assertIn(field.replace("_", " ").title(), text)
        self.assertIn("Pre-submission checklist", text)

    def test_render_substitutes_values_and_annotates_tier(self):
        text = render(self.program, {"title": "UAF in some_subsystem", "bug_class": "use-after-free"})
        self.assertIn("UAF in some_subsystem", text)
        self.assertIn("Program tier for `use-after-free`", text)
        self.assertIn("**strong-primitive**", text)

    def test_render_missing_fields_become_todo(self):
        text = render(self.program, {})
        self.assertIn("TODO", text)


class ProgramsCliTests(unittest.TestCase):
    def _run(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(argv)
        return code, out.getvalue()

    def test_programs_list(self):
        code, output = self._run(["programs", "list"])
        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertEqual({p["key"] for p in data}, {"kctf"})

    def test_programs_show_unknown_is_handled(self):
        code, _ = self._run(["programs", "show", "nope"])
        self.assertEqual(code, 1)

    def test_report_template_cli(self):
        code, output = self._run(["report", "template", "kctf"])
        self.assertEqual(code, 0)
        self.assertIn("bug report draft", output)

    def test_report_build_cli_with_fields(self):
        code, output = self._run(["report", "build", "kctf", "--fields", json.dumps({"bug_class": "use-after-free"})])
        self.assertEqual(code, 0)
        self.assertIn("**strong-primitive**", output)


if __name__ == "__main__":
    unittest.main()
