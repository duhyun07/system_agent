from __future__ import annotations

from datetime import date
from typing import Any

from core.programs import Program

# Human-readable prompts for the fields used by the program profiles. Any field a
# profile names that is missing here still renders with a generic prompt.
FIELD_HELP: dict[str, str] = {
    "title": "One-line summary of the bug.",
    "affected_subsystem": "Kernel subsystem / directory.",
    "affected_versions": "Version(s) confirmed affected, with commit if known.",
    "bug_class": "e.g. use-after-free, out-of-bounds-write, race-condition.",
    "novelty": "0-day | 1-day (with fix commit) | unsure.",
    "fix_commit": "Upstream fixing commit, or 'none found'.",
    "regression_range": "Bisected commit range introducing the bug, or 'unknown'.",
    "root_cause": "The defect, cited to source-relative path:line.",
    "reachability": "How the vulnerable code is reached on the target instance.",
    "reproduction": "Trigger steps / minimized non-weaponized reproducer. No exploit payload.",
    "affected_config": "Relevant CONFIG_* / instance (LTS/COS/mitigation).",
    "impact": "Primitive obtained, cited to evidence.",
    "crash_evidence": "Sanitizer output (KASAN/KCSAN/KFENCE/lockdep), pasted as untrusted evidence.",
}


def blank_template(program: Program) -> str:
    """A ready-to-fill Markdown skeleton for the program's submission."""
    lines = [
        f"# {program.name} — bug report draft",
        "",
        f"<!-- Program: {program.key}. Fill every field from evidence. Delete this comment. -->",
        f"<!-- Official rules: {program.links.get('official_rules', 'see program page')} -->",
        f"_Drafted: {date.today().isoformat()}_",
        "",
    ]
    for name in program.report_fields:
        pretty = name.replace("_", " ").title()
        help_text = FIELD_HELP.get(name, "")
        lines.append(f"## {pretty}")
        if help_text:
            lines.append(f"<!-- {help_text} -->")
        lines.append("")
        lines.append("TODO")
        lines.append("")
    lines.append("## Pre-submission checklist")
    for item in program.checklist:
        lines.append(f"- [ ] {item}")
    lines.append("")
    lines.append(
        "> System Agent drafts triage and this report from source evidence only. "
        "Capturing any flag, running a reproducer, and submission are performed by the researcher "
        "under the program's official rules."
    )
    return "\n".join(lines) + "\n"


def render(program: Program, fields: dict[str, Any]) -> str:
    """Render the submission report, substituting provided fields.

    A `bug_class` value is annotated with the program's tier mapping so the
    severity reasoning is traceable. Unknown field keys are ignored; missing
    ones render as TODO with their help text.
    """
    fields = {str(k): v for k, v in (fields or {}).items()}
    lines = [
        f"# {program.name} — bug report",
        "",
        f"_Program: {program.key} · Drafted: {date.today().isoformat()}_",
        f"_Official rules: {program.links.get('official_rules', 'see program page')}_",
        "",
    ]
    bug_class = fields.get("bug_class")
    classification = program.classify(bug_class) if bug_class else None
    for name in program.report_fields:
        pretty = name.replace("_", " ").title()
        lines.append(f"## {pretty}")
        value = fields.get(name)
        if value is None or value == "":
            help_text = FIELD_HELP.get(name, "")
            lines.append(f"<!-- {help_text} -->" if help_text else "")
            lines.append("TODO")
        else:
            lines.append(str(value).rstrip())
            if name == "bug_class" and classification is not None:
                lines.append("")
                lines.append(
                    f"> Program tier for `{classification.name}`: **{classification.tier}**. "
                    f"{classification.note}".rstrip()
                )
        lines.append("")
    lines.append("## Pre-submission checklist")
    for item in program.checklist:
        lines.append(f"- [ ] {item}")
    lines.append("")
    lines.append(
        "> Triage and report drafted from source evidence only; no exploit is included. "
        "Verify current rules and submit through the official program process."
    )
    return "\n".join(lines) + "\n"
