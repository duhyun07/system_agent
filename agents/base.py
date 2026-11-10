from __future__ import annotations
from core.orchestrator import SystemAgent


class ResearchAgent:
    focus: str = ""
    # Offline research agents run with the network disabled (Phase B isolation).
    # Online setup agents override this to True.
    network: bool = False
    source_instructions = "For filesystem Skills, relative paths are resolved against the supplied source root; do not assume the project root. Marker files only confirm the checkout; they are not vulnerability candidates. Do not choose the first alphabetic file in a directory as a vulnerability candidate. Before your final answer, call read_file or grep on a specific source file. Do not stop after list_dir or search_files. Cite observed evidence as source-relative path:line. search_files matches file basenames only; use list_dir for directories. Empty or truncated search results alone do not establish that a directory or feature is absent. Do not invent or guess fetch URLs: only fetch a URL that a web_search result returned, and never construct kernel.org or other download paths from a version string. If web_search returns no results, do not fetch; rely on the local source. The source tree is the primary evidence; the network is optional and must not become a loop of guessed URLs. For broad vulnerability requests, inspect one candidate subsystem and report a hypothesis only if specific source evidence supports it; do not claim to have found a vulnerability without proof. Distinguish source presence from build configuration."
    def __init__(self, system: SystemAgent):
        self.system = system

    async def run(self, task: str, *, source: str | None = None, user_task: str | None = None, allow_network: bool | None = None) -> str:
        net = self.network if allow_network is None else allow_network
        return await self.system.run(task, instructions=self.focus + ("\n" + self.source_instructions if source else ""), require_line_evidence=bool(source), source_root=source, task_reminder=user_task, allow_network=net)
