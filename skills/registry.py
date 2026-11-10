from __future__ import annotations

from skills.base import BaseSkill


class SkillRegistry:
    def __init__(self):
        self._skills: dict[str, BaseSkill] = {}

    def register(self, skill: BaseSkill) -> None:
        if skill.name in self._skills:
            raise ValueError(f"Duplicate skill: {skill.name}")
        self._skills[skill.name] = skill

    def get(self, name: str) -> BaseSkill:
        return self._skills[name]

    def list(self) -> list[BaseSkill]:
        return list(self._skills.values())


def default_registry() -> SkillRegistry:
    from skills.filesystem.read_file import ReadFile
    from skills.filesystem.write_file import WriteFile
    from skills.filesystem.edit_file import EditFile
    from skills.filesystem.list_dir import ListDir
    from skills.filesystem.search_files import SearchFiles
    from skills.filesystem.grep import Grep
    from skills.filesystem.file_info import FileInfo
    from skills.filesystem.apply_patch import ApplyPatch
    from skills.network.fetch import Fetch
    from skills.network.web_search import WebSearch
    from skills.kernel.search import KernelSourceSearch, KernelFunctionLookup, KernelCallgraphLookup
    from skills.kernel.config import KernelConfigLookup
    from skills.kernel.commit import KernelCommitDiff
    from skills.kernel.logs import KernelLogParse, KernelCrashDeduplicate
    from skills.kernel.env import KernelBuildInfo, KernelCoverageRead, KernelVmStatus
    from skills.kernel.test_run import KernelTestRun
    registry = SkillRegistry()
    for cls in (
        ReadFile, WriteFile, EditFile, ListDir, SearchFiles, Grep, FileInfo, ApplyPatch,
        Fetch, WebSearch,
        KernelSourceSearch, KernelFunctionLookup, KernelCallgraphLookup, KernelConfigLookup,
        KernelCommitDiff, KernelLogParse, KernelCrashDeduplicate, KernelBuildInfo,
        KernelCoverageRead, KernelVmStatus, KernelTestRun,
    ):
        registry.register(cls())
    return registry
