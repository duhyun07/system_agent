from __future__ import annotations

from agents.base import ResearchAgent
from adapters.kernel.source import KernelSourceAdapter


class KernelResearchAgent(ResearchAgent):
    """Ollama-only kernel research agent over a validated Linux checkout.

    Shares the marker-validated source inspection and the line-evidence contract:
    the final answer is rejected unless it cites inspected source lines. Runs with
    the network disabled (Phase B isolation).
    """
    network = False

    async def inspect_and_run(self, source: str, task: str) -> str:
        evidence = await KernelSourceAdapter().inspect(self.system, source, task)
        return await self.run(
            f"Validated Linux kernel source: {source}. "
            f"User-mentioned directory observations: {evidence['mentioned_dirs']}. User task: {task}",
            source=source, user_task=task,
        )
