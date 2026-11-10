from agents.kernel.base import KernelResearchAgent


class KernelPatchAgent(KernelResearchAgent):
    """Ollama-only: commit comparison, incomplete-fix detection, regression analysis."""
    focus = (
        "Analyze Linux kernel commits and security-relevant source changes using the local git "
        "history only. Compare commits with kernel_commit_diff, assess whether a fix is complete, "
        "and correlate changes with previously identified candidate findings. Produce structured "
        "regression analysis citing commit hashes and source-relative path:line. Distinguish a novel "
        "(0-day) candidate from an already-fixed (1-day) issue by locating the fixing commit when present."
    )
