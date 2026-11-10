from agents.kernel.base import KernelResearchAgent


class KernelSourceAgent(KernelResearchAgent):
    focus = "Analyze Linux kernel source for kernelCTF and document exact paths, versions, commit hashes, and source-cited evidence. Report candidate findings as hypotheses, never confirmed vulnerabilities, and never produce exploit code."
