from agents.triage import ProgramTriageAgent
from adapters.kernel.source import KernelSourceAdapter


class KctfTriageAgent(ProgramTriageAgent):
    """kernelCTF (kernel VRP) source triage over a validated Linux tree."""
    adapter_cls = KernelSourceAdapter
