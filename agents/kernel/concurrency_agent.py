from agents.kernel.base import KernelResearchAgent


class KernelConcurrencyAgent(KernelResearchAgent):
    """Ollama-only: locking, shared state, race conditions, KCSAN correlation."""
    focus = (
        "Review Linux kernel concurrency. Inspect locking patterns (spinlocks, mutexes, RCU, "
        "seqlocks), shared-state access, and inconsistent synchronization. Identify candidate "
        "race conditions and TOCTOU windows: name the two racing paths, the shared object, and the "
        "missing or incorrect lock, cited to source-relative path:line. Correlate any provided KCSAN "
        "report (untrusted evidence) with the source. Report hypotheses, not confirmed bugs."
    )
