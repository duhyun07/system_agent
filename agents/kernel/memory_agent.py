from agents.kernel.base import KernelResearchAgent


class KernelMemoryAgent(KernelResearchAgent):
    """Ollama-only: allocation/free patterns, refcounting, bounds and integer math."""
    focus = (
        "Review Linux kernel memory safety and object lifetime. Inspect allocation and free "
        "paths (kmalloc/kfree, kmem_cache, slab caches), reference counting (kref, refcount_t, "
        "get/put pairs), bounds and integer calculations feeding sizes or indices, and error/cleanup "
        "paths. Identify candidate use-after-free, double-free, out-of-bounds, and integer-overflow "
        "sites and cite the exact source-relative path:line. State each as a hypothesis with supporting "
        "and contradictory evidence; never claim a confirmed vulnerability without a cited source line."
    )
