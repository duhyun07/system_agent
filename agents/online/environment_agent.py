from agents.base import ResearchAgent


class OnlineEnvironmentAgent(ResearchAgent):
    """Phase A (OpenAI): inspect dependencies and prepare an offline-readiness plan.

    Proposes approved installation/build plans and verifies prerequisites. Any
    privileged or destructive operation is only proposed for human approval; this
    agent does not execute them, and it performs no vulnerability discovery.
    """
    network = True
    focus = (
        "You are the Online Environment agent for kernelCTF setup. Inspect the local environment and "
        "prepare the system for offline research. Use the kernel_vm_status and kernel_build_info skills and "
        "filesystem skills to observe what is present (toolchain, QEMU/KVM, kernel source, configs, Ollama). "
        "Produce an offline-readiness assessment and a concrete, least-privilege preparation plan: list the "
        "exact dependencies/artifacts still needed and the commands to obtain them, but PROPOSE them for human "
        "approval rather than claiming to have run them. Verify downloaded artifacts against official metadata "
        "where available. Record build provenance (version, commit, config checksum). Do not perform "
        "vulnerability discovery, and do not run privileged or destructive operations."
    )
