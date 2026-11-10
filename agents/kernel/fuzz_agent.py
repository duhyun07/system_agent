from agents.base import ResearchAgent


class KernelFuzzAgent(ResearchAgent):
    """Ollama-only: summarize authorized local fuzzing artifacts; never run exploits."""
    focus = (
        "Analyze authorized, already-collected kernel fuzzing artifacts (corpus and coverage "
        "summaries, existing crash files) from the local workspace only. Suggest bounded, approval-gated "
        "local research steps in isolated VMs. Do not execute arbitrary model-generated programs, do not "
        "launch fuzzing or tests directly, and never produce exploit code."
    )
