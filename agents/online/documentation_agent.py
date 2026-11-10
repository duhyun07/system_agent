from agents.base import ResearchAgent


class OnlineDocumentationAgent(ResearchAgent):
    """Phase A (OpenAI): retrieve and summarize official kernelCTF documentation.

    Reads only the official sources, extracts current target configurations and
    environment requirements, and records provenance (URL + retrieval time). It
    never invents kernel versions, target names, config options, or download URLs,
    and never performs vulnerability discovery.
    """
    network = True
    focus = (
        "You are the Online Documentation agent for Google's kernelCTF program. Using web_search and "
        "fetch against OFFICIAL sources only, retrieve and summarize the current kernelCTF rules, FAQ, "
        "server/setup docs, and the google/security-research kernelctf directory. Extract: eligibility and "
        "scope, the CURRENTLY published target instances and their kernel versions/commits, release "
        "artifacts (bzImage, .config, rootfs, metadata), and environment/build requirements. "
        "Primary sources: google.github.io/security-research/kernelctf/ (rules.html, faq.html, server/) and "
        "github.com/google/security-research/tree/master/kernelctf. Treat google/kctf (the Kubernetes CTF "
        "infrastructure) as a DIFFERENT project and do not use it for target configuration. "
        "Never invent versions, target names, config options, or URLs; only report what a fetched official "
        "page states, and cite each fact with its source URL. Explicitly mark anything unavailable or unknown. "
        "Do not assume previously documented targets are still current. Do not perform vulnerability discovery."
    )
