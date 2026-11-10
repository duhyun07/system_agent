from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from typing import Any
import yaml

Mode = Literal["offline", "online", "hybrid"]


@dataclass
class Limits:
    max_tool_calls_per_task: int = 30
    max_iterations: int = 40
    max_execution_seconds: float = 120
    max_tool_seconds: float = 30
    max_read_bytes: int = 1_048_576
    max_write_bytes: int = 1_048_576
    max_output_bytes: int = 65_536
    max_model_tool_output_bytes: int = 8_192
    max_fetch_bytes: int = 2_097_152
    max_fetch_redirects: int = 3
    max_scan_bytes: int = 2_097_152
    max_entries: int = 1000
    max_walk_entries: int = 200000
    max_context_chars: int = 100_000
    max_input_tokens: int = 100_000
    max_output_tokens: int = 10_000
    max_spend_usd: float = 0.0


@dataclass
class Policy:
    workspace_roots: tuple[Path, ...]
    mode: Mode = "offline"
    limits: Limits = field(default_factory=Limits)
    allowed_domains: tuple[str, ...] = ()
    ignored_dirs: tuple[str, ...] = (".git", ".aws", ".codex", ".agents", "__pycache__", ".venv")
    protected_names: tuple[str, ...] = (".env", ".env.local", "id_rsa", "id_ed25519", "credentials", "credentials.json", "secrets.yaml", "secrets.yml")
    search_provider: str = "duckduckgo"
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "qwen3:4b"
    ollama_code_model: str = "qwen2.5-coder:7b"
    ollama_num_ctx: int | None = None
    ollama_num_gpu: int | None = None
    openai_model: str = ""
    openai_input_usd_per_million: float = 0.0
    openai_output_usd_per_million: float = 0.0
    retry_limit: int = 2
    request_timeout_seconds: float = 30
    skill_rules: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.workspace_roots:
            raise ValueError("At least one workspace root is required")
        self.workspace_roots = tuple(Path(p).resolve() for p in self.workspace_roots)
        if self.mode not in ("offline", "online", "hybrid"):
            raise ValueError("Invalid mode")

    @classmethod
    def load(cls, root: Path, mode: Mode | None = None) -> "Policy":
        root = root.resolve()
        state = root / ".system-agent-mode"
        chosen = mode or (state.read_text().strip() if state.exists() else "offline")
        if chosen not in ("offline", "online", "hybrid"):
            raise ValueError("Invalid mode")
        path = root / "configs" / f"{chosen}.yaml"
        data = yaml.safe_load(path.read_text()) if path.exists() else {}
        data = data or {}
        rules_path = root / "configs" / "skills.yaml"
        shared = yaml.safe_load(rules_path.read_text()) or {} if rules_path.exists() else {}
        limits = Limits(**{**shared.get("limits", {}), **data.get("limits", {})})
        llm = data.get("llm", {})
        network = data.get("network", {})
        rules = shared.get("skills", {})
        configured_roots = data.get("workspace_roots", [str(root)])
        extras = [(Path(value) if Path(value).is_absolute() else root / value).resolve() for value in configured_roots]
        roots = tuple(dict.fromkeys((root, *extras)))
        return cls(
            workspace_roots=roots, mode=chosen, limits=limits,
            allowed_domains=tuple(network.get("allowed_domains", [])),
            search_provider=network.get("search_provider", "duckduckgo"),
            ollama_url=llm.get("ollama_url", "http://127.0.0.1:11434"),
            ollama_model=llm.get("ollama_model", "qwen3:4b"),
            ollama_code_model=llm.get("code_model", "qwen2.5-coder:7b"),
            ollama_num_ctx=llm.get("num_ctx"),
            ollama_num_gpu=llm.get("num_gpu"),
            openai_model=llm.get("openai_model", ""),
            openai_input_usd_per_million=llm.get("input_usd_per_million", 0),
            openai_output_usd_per_million=llm.get("output_usd_per_million", 0),
            skill_rules=rules,
        )
