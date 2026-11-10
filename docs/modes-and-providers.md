# Modes and Providers

A **mode** selects which LLM provider is active.

| Mode | Provider | Used for |
| --- | --- | --- |
| `offline` (default) | local Ollama on loopback | Phase B research |
| `online` | OpenAI Responses API | Phase A documentation / setup |
| `hybrid` | Ollama for research; cloud only via an explicit approved command | mixed |

```bash
system-agent mode show
system-agent mode set offline   # research
system-agent mode set online    # documentation/setup
```

The mode is stored in `.system-agent-mode`. Modes are independent of the network
allowlist.

## Online (OpenAI)

Set in `configs/online.yaml`: `OPENAI_API_KEY` (environment), an `openai_model`,
per-million-token prices, and a positive `max_spend_usd`. The router enforces
context, token, iteration, tool, time, and spending limits. Online mode may send
tool results to OpenAI as part of the requested task.

## Hybrid

Ordinary research uses local Ollama. Cloud inference is a **separate explicit
command** that requires approval of the SHA-256 of its exact UTF-8 JSON payload:

```bash
system-agent cloud approval-hash "summarize the current rules"
system-agent cloud run "summarize the current rules" --approve-sha256 <hash>
```

There is no automatic cloud fallback and no automatic local-file upload.

## Offline (Ollama) and GPU

The offline provider talks to Ollama at `127.0.0.1:11434`. Defaults:

| Setting | Value |
| --- | --- |
| `default_model` | `qwen3:4b` |
| `code_model` (optional) | `qwen2.5-coder:7b` |
| `context_length` | 8192 |
| parallelism | one inference at a time |

### GPU offload

`configs/offline.yaml` sets `llm.num_gpu: 999`, which offloads every model layer
that fits onto the GPU (e.g. RTX 4060 8GB). Ollama clamps to available VRAM and
spills the rest to CPU. Set `num_gpu: 0` to force CPU-only.

Confirm placement:

```bash
ollama ps
# NAME       ...  PROCESSOR    CONTEXT
# qwen3:4b   ...  100% GPU     8192
```

`system-agent models list` shows the configured roster and installed models;
`system-agent models test --provider ollama` does a minimal round-trip.
