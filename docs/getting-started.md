# Getting Started

## Install

Use Python 3.11+ in the repository:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/system-agent doctor
```

Dependencies: `httpx`, the official `openai` SDK, `PyYAML`, `jsonschema`,
`regex`. API keys are read from the environment; `.env` is never auto-loaded.

## Running the tests

{% hint style="info" %}
On a host whose system Python has conflicting pytest plugins (for example a ROS
install), disable plugin autoload:
{% endhint %}

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 .venv/bin/python -m pytest -q
```

## First run-through

```bash
# 1. Health + phase
system-agent doctor
system-agent status

# 2. Online setup (set mode online for 'setup docs')
system-agent mode set online
system-agent setup docs
system-agent setup target select --instance lts --source /path/to/linux
system-agent setup verify

# 3. Enter offline research
system-agent mode set offline
system-agent research start --offline

# 4. Offline kernel research (Ollama only, no network)
system-agent research source --subsystem net/tls

# 5. Crash triage
system-agent crash triage --input ./crash.log --source /path/to/linux

# 6. Findings and reports
system-agent findings list
system-agent report generate --program kctf
```

Commands print JSON to **stdout** and human-readable progress to **stderr**, so
you can redirect results while still watching progress:

```bash
system-agent research source --subsystem mm > reports/mm.md
```

See [Workflow Phases](workflow-phases.md) for how these commands advance the
state machine, and [CLI Reference](cli-reference.md) for every command.
