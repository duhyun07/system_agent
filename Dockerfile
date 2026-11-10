FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml cli.py ./
COPY core ./core
COPY llm ./llm
COPY skills ./skills
COPY agents ./agents
COPY adapters ./adapters
COPY security ./security
RUN pip install --no-cache-dir . && mkdir -p /workspace/research /workspace/logs
COPY configs /workspace/configs
WORKDIR /workspace
ENTRYPOINT ["system-agent"]
