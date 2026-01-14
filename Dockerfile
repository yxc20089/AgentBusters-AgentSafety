FROM ghcr.io/astral-sh/uv:python3.13-bookworm

RUN adduser agent
USER agent
WORKDIR /home/agent

# Copy project files
COPY pyproject.toml uv.lock README.md ./
COPY src src
COPY scenarios scenarios

# Install dependencies
RUN \
    --mount=type=cache,target=/home/agent/.cache/uv,uid=1000 \
    uv sync --locked

# Entry point: Security Arena Orchestrator
ENTRYPOINT ["uv", "run", "python", "scenarios/security_arena/orchestrator.py"]
CMD ["--host", "0.0.0.0", "--port", "9009"]
EXPOSE 9009
