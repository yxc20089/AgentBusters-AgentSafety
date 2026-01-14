# Base image with uv package manager (fast Python dependency resolution)
FROM ghcr.io/astral-sh/uv:python3.13-bookworm

# Create non-root user with explicit UID for reproducible builds
# UID 1000 matches cache mount configuration below
RUN adduser --uid 1000 agent
USER agent
WORKDIR /home/agent

# Copy project files with correct ownership for agent user
COPY --chown=agent:agent pyproject.toml uv.lock README.md ./
COPY --chown=agent:agent src src
# scenarios directory required at runtime for loading plugins dynamically
COPY --chown=agent:agent scenarios scenarios

# Install dependencies with cache mount for faster rebuilds
RUN \
    --mount=type=cache,target=/home/agent/.cache/uv,uid=1000 \
    uv sync --locked

# Entry point: Security Arena Orchestrator
# Default port 9010 matches orchestrator.py default (line 700)
ENTRYPOINT ["uv", "run", "python", "scenarios/security_arena/orchestrator.py"]
CMD ["--host", "0.0.0.0", "--port", "9010"]
EXPOSE 9010
