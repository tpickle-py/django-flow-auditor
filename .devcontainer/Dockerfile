FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

# Install additional system utilities
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl \
        git \
        ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Install uv from the official Astral image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Ensure vscode user has access
USER vscode
ENV PATH="/home/vscode/.local/bin:${PATH}"
