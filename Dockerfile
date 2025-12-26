# Lightweight base with dev tooling
FROM mcr.microsoft.com/devcontainers/base:ubuntu

# System deps (build tools are nice for the odd pip build)
RUN apt-get update && apt-get install -y --no-install-recommends \
  curl ca-certificates git build-essential pkg-config python3-venv unzip \
  && rm -rf /var/lib/apt/lists/*

# Install uv and place it on PATH for all users
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
  && mv /root/.local/bin/uv /usr/local/bin/uv

# Install AWS CLI v2
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o "awscliv2.zip" \
  && unzip awscliv2.zip \
  && ./aws/install \
  && rm -rf awscliv2.zip aws/

# Ensure a non-root user exists (devcontainers base includes 'vscode')
USER vscode
WORKDIR /work

# Set up automatic venv activation in bashrc
RUN echo 'if [ -f "/work/auth/.venv/bin/activate" ]; then source /work/auth/.venv/bin/activate; fi' >> ~/.bashrc
