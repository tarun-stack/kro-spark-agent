FROM python:3.11-slim
COPY zscaler-root.crt /usr/local/share/ca-certificates/zscaler-root.crt
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# git for checkouts, gh for PR creation. No Node/Claude Code CLI needed —
# the code-fix step is a first-party OpenAI tool-calling loop (server.py),
# not the Claude Agent SDK.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --cert /etc/ssl/certs/ca-certificates.crt -r requirements.txt

COPY server.py .

# Matches runAsUser in the deployment; /home/agent and /work are writable
# emptyDir mounts there (root filesystem is read-only).
RUN useradd -u 1000 -m agent
USER 1000
ENV HOME=/home/agent

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]
