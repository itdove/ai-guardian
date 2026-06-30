# ai-guardian support reproduction image
#
# Minimal UBI-based container with ai-guardian and all headless-capable IDEs
# for reproducing user-reported issues across environments and architectures.
#
# Build:
#   podman build -t ai-guardian-support support/
#   podman build --build-arg AI_GUARDIAN_VERSION=1.13.0 -t ai-guardian-support support/
#
# Run:
#   podman run -it -p 63152 ai-guardian-support
#   podman run -it -p 63152 -e AI_GUARDIAN_IDE=opencode ai-guardian-support
#
# Local wheel:
#   python -m build --wheel && cp dist/ai_guardian-*.whl support/vendor/
#   podman build --build-arg AI_GUARDIAN_VERSION=ai_guardian-1.13.0.dev0-py3-none-any.whl -t ai-guardian-support support/

FROM registry.access.redhat.com/ubi10/ubi-minimal:latest

ARG AI_GUARDIAN_VERSION=1.13.0
ARG AI_GUARDIAN_REST_PORT=63152
ARG UV_VERSION=0.11.16
ARG OPENCODE_VERSION=1.17.3

USER root

# Copy wheel files if present (Dockerfile included to guarantee COPY succeeds
# even when no .whl files exist in the build context)
COPY Dockerfile vendor/ai_guardian-*.whl /tmp/

# System packages + uv + ai-guardian + scanners
# libxcb mesa-libGL libSM libXext: needed by rapidocr-onnxruntime for image scanning
RUN microdnf install -y --nodocs \
        shadow-utils git jq curl bash tar gzip xz findutils sed \
        ca-certificates vim-minimal which hostname procps-ng \
        python3 python3-pip nodejs \
        libxcb mesa-libGL libSM libXext \
    && microdnf clean all \
    \
    # uv — Python package manager
    && curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" \
        | env INSTALLER_NO_MODIFY_PATH=1 UV_INSTALL_DIR=/usr/local/bin sh \
    && uv --version \
    \
    # ai-guardian — from wheel if provided, otherwise PyPI
    && echo "Installing ai-guardian: ${AI_GUARDIAN_VERSION}" \
    && case "${AI_GUARDIAN_VERSION}" in \
        *.whl) UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin \
               uv tool install "/tmp/${AI_GUARDIAN_VERSION}" \
               --with rapidocr-onnxruntime==1.4.4 ;; \
        *)     UV_TOOL_DIR=/opt/uv-tools UV_TOOL_BIN_DIR=/usr/local/bin \
               uv tool install "ai-guardian==${AI_GUARDIAN_VERSION}" \
               --with rapidocr-onnxruntime==1.4.4 ;; \
    esac \
    && chmod -R a+rX /opt/uv-tools \
    && rm -f /tmp/ai_guardian-*.whl /tmp/Dockerfile \
    && ln -sf /usr/local/bin/ai-guardian /usr/bin/ai-guardian \
    && (ai-guardian --version || echo "ai-guardian installed (version check skipped under emulation)") \
    \
    # Secret scanners
    && (ai-guardian scanner install gitleaks --use-pinned || true) \
    && test -x /usr/local/bin/gitleaks \
    && (ai-guardian scanner install betterleaks --use-pinned || true) \
    && test -x /usr/local/bin/betterleaks \
    \
    # Sandbox user
    && groupadd -g 1000 sandbox \
    && useradd -m -u 1000 -g sandbox -d /sandbox sandbox \
    && ln -s /sandbox /home/sandbox \
    && rm -f /sandbox/.bash_profile \
    && echo 'export PATH="$HOME/.local/bin:$PATH"' > /sandbox/.bashrc \
    && chown sandbox:sandbox /sandbox/.bashrc \
    && echo 'printf "ai-guardian support container (built on '"$(date)"')\n\n"' \
        > /etc/profile.d/support_banner.sh

# IDEs — install as sandbox user so binaries land in ~/.local/bin/
USER sandbox
ENV HOME=/sandbox
ENV PATH="/sandbox/.local/bin:${PATH}"

# Claude Code
RUN curl -fsSL https://claude.ai/install.sh | sh \
    && chmod 755 "$HOME/.local/bin/claude" \
    && (claude --version 2>/dev/null || echo "Claude Code installed")

# OpenCode
RUN cd "$HOME" \
    && curl -fsSL https://opencode.ai/install | VERSION=${OPENCODE_VERSION} bash \
    && chmod 755 "$HOME/.opencode/bin/opencode" \
    && ("$HOME/.opencode/bin/opencode" --version 2>/dev/null \
        || echo "OpenCode ${OPENCODE_VERSION} installed")
ENV PATH="/sandbox/.opencode/bin:${PATH}"

# Gemini CLI, Codex CLI, OpenClaw (npm global installs need root)
USER root
RUN npm install -g @google/gemini-cli @openai/codex openclaw 2>/dev/null \
    && (gemini --version 2>/dev/null || echo "Gemini CLI installed") \
    && (codex --version 2>/dev/null || echo "Codex CLI installed") \
    && (openclaw --version 2>/dev/null || echo "OpenClaw installed")

# Kiro CLI
USER sandbox
RUN ARCH=$(uname -m) && \
    curl --proto '=https' --tlsv1.2 -sSf \
      "https://desktop-release.q.us-east-1.amazonaws.com/latest/kirocli-${ARCH}-linux.zip" \
      -o /tmp/kirocli.zip && \
    cd /tmp && python3 -c "import zipfile; zipfile.ZipFile('kirocli.zip').extractall()" && \
    chmod +x kirocli/install.sh && ./kirocli/install.sh --no-confirm && \
    rm -rf /tmp/kirocli* && \
    (kiro --version 2>/dev/null || echo "Kiro CLI installed")

# Prepare config directories
USER root
RUN mkdir -p /sandbox/.claude /sandbox/.config /sandbox/.gemini /sandbox/.codex \
        /sandbox/.kiro /sandbox/.openclaw \
    && chown -R sandbox:sandbox /sandbox/.claude /sandbox/.config \
        /sandbox/.gemini /sandbox/.codex /sandbox/.kiro /sandbox/.openclaw

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV AI_GUARDIAN_REST_PORT=${AI_GUARDIAN_REST_PORT}
LABEL ai-guardian.daemon=true
LABEL ai-guardian.support-image=true

EXPOSE ${AI_GUARDIAN_REST_PORT}

WORKDIR /sandbox
USER sandbox

ENTRYPOINT ["entrypoint.sh"]
CMD ["bash", "-l"]
