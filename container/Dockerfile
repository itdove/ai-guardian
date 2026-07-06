# ai-guardian container image
#
# UBI-based container with ai-guardian and all headless-capable IDEs.
# Published to quay.io/itdove/ai-guardian on every merge and release.
#
# Pull:
#   podman pull quay.io/itdove/ai-guardian:latest
#   podman pull quay.io/itdove/ai-guardian:dev
#
# Build locally:
#   Podman: podman build -t ai-guardian container/
#   Docker:  docker build -t ai-guardian container/
#   Podman: podman build --build-arg AI_GUARDIAN_VERSION=1.13.0 -t ai-guardian container/
#   Docker:  docker build --build-arg AI_GUARDIAN_VERSION=1.13.0 -t ai-guardian container/
#
# Run:
#   Podman: podman run -it -p 63152 ai-guardian-support
#   Docker:  docker run -it -p 63152 ai-guardian-support
#
#   With IDE:
#   Podman: podman run -it -p 63152 -e AI_GUARDIAN_IDE=opencode ai-guardian-support
#   Docker:  docker run -it -p 63152 -e AI_GUARDIAN_IDE=opencode ai-guardian-support
#
#   Find mapped port:
#   Podman: podman port <container-name>
#   Docker:  docker port <container-name>
#
# Using run.sh (handles both engines):
#   ./container/run.sh                         # uses podman by default
#   CONTAINER_ENGINE=docker ./container/run.sh # use docker instead
#
# Local wheel:
#   python -m build --wheel && cp dist/ai_guardian-*.whl container/vendor/
#   podman build --build-arg AI_GUARDIAN_VERSION=ai_guardian-1.13.0.dev0-py3-none-any.whl -t ai-guardian container/

FROM registry.access.redhat.com/ubi10/ubi-minimal:latest

ARG AI_GUARDIAN_VERSION=1.13.1
ARG AI_GUARDIAN_REST_PORT=63152
ARG UV_VERSION=0.11.16
ARG OPENCODE_VERSION=1.17.3
ARG GH_VERSION=2.74.1
ARG GLAB_VERSION=1.91.0

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

# Claude Code is proprietary (All Rights Reserved) — installed at runtime
# with user ToS consent via entrypoint.sh, not at build time.

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

# Forge CLIs — gh and glab for issue tracker integration
USER root
RUN ARCH=$(uname -m | sed 's/aarch64/arm64/;s/x86_64/amd64/') \
    \
    # glab CLI
    && curl -fsSL -o /tmp/glab.tar.gz \
        "https://gitlab.com/gitlab-org/cli/-/releases/v${GLAB_VERSION}/downloads/glab_${GLAB_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -xzf /tmp/glab.tar.gz -C /usr/local bin/glab \
    && rm /tmp/glab.tar.gz \
    \
    # gh CLI (with checksum verification)
    && TARBALL="gh_${GH_VERSION}_linux_${ARCH}.tar.gz" \
    && curl -fsSL -o "/tmp/${TARBALL}" \
        "https://github.com/cli/cli/releases/download/v${GH_VERSION}/${TARBALL}" \
    && curl -fsSL -o /tmp/gh_checksums.txt \
        "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_checksums.txt" \
    && cd /tmp && grep -F " ${TARBALL}" gh_checksums.txt | sha256sum -c - \
    && tar -xzf "/tmp/${TARBALL}" -C /usr/local/bin --strip-components=2 \
        "gh_${GH_VERSION}_linux_${ARCH}/bin/gh" \
    && ln -sf /usr/local/bin/gh /usr/bin/gh \
    && rm "/tmp/${TARBALL}" /tmp/gh_checksums.txt \
    \
    && (gh --version 2>/dev/null || echo "gh CLI installed") \
    && (glab --version 2>/dev/null || echo "glab CLI installed")

# Kiro CLI is AWS proprietary — installed at runtime with user ToS
# consent via entrypoint.sh, not at build time.

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
