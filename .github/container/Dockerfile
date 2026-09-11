# syntax=docker/dockerfile:1

# Debian slim (glibc) base so pip/uv install prebuilt manylinux wheels for
# numpy / pandas / pydantic-core / lxml / pillow / typst. Nothing compiles
# from source, so there is no build toolchain to install and later delete,
# and each architecture is built natively in CI (no QEMU emulation).
FROM python:3.13-slim-bookworm@sha256:ed86c82274b3c69b52fb5820f358f0bd7df0b603332063cb5c6e32bd220c3e6e

# Pinned uv (never :latest) so this layer is reproducible and cache-stable.
COPY --from=ghcr.io/astral-sh/uv:0.9.5@sha256:f459f6f73a8c4ef5d69f4e6fbbdb8af751d6fa40ec34b39a1ab469acd6e289b7 /uv /usr/local/bin/uv

# bash + bash-completion: Debian's /bin/sh is dash (no history, no tab
# completion). This image is used interactively, so make bash the default shell.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git \
      ca-certificates \
      bash \
      bash-completion \
  && rm -rf /var/lib/apt/lists/*

ARG BUILD_SHA=unknown
ARG IMAGE_REPO=unknown
ARG IMAGE_TAG=latest
ENV MSCP_BUILD_SHA=${BUILD_SHA} \
    MSCP_IMAGE_REPO=${IMAGE_REPO} \
    MSCP_IMAGE_TAG=${IMAGE_TAG}

WORKDIR /mscp

# Install Python dependencies before copying source so the layer cache is not
# invalidated by code changes.
COPY requirements.txt ./
RUN uv venv /opt/venv && \
    uv pip install --no-cache --python /opt/venv/bin/python -r requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

COPY . .

RUN useradd -m -u 1001 -s /bin/bash mscp && \
    printf '%s\n' \
      "[ -f /usr/share/bash-completion/bash_completion ] && . /usr/share/bash-completion/bash_completion" \
      "export PATH=/opt/venv/bin:\$PATH" \
      "PS1='mscp \\\$ '" \
      > /home/mscp/.bashrc && \
    chown -R mscp:mscp /mscp /home/mscp && \
    chmod +x /mscp/.github/container/entrypoint.sh
USER mscp

ENTRYPOINT ["/mscp/.github/container/entrypoint.sh"]
CMD ["bash"]
