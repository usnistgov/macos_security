FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN apk update && apk add --no-cache \
  python3 \
  git \
  build-base \
  libjpeg-turbo \
  libpng \
  freetype \
  libxml2 \
  libxslt \
  yaml \
  perl \
  openssl

RUN apk add --no-cache --virtual .build-deps \
    musl-dev \
    linux-headers \
    g++ \
    gcc \
    zlib-dev \
    make \
    python3-dev \
    jpeg-dev \
    freetype-dev \
    libpng-dev \
    openblas-dev \
    libxml2-dev \
    libxslt-dev \
    yaml-dev \
    rust \
    cargo \
    openssl-dev \
    pkgconfig

ARG BUILD_SHA=unknown
ARG IMAGE_REPO=unknown
ARG IMAGE_TAG=latest
ENV MSCP_BUILD_SHA=${BUILD_SHA}
ENV MSCP_IMAGE_REPO=${IMAGE_REPO}
ENV MSCP_IMAGE_TAG=${IMAGE_TAG}

WORKDIR /mscp

# Install Python dependencies before copying source (layer cache is not invalidated by code changes)
COPY requirements.txt ./
RUN uv venv /opt/venv && \
    uv pip install --no-cache --python /opt/venv/bin/python -r requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

RUN apk del .build-deps

COPY . .

RUN adduser -D -u 1001 mscp && chown -R mscp:mscp /mscp && \
    chmod +x /mscp/.github/container/entrypoint.sh
USER mscp

ENTRYPOINT ["/mscp/.github/container/entrypoint.sh"]
CMD ["sh"]
