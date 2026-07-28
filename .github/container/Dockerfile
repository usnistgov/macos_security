FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN apk update && apk add --no-cache \
  python3 \
  ruby \
  git \
  ruby-dev \
  build-base \
  libjpeg-turbo \
  libpng \
  freetype \
  libxml2 \
  libxslt \
  yaml

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
    cargo

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

# Install Ruby dependencies before copying source
COPY Gemfile ./
RUN gem install bundler && bundle install

RUN apk del .build-deps

COPY . .

RUN adduser -D -u 1001 mscp && chown -R mscp:mscp /mscp && \
    chmod +x /mscp/.github/container/entrypoint.sh
USER mscp

ENTRYPOINT ["/mscp/.github/container/entrypoint.sh"]
CMD ["sh"]
