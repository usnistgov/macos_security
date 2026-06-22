FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d

# Install required packages
RUN apk update && apk add --no-cache \
  python3 \
  ruby \
  git \
  py3-pip \
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

# Set working directory
WORKDIR /mscp

# Copy MSCP code from build context
COPY . .

# Install Python dependencies
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# Install Ruby dependencies
#COPY Gemfile ./
RUN gem install bundler && bundle install
RUN bundle add base64

# Clean up build dependencies
RUN apk del .build-deps

# Run as non-root user
RUN adduser -D -u 1001 mscp && chown -R mscp:mscp /mscp
USER mscp

# Run a shell when container starts
CMD ["sh"]
