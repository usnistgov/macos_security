FROM alpine:latest

# Install required packages
RUN apk update && apk add --no-cache \
  python3 \
  ruby \
  git \
  py3-pip \
  ruby-dev \
  build-base \
  git 

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
    openblas-dev

# Set working directory
WORKDIR /mscp

# Copy MSCP code
RUN git clone --single-branch -b dev_2.0 https://github.com/usnistgov/macos_security /mscp 

# Install Python dependencies
RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

# Install Ruby dependencies
#COPY Gemfile ./
RUN gem install bundler && bundle install
RUN bundle add base64

# Clean up build dependencies
RUN apk del .build-deps

# Run a shell when container starts
CMD ["sh"]
