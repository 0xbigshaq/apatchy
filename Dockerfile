FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    make \
    pkg-config \
    autoconf \
    libtool \
    python3 \
    python3-pip \
    python3-venv \
    wget \
    curl \
    git \
    lsb-release \
    software-properties-common \
    gnupg \
    sudo \
    valgrind \
    libpcre2-dev \
    zlib1g-dev \
    libxml2-dev \
    libexpat1-dev \
    uuid-dev \
    libssl-dev \
    libapr1-dev \
    libaprutil1-dev \
    cmake \
    bear \
    doxygen \
    graphviz \
    lcov \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install uv

RUN useradd -m -s /bin/bash meow && \
    echo "meow ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER meow

ENV NVM_DIR=/home/meow/.nvm

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash && \
    . "$NVM_DIR/nvm.sh" && nvm install 22 && nvm alias default 22

ENV PATH="$NVM_DIR/versions/node/v22/bin:$PATH"


WORKDIR /repo

ENTRYPOINT ["/bin/bash"]
