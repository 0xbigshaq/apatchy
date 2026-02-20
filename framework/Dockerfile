FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    wget \
    curl \
    git \
    clang \
    llvm \
    libapr1-dev \
    libaprutil1-dev \
    libpcre2-dev \
    libxml2-dev \
    libssl-dev \
    zlib1g-dev \
    # AFL++ dependencies
    afl++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install the package
RUN pip3 install .

# Set environment variables for AFL
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1

# Entry point
ENTRYPOINT ["fuzzer"]
CMD ["--help"]
