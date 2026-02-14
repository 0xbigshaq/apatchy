# Apache HTTPD Fuzzer

A modular, Python-based framework for fuzzing Apache HTTPD modules.

## Features

-   **Modular Architecture**: Separate managers for configuration, building, fuzzing, and reporting.
-   **Multi-Engine Support**: Supports AFL++ and LibFuzzer.
-   **Advanced Build Modes**: Easily switch between ASan, Coverage, and Standard builds.
-   **Rich UI**: User-friendly terminal interface.
-   **Direct Integration**: Downloads and builds Apache and APR from source.

## Installation

### For Users
To install the package system-wide or in your user library:
```bash
pip install .
```

### For Developers (Recommended)
To contribute or modify the fuzzer without reinstalling after every change, use an editable install inside a virtual environment:

```bash
# Create a virtual environment
python3 -m venv venv

# Activate it (Linux/macOS)
source venv/bin/activate

# Install in editable mode
pip install -e .
```

## Usage

```bash
# Download Apache source
fuzzer download

# Configure for fuzzing (default)
fuzzer configure

# Compile
fuzzer compile

# Build Harness (AFL mode)
fuzzer build afl

# Start Fuzzing
fuzzer fuzz
```

## Documentation

Run `fuzzer docs` to view the full documentation.
