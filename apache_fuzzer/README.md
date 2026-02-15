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

## Resuming a Fuzzing Session

After stopping a fuzzer with Ctrl+C, resume from where it left off using `--resume`:

```bash
fuzzer fuzz --resume --output-dir out-afl-mod-crypt-1 \
  --config configs/crypto-fuzz.conf \
  -g src/apache_fuzzer/grammars/http_session_crypto.json \
  --mutator path/to/libgrammarmutator.so
```

This sets `AFL_AUTORESUME=1` so AFL++ picks up the existing corpus and state.

## Parallel Fuzzing (AFL++)

Run multiple AFL++ instances in parallel with automatic corpus synchronization using `--role` and `--name`.

### Starting from a previous solo run

If you have an existing output directory from a solo run (e.g. `out-afl-1/default/`), resume it as the main parallel instance:

```bash
# Terminal 1 - main instance (inherits existing corpus)
fuzzer fuzz --resume --role main --name main01 --output-dir out-afl-1 ...
```

The CLI will detect the existing `default/` directory and prompt you to rename it to `main01/` so AFL++ can use it in parallel mode. Your corpus is preserved - just under the new name.

### Launching secondary instances

In separate terminals, add secondary instances that share the same `--output-dir`:

```bash
# Terminal 2
fuzzer fuzz --role secondary --name sec01 --output-dir out-afl-1 ...

# Terminal 3
fuzzer fuzz --role secondary --name sec02 --output-dir out-afl-1 ...
```

AFL++ automatically synchronizes the corpus between all instances. Secondaries will immediately pick up the main's queue entries and contribute their own findings back.

### Starting fresh with parallel from the beginning

```bash
# Terminal 1 - main
fuzzer fuzz --role main --output-dir out-parallel ...

# Terminal 2 - secondary
fuzzer fuzz --role secondary --name sec01 --output-dir out-parallel ...
```

When `--name` is omitted, it defaults to `main01` for main and `sec01` for secondary.

> **Note:** `--role` and `--name` are only supported with `--engine afl` (the default).

## Documentation

Run `fuzzer docs` to view the full documentation.
