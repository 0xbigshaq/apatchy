# Apatchy - Apache HTTPD Fuzzer

A modular, Python-based framework for fuzzing Apache HTTPD modules. For the full project documentation - how it works, getting started, architecture - see the [docs/](../docs/README.md) directory.

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

## Resuming a Fuzzing Session

After stopping the fuzzer with Ctrl+C, resume from where it left off using `--resume`:

```bash
apatchy fuzz --resume --output-dir fuzz-output \
  --config configs/crypto-fuzz.conf \
  -g src/apatchy/grammars/http_session_crypto.json
```

