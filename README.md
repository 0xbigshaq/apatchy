<p align="center">
  <img src="docs/apatchy-logo-transparent.png" alt="apatchy" width="200">
</p>

<h1 align="center">apatchy</h1>

<p align="center">
  <strong>An in-process fuzzing framework for Apache HTTPD</strong>
</p>

---

apatchy lets you fuzz Apache's full HTTP request processing pipeline - parsing, hooks, filters, handlers - without any network I/O. It replaces Apache's socket layer with custom I/O filters, feeding raw bytes directly into the same code paths that handle real HTTP traffic.

## Quick Start

```bash
cd framework

apatchy setup check              # verify dependencies
apatchy setup afl                # install AFL++ locally

apatchy download --version 2.4.62
apatchy configure
apatchy make

apatchy link afl                # link the harness
apatchy fuzz --config rewrite.conf
```

## Documentation

Full docs live in [`docs/`](docs/README.md) - architecture, Apache internals, CLI reference, and guides for targeting specific modules.

## License

See [LICENSE](LICENSE).
