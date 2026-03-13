<p align="center">
  <img src="docs/apatchy-logo-transparent.png" alt="apatchy" width="200">
</p>

<h1 align="center">apatchy</h1>

<p align="center">
  <i>An in-process fuzzing framework for Apache HTTPD</i>
  <br />
  <a href='https://pwner.gg/apatchy/'>
  <img src='https://img.shields.io/badge/docs-8A2BE2' />
  </a>
</p>

---

apatchy lets you fuzz Apache's full HTTP request processing pipeline - parsing, hooks, filters, handlers - without any network I/O. It replaces Apache's socket layer with custom I/O filters, feeding raw bytes directly into the same code paths that handle real HTTP traffic.

## Features

* Manage different build-trees & configurations 
* Coverage reports generation
* Custom Introspection: LLVM Call-tree Analysis
* Manager for: Harness, AFL++ Mutator
* Triage bugs / re-play payloads
* Profiling (kcachegrind/qcachegrind) to analyze bottlenecks in your harness logic to get better perf.
* Custom toolchain to verify depndencies 
* Compatability with older Apache versions
* 1day re-production system
* and more :D 

![main-view](docs/_static/images/introspector-mainview.png)

## Quick Start

Recommended to run this on WSL2 and/or docker container

```bash
docker build --build-arg UID=$(id -u) -t apatchy-dev .
docker run -it --rm -p 9000:9000 -v $(pwd):/repo apatchy-dev
```

then run this by the order:
```bash
# activate environment
cd framework/
uv venv .venv
uv pip install --python .venv -e ".[dev,test,docs]"
source .venv/bin/activate

# init setup (one-time)
apatchy setup check                            # verify dependencies
apatchy setup --force llvm --llvm-version 18   # install LLVM tools locally
apatchy setup --force afl                      # install AFL++ locally

# build
apatchy download          # download apache
apatchy configure         # ./configure
apatchy make --bear       # compile apache w/ compilation db
apatchy link afl --bear   # link the harness w/ compilation db

# fuzz :D 
mkdir /tmp/htdocs               # required by some configs
apatchy fuzz --config configs/rewrite.conf

# see coverage
apatchy coverage report --with-introspect --jobs 8 --config configs/rewrite.conf

# generate call tree / GUI
cd introspector/
cmake -B build/
cmake --build build/
cd ../
apatchy introspect --port 9000
```

## Documentation

>Note: **This is still in progress**/not complete. I know the CLI needs more attention.

* The documentation is live at https://pwner.gg/apatchy/
* You can generate it locally via `apatchy docs --serve`

## License

See [LICENSE](LICENSE).
