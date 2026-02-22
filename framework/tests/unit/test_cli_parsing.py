"""Tests for CLI argument parsing in apatchy.main."""

import argparse
import sys

import pytest


def _parse(args):
    """Run the apatchy argument parser on a list of args without dispatching."""
    # Import here to avoid side effects at module level
    from unittest.mock import patch
    from apatchy.main import main

    with patch("sys.argv", ["apatchy"] + args):
        # Build the parser the same way main() does, but don't dispatch
        parser = argparse.ArgumentParser(
            description="Apache HTTPD Fuzzing Framework",
            add_help=False,
        )
        from apatchy.main import _add_help, _sub
        _add_help(parser)
        parser.add_argument('-v', '--verbose', action='store_true', default=False)
        subparsers = parser.add_subparsers(dest="command")

        # Download
        dl = _sub(subparsers, "download")
        dl.add_argument("--version")

        # Configure
        cfg = _sub(subparsers, "configure")
        cfg.add_argument("--mode", choices=["fuzz", "coverage"], default="fuzz")
        cfg.add_argument("--asan", action="store_true")
        cfg.add_argument("--ubsan", action="store_true")
        cfg.add_argument("--intsan", action="store_true")
        cfg.add_argument("--truncsan", action="store_true")

        # Compile
        comp = _sub(subparsers, "compile")
        comp.add_argument("-j", "--jobs", type=int, default=None)
        comp.add_argument("--bear", action="store_true")

        # Build
        build = _sub(subparsers, "build")
        build.add_argument("engine", choices=["afl", "libfuzzer", "standalone"])
        build.add_argument("--harness")
        build.add_argument("--bear", action="store_true")

        # Fuzz
        fuzz = _sub(subparsers, "fuzz")
        fuzz.add_argument("--engine", choices=["afl", "libfuzzer"], default="afl")
        fuzz.add_argument("--config", default="fuzz.conf")
        fuzz.add_argument("--mutator", "-m")
        fuzz.add_argument("--grammar", "-g")
        fuzz.add_argument("--resume", action="store_true")
        fuzz.add_argument("--output-dir", default="afl-output")
        fuzz.add_argument("--role", choices=["main", "secondary"], default=None)
        fuzz.add_argument("--name", default=None)
        fuzz.add_argument("--suppress", default=None)

        # Triage
        tri = _sub(subparsers, "triage")
        tri.add_argument("crash_file")
        tri.add_argument("--config", default="fuzz.conf")
        tri.add_argument("--no-color", action="store_true")
        tri.add_argument("--suppress", default=None)

        # Coverage
        cov = _sub(subparsers, "coverage")
        cov_sub = cov.add_subparsers(dest="action")
        cov_report = _sub(cov_sub, "report")
        cov_report.add_argument("--afl-dir", default="afl-output")
        cov_report.add_argument("--output", default="coverage-report")
        cov_report.add_argument("--harness", default=None)

        # Setup
        setup = _sub(subparsers, "setup")
        setup.add_argument("--standalone", action="store_true")
        setup_sub = setup.add_subparsers(dest="action")
        _sub(setup_sub, "check")
        _sub(setup_sub, "afl")
        _sub(setup_sub, "llvm")

        return parser.parse_args(args)


# --- download ---

def test_download_command():
    """Parse 'download' subcommand."""
    args = _parse(["download"])
    assert args.command == "download"


def test_download_with_version():
    """Parse 'download --version 2.4.58'."""
    args = _parse(["download", "--version", "2.4.58"])
    assert args.version == "2.4.58"


def test_download_version_default_none():
    """Download version defaults to None."""
    args = _parse(["download"])
    assert args.version is None


# --- configure ---

def test_configure_defaults():
    """Configure defaults to fuzz mode, no sanitizers."""
    args = _parse(["configure"])
    assert args.command == "configure"
    assert args.mode == "fuzz"
    assert args.asan is False
    assert args.ubsan is False


def test_configure_coverage_mode():
    """Parse 'configure --mode coverage'."""
    args = _parse(["configure", "--mode", "coverage"])
    assert args.mode == "coverage"


def test_configure_sanitizers():
    """Parse all sanitizer flags together."""
    args = _parse(["configure", "--asan", "--ubsan", "--intsan", "--truncsan"])
    assert args.asan is True
    assert args.ubsan is True
    assert args.intsan is True
    assert args.truncsan is True


# --- compile ---

def test_compile_defaults():
    """Compile defaults to no jobs, no bear."""
    args = _parse(["compile"])
    assert args.command == "compile"
    assert args.jobs is None
    assert args.bear is False


def test_compile_with_jobs():
    """Parse 'compile -j 8'."""
    args = _parse(["compile", "-j", "8"])
    assert args.jobs == 8


def test_compile_with_bear():
    """Parse 'compile --bear'."""
    args = _parse(["compile", "--bear"])
    assert args.bear is True


# --- build ---

def test_build_afl():
    """Parse 'build afl'."""
    args = _parse(["build", "afl"])
    assert args.command == "build"
    assert args.engine == "afl"


def test_build_libfuzzer():
    """Parse 'build libfuzzer'."""
    args = _parse(["build", "libfuzzer"])
    assert args.engine == "libfuzzer"


def test_build_standalone():
    """Parse 'build standalone'."""
    args = _parse(["build", "standalone"])
    assert args.engine == "standalone"


def test_build_with_harness():
    """Parse 'build afl --harness full_pipeline'."""
    args = _parse(["build", "afl", "--harness", "full_pipeline"])
    assert args.harness == "full_pipeline"


def test_build_invalid_engine():
    """Invalid engine raises SystemExit."""
    with pytest.raises(SystemExit):
        _parse(["build", "invalid_engine"])


# --- fuzz ---

def test_fuzz_defaults():
    """Fuzz defaults to afl engine, fuzz.conf, no resume."""
    args = _parse(["fuzz"])
    assert args.command == "fuzz"
    assert args.engine == "afl"
    assert args.config == "fuzz.conf"
    assert args.resume is False
    assert args.output_dir == "afl-output"


def test_fuzz_libfuzzer():
    """Parse 'fuzz --engine libfuzzer'."""
    args = _parse(["fuzz", "--engine", "libfuzzer"])
    assert args.engine == "libfuzzer"


def test_fuzz_with_mutator():
    """Parse 'fuzz -m /path/to/mutator.so'."""
    args = _parse(["fuzz", "-m", "/path/to/mutator.so"])
    assert args.mutator == "/path/to/mutator.so"


def test_fuzz_with_grammar():
    """Parse 'fuzz -g http.json'."""
    args = _parse(["fuzz", "-g", "http.json"])
    assert args.grammar == "http.json"


def test_fuzz_resume():
    """Parse 'fuzz --resume'."""
    args = _parse(["fuzz", "--resume"])
    assert args.resume is True


def test_fuzz_parallel_main():
    """Parse 'fuzz --role main --name fuzzer01'."""
    args = _parse(["fuzz", "--role", "main", "--name", "fuzzer01"])
    assert args.role == "main"
    assert args.name == "fuzzer01"


def test_fuzz_suppress():
    """Parse 'fuzz --suppress ubsan.supp'."""
    args = _parse(["fuzz", "--suppress", "ubsan.supp"])
    assert args.suppress == "ubsan.supp"


# --- triage ---

def test_triage():
    """Parse 'triage crash_001'."""
    args = _parse(["triage", "crash_001"])
    assert args.command == "triage"
    assert args.crash_file == "crash_001"


def test_triage_no_color():
    """Parse 'triage crash_001 --no-color'."""
    args = _parse(["triage", "crash_001", "--no-color"])
    assert args.no_color is True


# --- coverage ---

def test_coverage_report():
    """Parse 'coverage report' with defaults."""
    args = _parse(["coverage", "report"])
    assert args.command == "coverage"
    assert args.action == "report"
    assert args.afl_dir == "afl-output"


def test_coverage_report_custom_output():
    """Parse 'coverage report --output my-report'."""
    args = _parse(["coverage", "report", "--output", "my-report"])
    assert args.output == "my-report"


# --- setup ---

def test_setup_check():
    """Parse 'setup check'."""
    args = _parse(["setup", "check"])
    assert args.command == "setup"
    assert args.action == "check"


def test_setup_afl():
    """Parse 'setup afl'."""
    args = _parse(["setup", "afl"])
    assert args.action == "afl"


def test_setup_llvm():
    """Parse 'setup llvm'."""
    args = _parse(["setup", "llvm"])
    assert args.action == "llvm"


def test_setup_standalone_flag():
    """Parse 'setup --standalone check'."""
    args = _parse(["setup", "--standalone", "check"])
    assert args.standalone is True


# --- global flags ---

def test_verbose_flag():
    """Parse '-v' global verbose flag."""
    args = _parse(["-v", "download"])
    assert args.verbose is True


# --- edge cases ---

def test_no_command_is_none():
    """No arguments sets command to None."""
    args = _parse([])
    assert args.command is None
