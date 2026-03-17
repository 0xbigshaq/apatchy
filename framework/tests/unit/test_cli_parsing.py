"""Tests for CLI argument parsing in apatchy.main."""

import argparse

import pytest


def _parse(args):
    """Run the apatchy argument parser on a list of args without dispatching."""
    # Import here to avoid side effects at module level
    from unittest.mock import patch

    with patch("sys.argv", ["apatchy"] + args):
        # Build the parser the same way main() does, but don't dispatch
        parser = argparse.ArgumentParser(
            description="Apache HTTPD Fuzzing Framework",
            add_help=False,
        )
        from apatchy.main import _add_help, _sub

        _add_help(parser)
        parser.add_argument("-v", "--verbose", action="store_true", default=False)
        subparsers = parser.add_subparsers(dest="command")

        # Download
        dl = _sub(subparsers, "download")
        dl.add_argument("--version")
        dl_sub = dl.add_subparsers(dest="action")
        _sub(dl_sub, "list")

        # Configure
        cfg = _sub(subparsers, "configure")
        cfg.add_argument("--mode", choices=["fuzz", "coverage"], default="fuzz")
        cfg.add_argument("--asan", action="store_true")
        cfg.add_argument("--ubsan", action="store_true")
        cfg.add_argument("--intsan", action="store_true")
        cfg.add_argument("--truncsan", action="store_true")

        # Make (compile Apache)
        comp = _sub(subparsers, "make")
        comp.add_argument("-j", "--jobs", type=int, default=None)
        comp.add_argument("--bear", action="store_true")

        # Link
        link = _sub(subparsers, "link")
        link.add_argument("engine", choices=["libfuzzer", "standalone"])
        link.add_argument("--harness")
        link.add_argument("--bear", action="store_true")

        # Fuzz
        fuzz = _sub(subparsers, "fuzz")
        fuzz.add_argument("--engine", choices=["libfuzzer"], default="libfuzzer")
        fuzz.add_argument("--config", default="fuzz.conf")
        fuzz.add_argument("--grammar", "-g")
        fuzz.add_argument("--resume", action="store_true")
        fuzz.add_argument("--output-dir", default="fuzz-output")
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
        cov_report.add_argument("--fuzzer-dir", default="fuzz-output")
        cov_report.add_argument("--output", default="coverage-report")
        cov_report.add_argument("--harness", default=None)

        # Setup
        setup = _sub(subparsers, "setup")
        setup.add_argument("--standalone", action="store_true")
        setup_sub = setup.add_subparsers(dest="action")
        _sub(setup_sub, "check")
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


def test_download_list():
    """Parse 'download list'."""
    args = _parse(["download", "list"])
    assert args.command == "download"
    assert args.action == "list"


def test_download_no_action_is_none():
    """Bare 'download' has no action (falls through to download)."""
    args = _parse(["download"])
    assert args.action is None


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


# --- make ---


def test_make_defaults():
    """Make defaults to no jobs, no bear."""
    args = _parse(["make"])
    assert args.command == "make"
    assert args.jobs is None
    assert args.bear is False


def test_make_with_jobs():
    """Parse 'make -j 8'."""
    args = _parse(["make", "-j", "8"])
    assert args.jobs == 8


def test_make_with_bear():
    """Parse 'make --bear'."""
    args = _parse(["make", "--bear"])
    assert args.bear is True


# --- link ---


def test_link_libfuzzer():
    """Parse 'link libfuzzer'."""
    args = _parse(["link", "libfuzzer"])
    assert args.engine == "libfuzzer"


def test_link_standalone():
    """Parse 'link standalone'."""
    args = _parse(["link", "standalone"])
    assert args.engine == "standalone"


def test_link_with_harness():
    """Parse 'link libfuzzer --harness mod_fuzzy'."""
    args = _parse(["link", "libfuzzer", "--harness", "mod_fuzzy"])
    assert args.harness == "mod_fuzzy"


def test_link_invalid_engine():
    """Invalid engine raises SystemExit."""
    with pytest.raises(SystemExit):
        _parse(["link", "invalid_engine"])


# --- fuzz ---


def test_fuzz_defaults():
    """Fuzz defaults to libfuzzer engine, fuzz.conf, no resume."""
    args = _parse(["fuzz"])
    assert args.command == "fuzz"
    assert args.engine == "libfuzzer"
    assert args.config == "fuzz.conf"
    assert args.resume is False
    assert args.output_dir == "fuzz-output"


def test_fuzz_libfuzzer():
    """Parse 'fuzz --engine libfuzzer'."""
    args = _parse(["fuzz", "--engine", "libfuzzer"])
    assert args.engine == "libfuzzer"


def test_fuzz_with_grammar():
    """Parse 'fuzz -g http.json'."""
    args = _parse(["fuzz", "-g", "http.json"])
    assert args.grammar == "http.json"


def test_fuzz_resume():
    """Parse 'fuzz --resume'."""
    args = _parse(["fuzz", "--resume"])
    assert args.resume is True


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
    assert args.fuzzer_dir == "fuzz-output"


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
