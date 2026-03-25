"""CLI entry point for the ``apatchy`` command.

Defines all argparse sub-commands and delegates to
:class:`~apatchy.method_dispatcher.MethodDispatcher`.
"""

import argparse
import subprocess
import sys
from pathlib import Path

import argcomplete

from apatchy.method_dispatcher import MethodDispatcher
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)

_COMPLETION_DIR = Path.home() / ".local" / "share" / "bash-completion" / "completions"
_COMPLETION_FILE = _COMPLETION_DIR / "apatchy"


def _ensure_bash_completion():
    """Install bash completion script if not already present."""
    if _COMPLETION_FILE.exists():
        return
    try:
        result = subprocess.run(
            ["register-python-argcomplete", "apatchy"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout:
            _COMPLETION_DIR.mkdir(parents=True, exist_ok=True)
            _COMPLETION_FILE.write_text(result.stdout)
    except FileNotFoundError:
        pass  # argcomplete not installed globally


class _ShortHelpAction(argparse.Action):
    """Print brief help and exit (-h)."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        parser.exit()


class _VerboseHelpAction(argparse.Action):
    """Print extended help with all subcommand details (--help)."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction) and action.choices:
                print(f"\n{'-' * 60}")
                print("subcommand details:")
                print(f"{'-' * 60}")
                for name, sub in action.choices.items():
                    print(f"\n  {name}:")
                    for line in sub.format_help().splitlines():
                        print(f"    {line}")
                print()
        parser.exit()


def _add_help(parser):
    """Add split -h (brief) and --help (verbose) to a parser."""
    parser.add_argument(
        "-h",
        action=_ShortHelpAction,
        default=argparse.SUPPRESS,
        help="show this help message and exit",
    )
    parser.add_argument(
        "--help",
        action=_VerboseHelpAction,
        default=argparse.SUPPRESS,
        help="show detailed help for all subcommands and exit",
    )


def _sub(subparsers, name, **kwargs):
    """Create a subparser with split -h/--help support."""
    kwargs["add_help"] = False
    p = subparsers.add_parser(name, **kwargs)
    _add_help(p)
    return p


def main():
    """Parse CLI arguments and dispatch to :class:`MethodDispatcher`."""
    parser = argparse.ArgumentParser(
        description="Apache HTTPD Fuzzing Framework",
        add_help=False,
    )
    _add_help(parser)
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Show full build output instead of the scrolling panel",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Download
    download_parser = _sub(subparsers, "download", help="Download Apache Source")
    download_parser.add_argument("--version", help="Specific Apache version to download")
    download_sub = download_parser.add_subparsers(dest="action")
    _sub(download_sub, "list", help="List available Apache HTTPD versions")

    # Configure
    configure_parser = _sub(subparsers, "configure", help="Configure Apache (vanilla root tree)")
    configure_parser.add_argument(
        "--asan", action="store_true", help="Enable AddressSanitizer (can combine with any mode)"
    )
    configure_parser.add_argument(
        "--ubsan", action="store_true", help="Enable UndefinedBehaviorSanitizer (can combine with any mode)"
    )
    configure_parser.add_argument(
        "--ubsan-ignorelist",
        default=None,
        help="Compile-time ignorelist file for UBSan (e.g. configs/ubsan.ignorelist)",
    )
    configure_parser.add_argument(
        "--intsan", action="store_true", help="Enable unsigned-integer-overflow sanitizer (can combine with any mode)"
    )
    configure_parser.add_argument(
        "--truncsan",
        action="store_true",
        help="Enable implicit-unsigned-integer-truncation sanitizer (can combine with any mode)",
    )

    # Make (compile Apache)
    compile_parser = _sub(subparsers, "make", help="Compile Apache build tree")
    compile_parser.add_argument(
        "--tree",
        required=True,
        choices=["vanilla", "lf", "cov"],
        help="Build tree: vanilla (root), lf (libfuzzer branch), cov (coverage branch)",
    )
    compile_parser.add_argument(
        "-j", "--jobs", type=int, default=None, help="Number of parallel make jobs (default: nproc)"
    )
    compile_parser.add_argument(
        "--bear", action="store_true", help="Wrap make with bear to generate compile_commands.json"
    )

    # Link Harness
    link_parser = _sub(subparsers, "link", help="Link fuzzing harness")
    link_parser.add_argument("engine", nargs="?", choices=["libfuzzer"], default="libfuzzer", help="Fuzzing engine")
    link_parser.add_argument("--harness", help="Harness name to use (e.g. 'mod_fuzzy_proto_session')")
    link_parser.add_argument(
        "--tree", choices=["lf", "cov"], default="lf", help="Build tree to link against (default: lf)"
    )
    link_parser.add_argument("--list-harnesses", action="store_true", help="List available harnesses and exit")
    link_parser.add_argument(
        "--bear", action="store_true", help="Wrap compilation with bear to generate compile_commands.json"
    )

    # Fuzz
    fuzz_parser = _sub(subparsers, "fuzz", help="Start fuzzing")
    fuzz_parser.add_argument("--engine", choices=["libfuzzer"], default="libfuzzer", help="Fuzzing engine")
    fuzz_parser.add_argument("--config", default="fuzz.conf", help="Httpd config file to use")
    fuzz_parser.add_argument("--grammar", "-g", help="Path to grammar file (sets GRAMMAR_FILE env var)")
    fuzz_parser.add_argument("--seed-dir", default=None, help="Seed directory (default: fuzz-seeds)")
    fuzz_parser.add_argument("--resume", action="store_true", help="Resume from existing output directory")
    fuzz_parser.add_argument(
        "--output-dir", default="fuzz-output", help="Fuzzer output directory (default: fuzz-output)"
    )
    fuzz_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Per-execution timeout in seconds",
    )
    fuzz_parser.add_argument(
        "--suppress", default=None, help="UBSan suppression file (e.g. ubsan.supp). See configs/ for examples."
    )
    fuzz_parser.add_argument("--debug", action="store_true", help="Show child process output for debugging")
    fuzz_parser.add_argument(
        "--workers", "-w", type=int, default=1, help="Number of parallel workers (uses libfuzzer -fork=N)"
    )
    fuzz_parser.add_argument(
        "--pulse",
        type=int,
        default=60,
        dest="pulse_interval",
        help="Stats export interval in seconds (default: 60)",
    )

    # Triage
    triage_parser = _sub(subparsers, "triage", help="Triage crashes")
    triage_parser.add_argument("crash_file", nargs="?", default=None, help="Path to crash file to triage")
    triage_parser.add_argument(
        "--pipeline",
        default=None,
        help="Directory of numbered crash files (0, 1, 2, ...) to replay as a multi-request pipeline",
    )
    triage_parser.add_argument(
        "--bulk",
        default=None,
        help="Directory of crash files to triage individually, printing a summary table of bug types",
    )
    triage_parser.add_argument("--config", default="fuzz.conf", help="Httpd config file to use")
    triage_parser.add_argument("--no-color", action="store_true", help="Disable colored output for sanitizer reports")
    triage_parser.add_argument(
        "--timeout", type=int, default=30, help="Timeout in seconds for the harness process (default: 30)"
    )
    triage_parser.add_argument(
        "--suppress", default=None, help="UBSan suppression file (e.g. ubsan.supp). See configs/ for examples."
    )

    # Coverage
    coverage_parser = _sub(subparsers, "coverage", help="Generate coverage report")
    coverage_sub = coverage_parser.add_subparsers(dest="action")
    coverage_report = _sub(coverage_sub, "report", help="Generate HTML coverage report from corpus")
    coverage_report.add_argument(
        "--fuzzer-dir",
        default="fuzz-output",
        dest="fuzzer_dir",
        help="Fuzzer output directory (default: fuzz-output)",
    )
    coverage_report.add_argument("--config", default="fuzz.conf", help="Httpd config for corpus replay")
    coverage_report.add_argument("--output", default="coverage-report", help="Output directory for HTML report")
    coverage_report.add_argument("--harness", default=None, help="Harness to use (e.g. mod_fuzzy)")
    coverage_report.add_argument(
        "--exclude",
        default=None,
        help="Path to file containing exclude regex (passed to llvm-cov -ignore-filename-regex)",
    )
    coverage_report.add_argument(
        "--with-introspect", action="store_true", default=False, help="Emit LLVM bitcode for compiled objects"
    )
    coverage_report.add_argument(
        "--with-modules", action="store_true", default=False, help="Build coverage-instrumented external modules"
    )

    # Introspect
    introspect_parser = _sub(subparsers, "introspect", help="Merge call tree analysis with coverage data")
    introspect_parser.add_argument(
        "--entry", default=None, help="Comma-separated entry function names (e.g. main,ap_read_request)"
    )
    introspect_parser.add_argument(
        "--profdata", default=None, help="Path to merged.profdata (auto-detected from coverage-report/)"
    )
    introspect_parser.add_argument(
        "--binary", default=None, help="Path to coverage binary (auto-detected: fuzz_harness_coverage)"
    )
    introspect_parser.add_argument(
        "--bitcode", default=None, help="Path to combined.bc (auto-detected from coverage build tree)"
    )
    introspect_parser.add_argument(
        "--fuzzer-dir",
        default="fuzz-output",
        dest="fuzzer_dir",
        help="Fuzzer output directory for stat.json (default: fuzz-output)",
    )
    introspect_parser.add_argument(
        "--output", "-o", default="introspect.json", help="Output JSON file (default: introspect.json)"
    )
    introspect_parser.add_argument(
        "--no-serve", action="store_true", default=False, help="Skip launching the GUI server"
    )
    introspect_parser.add_argument("--port", type=int, default=9000, help="Port for the GUI server (default: 9000)")

    # Profile
    profile_parser = _sub(subparsers, "profile", help="Profile harness execution")
    profile_sub = profile_parser.add_subparsers(dest="action")
    profile_callgrind = _sub(profile_sub, "callgrind", help="Replay corpus under callgrind for kcachegrind")
    profile_callgrind.add_argument(
        "--fuzzer-dir",
        default="fuzz-output",
        dest="fuzzer_dir",
        help="Corpus directory (default: fuzz-output)",
    )
    profile_callgrind.add_argument("--config", default="fuzz.conf", help="Httpd config for corpus replay")
    profile_callgrind.add_argument("--output", default="callgrind-out", help="Output directory for callgrind files")
    profile_callgrind.add_argument("--harness", default=None, help="Harness to use (e.g. mod_fuzzy)")

    # Setup / toolchain
    setup_parser = _sub(subparsers, "setup", help="Manage toolchain and dependencies")
    setup_parser.add_argument(
        "--force",
        action="store_true",
        help="Download tools into toolchain/ even if system copies exist",
    )
    setup_sub = setup_parser.add_subparsers(dest="action", help="Setup sub-commands")
    _sub(setup_sub, "check", help="Check all dependency status")
    _sub(setup_sub, "libtool", help="Download libtool into toolchain/")
    llvm_sub = _sub(setup_sub, "llvm", help="Detect and suggest LLVM tool installation")
    llvm_sub.add_argument(
        "--llvm-version",
        metavar="VER",
        help="LLVM major version to use (e.g. 18). Skips clang detection.",
    )
    _sub(setup_sub, "lpm", help="Clone and build libprotobuf-mutator into toolchain/")

    # Module (external DSO modules)
    module_parser = _sub(subparsers, "module", help="Manage external Apache modules")
    module_sub = module_parser.add_subparsers(dest="action", help="Module sub-commands")
    module_build = _sub(module_sub, "build", help="Build external module as .so DSO")
    module_build.add_argument("name", nargs="?", default=None, help="Module name (builds all if omitted)")
    module_build.add_argument("--cc", default=None, help="C compiler to use (default: clang)")
    module_build.add_argument("--tree", default=None, help="Build tree suffix (e.g. lf, cov, prof)")
    _sub(module_sub, "list", help="List available external modules")

    # Dev (harness developer projects)
    dev_parser = _sub(subparsers, "dev", help="Manage developer harness projects")
    dev_sub = dev_parser.add_subparsers(dest="action", help="Dev sub-commands")
    dev_init = _sub(dev_sub, "init", help="Create a new dev harness project")
    dev_init.add_argument("name", help="Project name (e.g. 'my_header_parse')")
    dev_build = _sub(dev_sub, "build", help="Build a dev harness project")
    dev_build.add_argument("name", help="Project name to build")
    dev_build.add_argument(
        "engine",
        nargs="?",
        default="libfuzzer",
        choices=["libfuzzer", "standalone"],
        help="Fuzzing engine (default: libfuzzer)",
    )
    _sub(dev_sub, "list", help="List dev harness projects")

    # Test
    test_parser = _sub(subparsers, "test", help="Run the test suite")
    test_parser.add_argument(
        "scope",
        nargs="?",
        choices=["unit", "integration"],
        default=None,
        help="Run only unit or integration tests (default: all)",
    )
    test_parser.add_argument("-k", dest="filter_expr", default=None, help="pytest -k filter expression")
    test_parser.add_argument(
        "--version",
        dest="apache_version",
        default=None,
        help="Apache version(s) for integration tests (comma-separated, e.g. '2.4.62')",
    )
    test_parser.add_argument("--cov", action="store_true", help="Enable coverage reporting")
    test_parser.add_argument("-x", "--failfast", action="store_true", help="Stop on first failure")

    # Docs
    docs_parser = _sub(subparsers, "docs", help="Build and view Sphinx API documentation")
    docs_parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Force regeneration of Doxygen API docs (tag file, HTML, and graphs)",
    )
    docs_parser.add_argument(
        "--serve",
        nargs="?",
        const=8000,
        type=int,
        metavar="PORT",
        help="Serve docs via HTTP after building (default port: 8000)",
    )
    docs_parser.add_argument(
        "--bind", default="localhost", metavar="ADDR", help="Address to bind the HTTP server to (default: localhost)"
    )

    # Bug (1day reproduction)
    bug_parser = _sub(subparsers, "bug", help="Manage 1day bug reproductions")
    bug_sub = bug_parser.add_subparsers(dest="action", help="Bug sub-commands")
    _sub(bug_sub, "list", help="List available bug reproductions")
    bug_info = _sub(bug_sub, "info", help="Show details for a specific bug")
    bug_info.add_argument("cve_id", help="CVE identifier (e.g. CVE-2022-23943)")
    bug_setup = _sub(bug_sub, "setup", help="Download, build, and prepare a bug for reproduction")
    bug_setup.add_argument("cve_id", help="CVE identifier (e.g. CVE-2022-23943)")
    bug_reproduce = _sub(bug_sub, "reproduce", help="Reproduce a bug by triaging its seeds")
    bug_reproduce.add_argument("cve_id", help="CVE identifier (e.g. CVE-2022-23943)")
    bug_clean = _sub(bug_sub, "clean", help="Clean generated artifacts for a bug (or all bugs)")
    bug_clean.add_argument("cve_id", nargs="?", default=None, help="CVE identifier (cleans all if omitted)")

    # Clean
    clean_parser = _sub(subparsers, "clean", help="Remove build artifacts and generated files")
    clean_parser.add_argument(
        "--all", action="store_true", help="Full reset: also remove httpd source, toolchain, and test cache"
    )

    argcomplete.autocomplete(parser)
    _ensure_bash_completion()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        dispatcher = MethodDispatcher()
        dispatcher.dispatch(args)
    except KeyboardInterrupt:
        print()
        sys.exit(130)
    except Exception:
        logger.exception("An error occurred during execution")
        sys.exit(1)


if __name__ == "__main__":
    main()
