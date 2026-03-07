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
    configure_parser = _sub(subparsers, "configure", help="Configure Apache for fuzzing")
    configure_parser.add_argument(
        "--mode", choices=["fuzz", "coverage"], default="fuzz", help="Build mode (compiler selection)"
    )
    configure_parser.add_argument(
        "--asan", action="store_true", help="Enable AddressSanitizer (can combine with any mode)"
    )
    configure_parser.add_argument(
        "--ubsan", action="store_true", help="Enable UndefinedBehaviorSanitizer (can combine with any mode)"
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
    compile_parser = _sub(subparsers, "make", help="Compile Apache")
    compile_parser.add_argument(
        "-j", "--jobs", type=int, default=None, help="Number of parallel make jobs (default: nproc)"
    )
    compile_parser.add_argument(
        "--bear", action="store_true", help="Wrap make with bear to generate compile_commands.json"
    )

    # Link Harness
    link_parser = _sub(subparsers, "link", help="Link fuzzing harness")
    link_parser.add_argument("engine", choices=["afl", "libfuzzer", "standalone"], help="Fuzzing engine")
    link_parser.add_argument("--harness", help="Harness name to use (e.g. 'mod_fuzzy')")
    link_parser.add_argument(
        "--bear", action="store_true", help="Wrap compilation with bear to generate compile_commands.json"
    )

    # Fuzz
    fuzz_parser = _sub(subparsers, "fuzz", help="Start fuzzing")
    fuzz_parser.add_argument("--engine", choices=["afl", "libfuzzer"], default="afl", help="Fuzzing engine")
    fuzz_parser.add_argument("--config", default="fuzz.conf", help="Httpd config file to use")
    fuzz_parser.add_argument("--mutator", "-m", help="Path to AFL++ custom mutator .so library")
    fuzz_parser.add_argument("--grammar", "-g", help="Path to grammar file (sets GRAMMAR_FILE env var)")
    fuzz_parser.add_argument("--resume", action="store_true", help="Resume from existing AFL output directory")
    fuzz_parser.add_argument("--output-dir", default="afl-output", help="AFL output directory (default: afl-output)")
    fuzz_parser.add_argument(
        "--role",
        choices=["main", "secondary"],
        default=None,
        help="AFL parallel mode: 'main' (-M) or 'secondary' (-S) instance",
    )
    fuzz_parser.add_argument("--name", default=None, help="AFL instance name for parallel mode (default: main01/sec01)")
    fuzz_parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Per-execution timeout in seconds (AFL -t flag). Default: let AFL auto-calibrate.",
    )
    fuzz_parser.add_argument(
        "--suppress", default=None, help="UBSan suppression file (e.g. ubsan.supp). See configs/ for examples."
    )
    fuzz_parser.add_argument(
        "--debug", action="store_true", help="Show AFL++ child process output for debugging/troubleshooting purposes"
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
    coverage_report = _sub(coverage_sub, "report", help="Generate HTML coverage report from AFL corpus")
    coverage_report.add_argument("--afl-dir", default="afl-output", help="AFL output directory")
    coverage_report.add_argument("--config", default="fuzz.conf", help="Httpd config for corpus replay")
    coverage_report.add_argument("--output", default="coverage-report", help="Output directory for HTML report")
    coverage_report.add_argument("--harness", default=None, help="Harness to use (e.g. mod_fuzzy)")

    # Grammar mutator
    grammar_parser = _sub(subparsers, "grammar", help="Manage AFL++ grammar mutators")
    grammar_sub = grammar_parser.add_subparsers(dest="action", help="Grammar sub-commands")
    _sub(grammar_sub, "setup", help="Clone AFL++, init submodule, download antlr4")
    grammar_build = _sub(grammar_sub, "build", help="Build grammar mutator .so for a grammar")
    grammar_build.add_argument("grammar_name", help="Name of grammar (e.g. 'http')")
    _sub(grammar_sub, "status", help="Show grammar mutator setup/build status")
    _sub(grammar_sub, "list", help="List available grammar JSON files")

    # Custom mutator
    mutator_parser = _sub(subparsers, "mutator", help="Manage custom mutators")
    mutator_sub = mutator_parser.add_subparsers(dest="action", help="Mutator sub-commands")
    mutator_build = _sub(mutator_sub, "build", help="Build custom mutator .so from .c source")
    mutator_build.add_argument("name", nargs="?", default=None, help="Mutator name (builds all if omitted)")
    _sub(mutator_sub, "list", help="List available custom mutators")

    # Setup / toolchain
    setup_parser = _sub(subparsers, "setup", help="Manage toolchain and dependencies")
    setup_parser.add_argument(
        "--standalone",
        action="store_true",
        help="Download tools into toolchain/ even if system copies exist",
    )
    setup_sub = setup_parser.add_subparsers(dest="action", help="Setup sub-commands")
    _sub(setup_sub, "check", help="Check all dependency status")
    _sub(setup_sub, "afl", help="Clone and build AFL++ into toolchain/")
    _sub(setup_sub, "llvm", help="Detect and suggest LLVM tool installation")

    # Harness
    harness_parser = _sub(subparsers, "harness", help="Manage fuzzing harnesses")
    harness_sub = harness_parser.add_subparsers(dest="action")
    _sub(harness_sub, "list", help="List available harnesses")
    harness_use = _sub(harness_sub, "use", help="Select a harness for building")
    harness_use.add_argument("name", help="Harness name (e.g. 'mod_fuzzy')")

    # Module (external DSO modules)
    module_parser = _sub(subparsers, "module", help="Manage external Apache modules")
    module_sub = module_parser.add_subparsers(dest="action", help="Module sub-commands")
    module_build = _sub(module_sub, "build", help="Build external module as .so DSO")
    module_build.add_argument("name", nargs="?", default=None, help="Module name (builds all if omitted)")
    module_build.add_argument("--cc", default=None, help="C compiler to use (default: afl-clang-fast)")
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
        default="standalone",
        choices=["afl", "libfuzzer", "standalone"],
        help="Fuzzing engine (default: standalone)",
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
