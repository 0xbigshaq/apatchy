import argparse
import sys
import argcomplete
from apache_fuzzer.utils.logger import get_logger
from apache_fuzzer.method_dispatcher import MethodDispatcher
from apache_fuzzer.config import Config

logger = get_logger(__name__)


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
        '-h', action=_ShortHelpAction,
        default=argparse.SUPPRESS,
        help='show this help message and exit',
    )
    parser.add_argument(
        '--help', action=_VerboseHelpAction,
        default=argparse.SUPPRESS,
        help='show detailed help for all subcommands and exit',
    )


def _sub(subparsers, name, **kwargs):
    """Create a subparser with split -h/--help support."""
    kwargs['add_help'] = False
    p = subparsers.add_parser(name, **kwargs)
    _add_help(p)
    return p


def main():
    parser = argparse.ArgumentParser(
        description="Apache HTTPD Fuzzing Framework",
        add_help=False,
    )
    _add_help(parser)
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Download
    download_parser = _sub(subparsers, "download", help="Download Apache Source")
    download_parser.add_argument("--version", help="Specific Apache version to download")

    # Configure
    configure_parser = _sub(subparsers, "configure", help="Configure Apache for fuzzing")
    configure_parser.add_argument("--mode", choices=["fuzz", "coverage"], default="fuzz", help="Build mode (compiler selection)")
    configure_parser.add_argument("--asan", action="store_true", help="Enable AddressSanitizer (can combine with any mode)")

    # Compile
    compile_parser = _sub(subparsers, "compile", help="Compile Apache")
    compile_parser.add_argument("--bear", action="store_true", help="Wrap make with bear to generate compile_commands.json")

    # Build Harness
    build_parser = _sub(subparsers, "build", help="Build fuzzing harness")
    build_parser.add_argument("engine", choices=["afl", "libfuzzer", "standalone"], help="Fuzzing engine")
    build_parser.add_argument("--harness", help="Harness name to use (e.g. 'full_pipeline')")
    build_parser.add_argument("--bear", action="store_true", help="Wrap compilation with bear to generate compile_commands.json")

    # Fuzz
    fuzz_parser = _sub(subparsers, "fuzz", help="Start fuzzing")
    fuzz_parser.add_argument("--engine", choices=["afl", "libfuzzer"], default="afl", help="Fuzzing engine")
    fuzz_parser.add_argument("--config", default="fuzz.conf", help="Httpd config file to use")
    fuzz_parser.add_argument("--mutator", "-m", help="Path to AFL++ custom mutator .so library")
    fuzz_parser.add_argument("--grammar", "-g", help="Path to grammar file (sets GRAMMAR_FILE env var)")
    fuzz_parser.add_argument("--resume", action="store_true", help="Resume from existing AFL output directory")
    fuzz_parser.add_argument("--output-dir", default="afl-output", help="AFL output directory (default: afl-output)")
    fuzz_parser.add_argument("--role", choices=["main", "secondary"], default=None,
                             help="AFL parallel mode: 'main' (-M) or 'secondary' (-S) instance")
    fuzz_parser.add_argument("--name", default=None,
                             help="AFL instance name for parallel mode (default: main01/sec01)")

    # Triage
    triage_parser = _sub(subparsers, "triage", help="Triage crashes")
    triage_parser.add_argument("crash_file", help="Path to crash file to triage")
    triage_parser.add_argument("--config", default="fuzz.conf", help="Httpd config file to use")

    # Coverage
    coverage_parser = _sub(subparsers, "coverage", help="Generate coverage report")
    coverage_sub = coverage_parser.add_subparsers(dest="action")
    coverage_report = _sub(coverage_sub, "report", help="Generate HTML coverage report from AFL corpus")
    coverage_report.add_argument("--afl-dir", default="afl-output", help="AFL output directory")
    coverage_report.add_argument("--config", default="fuzz.conf", help="Httpd config for corpus replay")
    coverage_report.add_argument("--output", default="coverage-report", help="Output directory for HTML report")

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
        "--standalone", action="store_true",
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
    harness_use.add_argument("name", help="Harness name (e.g. 'full_pipeline')")

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
    dev_build.add_argument("engine", nargs="?", default="standalone",
                           choices=["afl", "libfuzzer", "standalone"],
                           help="Fuzzing engine (default: standalone)")
    _sub(dev_sub, "list", help="List dev harness projects")

    # Docs
    _sub(subparsers, "docs", help="View documentation")

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        dispatcher = MethodDispatcher()
        dispatcher.dispatch(args)
    except Exception as e:
        logger.exception("An error occurred during execution")
        sys.exit(1)

if __name__ == "__main__":
    main()
