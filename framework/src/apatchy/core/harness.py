"""Build, link, and manage fuzzing harness binaries.

:class:`HarnessBuilder` compiles ``fuzz_harness.c`` against the Apache
build tree and links it with all statically-built modules, producing a
self-contained binary for AFL++, LibFuzzer, or standalone execution.
"""

import os
import re
import shutil
from pathlib import Path
from apatchy.utils.logger import get_logger
from apatchy.config import Config
from apatchy.core.process_runner import ProcessRunner

logger = get_logger(__name__)

#: Compiler selection per build mode.
COMPILERS = {
    "afl": "afl-clang-fast",
    "libfuzzer": "clang",
    "standalone": "clang",
    "coverage": "clang",
}


class HarnessBuilder:
    """Compile and link a fuzzing harness against an Apache build tree.

    Parameters
    ----------
    httpd_root : Path
        Root of the configured/compiled Apache HTTPD source tree.
    """

    def __init__(self, httpd_root, verbose: bool = False):
        self.httpd_root = httpd_root
        self.logger = logger
        self.runner = ProcessRunner(verbose=verbose)
        self.libtool = self.httpd_root / "srclib" / "apr" / "libtool"

    @staticmethod
    def list_harnesses():
        """List available harness files with their descriptions."""
        harnesses = []
        for path in sorted(Config.HARNESSES_DIR.glob("*.c")):
            desc = ""
            try:
                with open(path) as f:
                    for line in f:
                        m = re.search(r'@description:\s*(.+)', line)
                        if m:
                            desc = m.group(1).strip()
                            break
            except OSError:
                pass
            harnesses.append({"name": path.stem, "source": str(path), "description": desc})
        return harnesses

    @staticmethod
    def resolve_harness(name):
        """Resolve a harness name to a file path.

        Resolution order:
        - Bundled: HARNESSES_DIR/<name>.c
        - Literal path: <name> as file path
        3. Work dir: WORK_DIR/<name>.c
        """
        # Bundled
        bundled = Config.HARNESSES_DIR / f"{name}.c"
        if bundled.exists():
            return bundled
        # Literal path
        literal = Path(name)
        if literal.exists():
            return literal
        # 3. Work dir
        work = Config.WORK_DIR / f"{name}.c"
        if work.exists():
            return work
        return None

    @staticmethod
    def use_harness(name):
        """Copy a harness to the CWD as fuzz_harness.c."""
        path = HarnessBuilder.resolve_harness(name)
        if not path:
            raise FileNotFoundError(f"Harness '{name}' not found")
        dest = Path("fuzz_harness.c")
        shutil.copy(path, dest)
        logger.info(f"Using harness: {path.name} -> {dest}")
        return dest

    def build(self, mode="standalone", cflags="", ldflags="", harness_name=None, cc=None, bear=False):
        """Compile and link the harness for the given fuzzing engine.

        Parameters
        ----------
        mode : str
            One of ``"afl"``, ``"libfuzzer"``, ``"standalone"``, or
            ``"coverage"``.
        cflags : str
            Extra compiler flags.
        ldflags : str
            Extra linker flags.
        harness_name : str, optional
            Name of a bundled harness to copy before building.
        cc : str, optional
            Override the compiler (defaults to :data:`COMPILERS` lookup).
        bear : bool
            Wrap compilation with ``bear`` for ``compile_commands.json``.
        """
        output_name = f"fuzz_harness_{mode}"
        if cc is None:
            cc = COMPILERS.get(mode, "clang")

        if not shutil.which(cc):
            self.logger.error(f"Compiler '{cc}' not found. Is AFL++ installed?")
            raise FileNotFoundError(f"{cc} not found in PATH")

        self.logger.info(f"Using compiler: {cc}")

        # Propagate sanitizer flags from Apache's config_vars.mk so the
        # harness objects are compiled with the same sanitizer as Apache.
        config_vars = self._parse_config_vars()
        for key in ("CFLAGS", "LDFLAGS"):
            for token in config_vars.get(key, "").split():
                if token.startswith("-fsanitize="):
                    if token not in cflags:
                        cflags = f"{cflags} {token}"
                    if token not in ldflags:
                        ldflags = f"{ldflags} {token}"

        # Add mode-specific defines so the harness compiles the right entry point
        if mode == "afl":
            cflags = f"-DAFL_FUZZ {cflags}"
        elif mode == "libfuzzer":
            cflags = f"-DLIBFUZZER {cflags}"

        # If a harness name was provided, copy it to CWD first
        if harness_name:
            self.use_harness(harness_name)

        # Ensure harness source exists
        src = Path("fuzz_harness.c")
        if not src.exists():
            # Default to uri_parse harness
            default_harness = Config.HARNESSES_DIR / "uri_parse.c"
            if default_harness.exists():
                 self.logger.info(f"Copying default harness from {default_harness}")
                 shutil.copy(default_harness, src)
            else:
                 self.logger.error("fuzz_harness.c not found and no default harness available!")
                 raise FileNotFoundError("fuzz_harness.c not found")

        # If the harness uses fuzz_common.h, copy companion files before compiling
        has_fuzz_common = False
        harness_text = Path("fuzz_harness.c").read_text()
        if '"fuzz_common.h"' in harness_text:
            for companion in ("fuzz_common.c", "fuzz_common.h"):
                companion_src = Config.HARNESSES_DIR / companion
                companion_dest = Path(companion)
                if companion_src.exists() and not companion_dest.exists():
                    shutil.copy(companion_src, companion_dest)
                    self.logger.info(f"Copied companion: {companion}")
            has_fuzz_common = True

        # Compile harness object
        self._compile_object("fuzz_harness.c", "fuzz_harness.lo", cflags, cc, bear=bear)

        # Compile fuzz_common if needed
        if has_fuzz_common:
            self._compile_object("fuzz_common.c", "fuzz_common.lo", cflags, cc, bear=bear)

        # Compile buildmark.c (provides ap_get_server_built)
        buildmark_src = self.httpd_root / "server" / "buildmark.c"
        self._compile_object(str(buildmark_src), "buildmark.lo", cflags, cc, bear=bear)

        # Compile modules.c (provides ap_prelinked_modules, ap_prelinked_module_symbols)
        modules_src = self.httpd_root / "modules.c"
        if modules_src.exists():
            self._compile_object(str(modules_src), "modules.lo", cflags, cc, bear=bear)

        # All harness modes provide their own main() which conflicts with
        # Apache's main() in libmain.a. Use -z muldefs to allow both;
        # our object file main() wins over the archive's.
        allow_muldefs = mode in ("afl", "libfuzzer", "standalone")

        # Coverage mode uses a separate Apache tree without AFL
        # instrumentation, so afl-compiler-rt.o is unnecessary and harmful
        # (it hooks dlopen and aborts when OpenSSL is loaded by
        # mod_session_crypto).  Standalone links against the existing
        # (possibly AFL-instrumented) tree and needs the runtime.
        skip_afl_rt = mode == "coverage"

        # When linking non-AFL compilers against AFL-instrumented Apache
        # objects (SanCov uses non-PIC R_X86_64_32S relocations), disable
        # PIE to avoid relocation errors.
        if mode == "standalone" and cc != "afl-clang-fast":
            ldflags = f"{ldflags} -no-pie"

        # Link everything
        objects = ["fuzz_harness.lo"]
        if has_fuzz_common:
            objects.append("fuzz_common.lo")
        objects.extend(["buildmark.lo", "modules.lo"])
        self._link_harness(output_name, objects, cflags, ldflags, cc, allow_muldefs, skip_afl_rt)

    @staticmethod
    def _find_afl_compiler_rt() -> str:
        """Locate afl-compiler-rt.o needed to link AFL-instrumented objects."""
        # Toolchain-local copy (from `apatchy setup afl`)
        local = Config.TOOLCHAIN_DIR / "aflplusplus" / "afl-compiler-rt.o"
        if local.exists():
            return str(local)
        # System-installed AFL++
        system = Path("/usr/lib/afl/afl-compiler-rt.o")
        if system.exists():
            return str(system)
        # Try afl-clang-fast --print-runtime-dir (AFL++ >= 4.x)
        afl_cc = shutil.which("afl-clang-fast")
        if afl_cc:
            import subprocess
            try:
                result = subprocess.run(
                    [afl_cc, "--print-runtime-dir"],
                    capture_output=True, text=True, timeout=5,
                )
                rt_dir = result.stdout.strip()
                candidate = Path(rt_dir) / "afl-compiler-rt.o"
                if candidate.exists():
                    return str(candidate)
            except (subprocess.TimeoutExpired, OSError):
                pass
        return ""

    def get_include_paths(self):
        """Return all -I include flags for Apache/APR/APR-Util headers."""
        includes = [
            f"-I{self.httpd_root}/include",
            f"-I{self.httpd_root}/srclib/apr/include",
            f"-I{self.httpd_root}/srclib/apr-util/include",
            f"-I{self.httpd_root}/os/unix",
            f"-I{self.httpd_root}/server"
        ]
        modules_dir = self.httpd_root / "modules"
        if modules_dir.exists():
            for p in modules_dir.rglob("*"):
                if p.is_dir():
                    includes.append(f"-I{p}")
        return includes

    def _compile_object(self, src, dest, cflags, cc="clang", bear=False):
        includes = self.get_include_paths()

        cmd = [
            str(self.libtool), "--mode=compile", cc,
            *cflags.split(), *includes,
            "-c", src, "-o", dest
        ]
        if bear:
            cmd = ["bear", "--force-wrapper", "--append", "--"] + cmd
        src_name = Path(src).name
        self.runner.run_build(cmd, label=f"Compiling {src_name}")

    def _parse_config_vars(self):
        """Parse config_vars.mk from the Apache build to extract linker flags."""
        config_vars = self.httpd_root / "build" / "config_vars.mk"
        result = {}
        if config_vars.exists():
            for line in config_vars.read_text().splitlines():
                m = re.match(r'^(\w+)\s*=\s*(.*)', line)
                if m:
                    result[m.group(1)] = m.group(2).strip()
        return result

    def _get_system_libs(self, config_vars):
        """Extract system library flags from config_vars.mk MOD_*_LDADD entries."""
        libs = []
        seen = set()
        # Collect all non-empty MOD_*_LDADD flags
        for key, val in config_vars.items():
            if key.startswith("MOD_") and key.endswith("_LDADD") and val:
                for flag in val.split():
                    if flag not in seen:
                        seen.add(flag)
                        libs.append(flag)
        # PCRE is needed by the server core
        pcre_libs = config_vars.get("PCRE_LIBS", "")
        for flag in pcre_libs.split():
            if flag not in seen:
                seen.add(flag)
                libs.append(flag)
        return libs

    def _link_harness(self, output, objects, cflags, ldflags, cc="clang", allow_muldefs=False, skip_afl_rt=False):
        modules_dir = self.httpd_root / "modules"

        libmain = f"{self.httpd_root}/server/libmain.la"
        libos = f"{self.httpd_root}/os/unix/libos.la"
        server_libs = [
            libmain,
            libos,
            f"{self.httpd_root}/server/mpm/event/libevent.la",
        ]

        # All statically built module libraries (deduplicated by basename)
        seen_basenames = set()
        for la in modules_dir.rglob("libmod_*.la"):
            if ".libs" in str(la):
                continue
            basename = la.name
            if basename not in seen_basenames:
                seen_basenames.add(basename)
                server_libs.append(str(la))

        # Repeat libmain and libos after modules to resolve circular archive
        # dependencies (modules reference server util functions like ap_cookie_*
        # that are in libmain.a but only needed after module archives load).
        server_libs.extend([libmain, libos])

        # Parse config_vars.mk for system library dependencies
        config_vars = self._parse_config_vars()
        system_libs = self._get_system_libs(config_vars)

        muldefs_flags = []
        if allow_muldefs:
            # Our harness provides main() which conflicts with Apache's main()
            # in libmain.a. Allow both definitions (-z muldefs) and force key
            # symbols to be pulled from the archive even though main.o (which
            # normally triggers the transitive chain) won't be loaded.
            muldefs_flags = [
                "-Wl,-z,muldefs",
                "-Wl,-u,ap_cookie_write",
                "-Wl,-u,ap_cookie_read",
                "-Wl,-u,ap_cookie_check_string",
                "-Wl,-u,ap_rxplus_compile",
                "-Wl,-u,ap_rxplus_exec",
            ]

        # When linking non-AFL modes against AFL-instrumented Apache objects,
        # we need the AFL compiler runtime to satisfy __afl_area_ptr etc.
        # Skip for coverage mode: Apache is rebuilt without AFL, and the
        # runtime's dlopen() hook aborts when modules load shared libs.
        afl_rt = []
        if not skip_afl_rt and cc != "afl-clang-fast":
            rt = self._find_afl_compiler_rt()
            if rt:
                afl_rt = [rt]

        cmd = [
            str(self.libtool), "--mode=link", cc,
            *muldefs_flags,
            *cflags.split(), *ldflags.split(),
            "-o", output,
            *objects,
            "-export-dynamic",
            *server_libs,
            f"{self.httpd_root}/srclib/apr-util/libaprutil-1.la",
            f"{self.httpd_root}/srclib/apr/libapr-1.la",
            *afl_rt,
            *system_libs,
            "-luuid", "-lcrypt", "-lpthread",
        ]
        self.runner.run_build(cmd, label="Linking harness")
