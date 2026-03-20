"""Build, link, and manage fuzzing harness binaries.

:class:`HarnessBuilder` compiles harness sources against the Apache
build tree and links them with all statically-built modules, producing a
self-contained binary for LibFuzzer or standalone execution.
"""

import json
import re
import subprocess
from pathlib import Path

from apatchy.config import Config
from apatchy.core import toolchain_config
from apatchy.core.process_runner import ProcessRunner
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)

#: Compiler selection per build mode.
COMPILERS = {
    "libfuzzer": "clang",
    "standalone": "clang",
    "coverage": "clang",
    "profile": "clang",
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
        for path in sorted(list(Config.HARNESSES_DIR.glob("*.c")) + list(Config.HARNESSES_DIR.glob("*.cc"))):
            desc = ""
            try:
                with open(path) as f:
                    for line in f:
                        m = re.search(r"@description:\s*(.+)", line)
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
        """
        # Bundled .c
        bundled = Config.HARNESSES_DIR / f"{name}.c"
        if bundled.exists():
            return bundled
        # Bundled .cc (proto harnesses)
        bundled_cc = Config.HARNESSES_DIR / f"{name}.cc"
        if bundled_cc.exists():
            return bundled_cc
        # Literal path
        literal = Path(name)
        if literal.exists():
            return literal
        return None

    @staticmethod
    def is_proto(name):
        """Return True if *name* resolves to a .cc (proto) harness."""
        if not name:
            return False
        resolved = HarnessBuilder.resolve_harness(name)
        return resolved is not None and resolved.suffix == ".cc"

    def build(self, mode="standalone", cflags="", ldflags="", harness_name=None, cc=None, bear=False):
        """Compile and link the harness for the given fuzzing engine.

        Parameters
        ----------
        mode : str
            One of ``"libfuzzer"``, ``"standalone"``, ``"coverage"``,
            or ``"profile"``.
        cflags : str
            Extra compiler flags.
        ldflags : str
            Extra linker flags.
        harness_name : str, optional
            Name of a bundled harness or path to a harness source file.
            Defaults to ``"mod_fuzzy"`` if not provided.
        cc : str, optional
            Override the compiler (defaults to :data:`COMPILERS` lookup).
        bear : bool
            Wrap compilation with ``bear`` for ``compile_commands.json``.
        """
        output_name = f"fuzz_harness_{mode}"
        if cc is None:
            cc = COMPILERS.get(mode, "clang")

        # Resolve compiler: toolchain.config first, then PATH
        resolved_cc = toolchain_config.resolve_tool(cc)
        if resolved_cc:
            cc = resolved_cc
        else:
            self.logger.error(f"Compiler '{cc}' not found")
            raise FileNotFoundError(f"{cc} not found in PATH")

        self.logger.info(f"Using compiler: {cc}")

        # Propagate sanitizer flags from Apache's config_vars.mk so the
        # harness objects are compiled with the same sanitizer as Apache.
        config_vars = self._parse_config_vars()
        for key in ("CFLAGS", "LDFLAGS"):
            for token in config_vars.get(key, "").split():
                if token.startswith(("-fsanitize", "-fno-sanitize")):
                    if token not in cflags:
                        cflags = f"{cflags} {token}"
                    if token not in ldflags:
                        ldflags = f"{ldflags} {token}"

        # Add mode-specific defines so the harness compiles the right entry point
        if mode == "libfuzzer":
            cflags = f"-DLIBFUZZER -fsanitize=fuzzer {cflags}"
            ldflags = f"-fsanitize=fuzzer {ldflags}"
        elif mode == "coverage":
            cflags = f"-DLIBFUZZER -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping {cflags}"
            ldflags = f"-fsanitize=fuzzer -fprofile-instr-generate {ldflags}"

        # Resolve harness source file
        if not harness_name:
            harness_name = "mod_fuzzy_proto"
        harness_src = self.resolve_harness(harness_name)
        if harness_src is None:
            self.logger.error(f"Harness '{harness_name}' not found")
            raise FileNotFoundError(f"Harness '{harness_name}' not found")
        harness_src = harness_src.resolve()
        self.logger.info(f"Using harness: {harness_src}")

        # Proto harnesses (.cc) need a completely different build pipeline
        if harness_src.suffix == ".cc":
            self._build_proto_harness(output_name, harness_src, cflags, ldflags)
            return

        # Add harness directory to include path so #include "fuzz_common.h" works
        harness_dir = harness_src.parent
        cflags = f"-I{harness_dir} {cflags}"

        # bear output goes into the harness source directory so .clangd can find it
        bear_output = None
        if bear:
            bear_cdb = harness_dir / "compile_commands.json"
            bear_cdb.unlink(missing_ok=True)
            bear_output = str(bear_cdb)

        # Compile harness object
        self._compile_object(str(harness_src), "fuzz_harness.lo", cflags, cc, bear_output=bear_output)

        # Compile fuzz_common if needed
        self._compile_object(str(harness_dir / "fuzz_common.c"), "fuzz_common.lo", cflags, cc, bear_output=bear_output)

        # Compile buildmark.c (provides ap_get_server_built)
        self._compile_object(str(self.httpd_root / "server" / "buildmark.c"), "buildmark.lo", cflags, cc)

        # Compile modules.c (provides ap_prelinked_modules, ap_prelinked_module_symbols)
        self._compile_object(str(self.httpd_root / "modules.c"), "modules.lo", cflags, cc)

        # Harness modes provide their own main() which conflicts with
        # Apache's main() in libmain.a. Use -z muldefs to allow both;
        # our object file main() wins over the archive's.
        allow_muldefs = mode in ("libfuzzer", "standalone")

        if "-no-pie" not in ldflags:
            ldflags = f"{ldflags} -no-pie"

        obj = str(Config.OBJ_DIR)
        objects = [f"{obj}/fuzz_harness.lo", f"{obj}/fuzz_common.lo", f"{obj}/buildmark.lo", f"{obj}/modules.lo"]
        self._link_harness(output_name, objects, cflags, ldflags, cc, allow_muldefs)

    def get_include_paths(self):
        """Return all -I include flags for Apache/APR/APR-Util headers."""
        includes = [
            f"-I{self.httpd_root}/include",
            f"-I{self.httpd_root}/srclib/apr/include",
            f"-I{self.httpd_root}/srclib/apr-util/include",
            f"-I{self.httpd_root}/os/unix",
            f"-I{self.httpd_root}/server",
        ]
        modules_dir = self.httpd_root / "modules"
        if modules_dir.exists():
            for p in modules_dir.rglob("*"):
                if p.is_dir():
                    includes.append(f"-I{p}")
        return includes

    def check_compiles(self, harness_src, cflags, cc="clang"):
        """Quick syntax-only probe. Returns (ok, stderr) tuple."""
        includes = self.get_include_paths()
        cmd = [cc, "-fsyntax-only", *cflags.split(), *includes, str(harness_src)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0, result.stderr

    def _compile_object(self, src, dest, cflags, cc="clang", bear_output=None):
        includes = self.get_include_paths()
        Config.OBJ_DIR.mkdir(exist_ok=True)
        dest = str(Config.OBJ_DIR / dest)

        cmd = [str(self.libtool), "--mode=compile", cc, *cflags.split(), *includes, "-c", src, "-o", dest]
        if bear_output:
            cmd = ["bear", "--output", bear_output, "--append", "--"] + cmd
        src_name = Path(src).name
        self.runner.run_build(cmd, label=f"Compiling {src_name}")

    def _parse_config_vars(self):
        """Parse config_vars.mk from the Apache build to extract linker flags."""
        config_vars = self.httpd_root / "build" / "config_vars.mk"
        result = {}
        if config_vars.exists():
            for line in config_vars.read_text().splitlines():
                m = re.match(r"^(\w+)\s*=\s*(.*)", line)
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

    def _link_harness(self, output, objects, cflags, ldflags, cc="clang", allow_muldefs=False):
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

        cmd = [
            str(self.libtool),
            "--mode=link",
            cc,
            *muldefs_flags,
            *cflags.split(),
            *ldflags.split(),
            "-o",
            output,
            *objects,
            "-export-dynamic",
            *server_libs,
            f"{self.httpd_root}/srclib/apr-util/libaprutil-1.la",
            f"{self.httpd_root}/srclib/apr/libapr-1.la",
            *system_libs,
            "-luuid",
            "-lcrypt",
            "-lpthread",
        ]
        self.runner.run_build(cmd, label="Linking harness")

    @staticmethod
    def _parse_harness_tags(harness_src):
        """Parse @protos and @converters tags from a harness source file."""
        protos = None
        converters = None
        try:
            with open(harness_src) as f:
                for line in f:
                    if line.strip() == "*/":
                        break
                    m = re.search(r"@protos:\s*(.+)", line)
                    if m:
                        protos = [s.strip() for s in m.group(1).split(",")]
                    m = re.search(r"@converters:\s*(.+)", line)
                    if m:
                        converters = [s.strip() for s in m.group(1).split(",")]
        except OSError:
            pass
        return protos, converters

    def _build_proto_harness(self, output_name, harness_src, cflags, ldflags):
        """Build a protobuf-based harness using libprotobuf-mutator.

        Pipeline:
        1. protoc generates .pb.h/.pb.cc from the .proto schema
        2. Compile .pb.cc with clang++ (pure C++, no libtool)
        3. Compile harness .cc with clang++ via libtool (Apache includes)
        4. Compile fuzz_common.c with clang via libtool
        5. Compile buildmark.c + modules.c
        6. Link with clang++ adding LPM + protobuf libraries
        """
        harness_dir = harness_src.parent
        cxx = toolchain_config.resolve_tool("clang++") or "clang++"
        c_cc = toolchain_config.resolve_tool("clang") or "clang"

        # Resolve LPM paths
        lpm_root, lpm_build = self._resolve_lpm_paths()
        if not lpm_root:
            self.logger.error("libprotobuf-mutator not found. Run 'apatchy setup lpm' first.")
            raise FileNotFoundError("libprotobuf-mutator not found")

        # Parse @protos/@converters tags to only build what this harness needs
        needed_protos, needed_converters = self._parse_harness_tags(harness_src)

        # Run protoc (all .proto files so imports resolve, but we only compile needed ones)
        gen_dir = Config.WORK_DIR / ".proto_gen"
        gen_dir.mkdir(exist_ok=True)

        proto_files = sorted(Config.PROTOS_DIR.glob("*.proto"))
        protoc = toolchain_config.resolve_tool("protoc") or "protoc"
        self.runner.run_build(
            [protoc, f"--cpp_out={gen_dir}", f"--proto_path={Config.PROTOS_DIR}"] + [str(p) for p in proto_files],
            label="Generating protobuf sources",
        )

        # Get protobuf compiler flags via pkg-config
        pb_cflags = self._pkg_config_flags("protobuf", "--cflags")
        pb_ldflags = self._pkg_config_flags("protobuf", "--libs")

        # LPM include and library paths
        lpm_includes = f"-I{lpm_root}"
        lpm_libs = []
        if lpm_build:
            lib_dir = lpm_build / "src" / "libfuzzer"
            lib_src = lpm_build / "src"
            lpm_libs = [f"-L{lib_dir}", f"-L{lib_src}"]
        lpm_libs += ["-lprotobuf-mutator-libfuzzer", "-lprotobuf-mutator"]

        # Compile only the .pb.cc files this harness needs
        Config.OBJ_DIR.mkdir(exist_ok=True)
        pb_objects = []
        for pb_cc in sorted(gen_dir.glob("*.pb.cc")):
            if needed_protos and pb_cc.stem.removesuffix(".pb") not in needed_protos:
                continue
            pb_obj = Config.OBJ_DIR / f"{pb_cc.stem}.o"
            self.runner.run_build(
                [cxx, "-c", "-O2", "-std=c++17", *pb_cflags.split(), f"-I{gen_dir}", str(pb_cc), "-o", str(pb_obj)],
                label=f"Compiling {pb_cc.name}",
            )
            pb_objects.append(str(pb_obj))

        # Build cflags for the harness: Apache includes + proto gen dir + LPM includes
        harness_cflags = f"-I{harness_dir} -I{gen_dir} {lpm_includes} {pb_cflags} -std=c++17 {cflags}"

        # Compile harness .cc via libtool with clang++
        self._compile_object(str(harness_src), "fuzz_harness.lo", harness_cflags, cxx)

        # Compile only the proto converters this harness needs
        converter_objects = []
        converters_dir = harness_dir / "proto_converters"
        if converters_dir.is_dir():
            for src in sorted(converters_dir.glob("*.cc")):
                if needed_converters and src.stem not in needed_converters:
                    continue
                obj_name = f"proto_{src.stem}.lo"
                self._compile_object(str(src), obj_name, harness_cflags, cxx)
                converter_objects.append(str(Config.OBJ_DIR / obj_name))

        # Compile fuzz_common.c and fuzz_backend.c with the C compiler via libtool
        c_cflags = f"-I{harness_dir} {cflags}"
        self._compile_object(str(harness_dir / "fuzz_common.c"), "fuzz_common.lo", c_cflags, c_cc)
        self._compile_object(str(harness_dir / "fuzz_backend.c"), "fuzz_backend.lo", c_cflags, c_cc)

        # Compile buildmark.c and modules.c
        self._compile_object(str(self.httpd_root / "server" / "buildmark.c"), "buildmark.lo", c_cflags, c_cc)
        self._compile_object(str(self.httpd_root / "modules.c"), "modules.lo", c_cflags, c_cc)

        # Link with clang++ so C++ stdlib resolves
        extra_ldflags = " ".join(lpm_libs) + " " + pb_ldflags + " -lcrypto"
        link_ldflags = f"{ldflags} {extra_ldflags}"
        if "-no-pie" not in link_ldflags:
            link_ldflags = f"{link_ldflags} -no-pie"

        obj = str(Config.OBJ_DIR)
        objects = (
            [f"{obj}/fuzz_harness.lo"]
            + converter_objects
            + [f"{obj}/fuzz_common.lo", f"{obj}/fuzz_backend.lo"]
            + pb_objects
            + [f"{obj}/buildmark.lo", f"{obj}/modules.lo"]
        )
        self._link_harness(
            output_name,
            objects,
            cflags,
            link_ldflags,
            cc=cxx,
            allow_muldefs=True,
        )

        # Write compile_commands.json so clangd can resolve proto/LPM headers
        self._write_proto_compile_commands(
            harness_src,
            harness_cflags,
            c_cflags,
            cxx,
            c_cc,
        )

    @staticmethod
    def _resolve_lpm_paths():
        """Find LPM root and build directories.

        Returns (lpm_root, lpm_build) or (None, None) if not found.
        """
        # Toolchain-local build
        lpm_build_path = toolchain_config.resolve_tool("lpm-build", section="fuzzing")
        lpm_root_path = toolchain_config.resolve_tool("lpm-root", section="fuzzing")
        if lpm_root_path and lpm_build_path:
            return Path(lpm_root_path), Path(lpm_build_path)

        # Check toolchain dir directly
        local_root = Config.TOOLCHAIN_DIR / "libprotobuf-mutator"
        local_build = local_root / "build"
        if (local_build / "src" / "libprotobuf-mutator.a").exists():
            return local_root, local_build

        # System-installed LPM
        for inc_dir in ("/usr/include", "/usr/local/include"):
            if Path(inc_dir, "libprotobuf-mutator").exists():
                return Path(inc_dir).parent, None

        return None, None

    @staticmethod
    def _pkg_config_flags(pkg, flag_type):
        """Run pkg-config and return the output, or empty string on failure."""
        try:
            result = subprocess.run(
                ["pkg-config", flag_type, pkg],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            pass
        return ""

    def _write_proto_compile_commands(self, harness_src, harness_cflags, c_cflags, cxx, c_cc):
        """Write compile_commands.json for proto harness sources so clangd works."""
        includes = self.get_include_paths()
        harness_dir = harness_src.parent
        directory = str(Config.WORK_DIR)

        entries = [
            {
                "directory": directory,
                "file": str(harness_src),
                "arguments": [cxx, *harness_cflags.split(), *includes, "-c", str(harness_src)],
            },
            {
                "directory": directory,
                "file": str(harness_dir / "fuzz_common.c"),
                "arguments": [c_cc, *c_cflags.split(), *includes, "-c", str(harness_dir / "fuzz_common.c")],
            },
        ]

        # Add proto converter .cc files
        converters_dir = harness_dir / "proto_converters"
        if converters_dir.is_dir():
            for src in sorted(converters_dir.glob("*.cc")):
                entries.append(
                    {
                        "directory": directory,
                        "file": str(src),
                        "arguments": [cxx, *harness_cflags.split(), *includes, "-c", str(src)],
                    }
                )

        cdb_path = harness_dir / "compile_commands.json"

        # Merge with existing entries (from --bear builds) instead of overwriting
        existing = []
        if cdb_path.exists():
            import contextlib

            with contextlib.suppress(json.JSONDecodeError, OSError):
                existing = json.loads(cdb_path.read_text())

        new_files = {e["file"] for e in entries}
        merged = [e for e in existing if e.get("file") not in new_files] + entries

        cdb_path.write_text(json.dumps(merged, indent=2) + "\n")
        self.logger.info(f"Wrote {cdb_path}")
