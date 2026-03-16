from pathlib import Path
from typing import Dict, List

from apatchy.core.toolchain.afl import AflTool
from apatchy.core.toolchain.base import ToolchainTool
from apatchy.core.toolchain.libtool import LibtoolTool
from apatchy.core.toolchain.llvm import LlvmTool
from apatchy.core.toolchain.lpm import LpmTool
from apatchy.core.toolchain.simple import BinaryTool, HeaderOrPkgTool, PkgOrConfigTool


def build_registry(toolchain_dir: Path, verbose: bool = False) -> List[ToolchainTool]:
    is_wsl = _is_wsl()
    tools: List[ToolchainTool] = [
        # Build
        BinaryTool("clang", "Build", "apatchy setup --force llvm --llvm-version 18", toolchain_dir, verbose),
        BinaryTool("make", "Build", "apt install make", toolchain_dir, verbose),
        BinaryTool("cmake", "Build", "apt install cmake", toolchain_dir, verbose),
        BinaryTool("bear", "Build", "apt install bear", toolchain_dir, verbose),
        BinaryTool("pkg-config", "Build", "apt install pkg-config", toolchain_dir, verbose),
        BinaryTool("autoconf", "Build", "apt install autoconf", toolchain_dir, verbose),
        LibtoolTool(toolchain_dir, verbose),
        # Docs
        BinaryTool("doxygen", "Docs", "apt install doxygen", toolchain_dir, verbose),
        BinaryTool("dot", "Docs", "apt install graphviz", toolchain_dir, verbose),
        # Fuzzing
        BinaryTool("protoc", "Build", "apt install protobuf-compiler", toolchain_dir, verbose),
        AflTool(toolchain_dir, verbose),
        LpmTool(toolchain_dir, verbose),
        # Coverage (LLVM)
        LlvmTool(toolchain_dir, verbose),
        # Profiling
        BinaryTool("valgrind", "Profiling", "apt install valgrind", toolchain_dir, verbose),
    ]
    if is_wsl:
        tools.append(
            BinaryTool(
                "qcachegrind.exe",
                "Profiling",
                "install QCachegrind on Windows",
                toolchain_dir,
                verbose,
                exists_only=True,
            )
        )
    else:
        tools.append(
            BinaryTool("kcachegrind", "Profiling", "apt install kcachegrind", toolchain_dir, verbose, exists_only=True)
        )
    tools += [
        # GUI
        BinaryTool("node", "GUI", "nvm install 22", toolchain_dir, verbose),
        BinaryTool("npm", "GUI", "nvm install 22", toolchain_dir, verbose),
        # Libraries
        PkgOrConfigTool(
            "libpcre2-dev", "Libraries", "apt install libpcre2-dev", toolchain_dir, "pcre2-config", "libpcre2", verbose
        ),
        PkgOrConfigTool("zlib1g-dev", "Libraries", "apt install zlib1g-dev", toolchain_dir, None, "zlib", verbose),
        PkgOrConfigTool(
            "libxml2-dev", "Libraries", "apt install libxml2-dev", toolchain_dir, "xml2-config", "libxml-2.0", verbose
        ),
        HeaderOrPkgTool(
            "libexpat1-dev", "Libraries", "apt install libexpat1-dev", toolchain_dir, "expat.h", "expat", verbose
        ),
        HeaderOrPkgTool("uuid-dev", "Libraries", "apt install uuid-dev", toolchain_dir, "uuid/uuid.h", "uuid", verbose),
        PkgOrConfigTool("libssl-dev", "Libraries", "apt install libssl-dev", toolchain_dir, None, "openssl", verbose),
        PkgOrConfigTool(
            "libprotobuf-dev", "Libraries", "apt install libprotobuf-dev", toolchain_dir, None, "protobuf", verbose
        ),
    ]
    return tools


def build_name_index(registry: List[ToolchainTool]) -> Dict[str, ToolchainTool]:
    return {t.name: t for t in registry if hasattr(t, "name") and isinstance(t.name, str)}


def _is_wsl() -> bool:
    from pathlib import Path

    try:
        return Path("/proc/version").exists() and "microsoft" in Path("/proc/version").read_text().lower()
    except Exception:
        return False
