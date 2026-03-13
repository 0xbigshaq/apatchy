import json
import os
import shutil
from pathlib import Path
from typing import Dict, List

from apatchy.config import Config
from apatchy.core.harness import HarnessBuilder
from apatchy.managers.config_manager import ConfigManager
from apatchy.utils.build_tree import AlternateBuildTree
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)

TEMPLATE_FILE = Path(__file__).parent.parent / "templates" / "dev_harness.c"


class DevManager:
    """Scaffold, build, and manage isolated developer harness projects.

    ``DevManager`` lets you create self-contained fuzzing harness projects
    under the ``dev/`` directory. Each project gets its own directory with a
    template ``harness.c``, a seed input directory, and a
    ``compile_commands.json`` for IDE auto-completion. Projects can then be
    compiled against the Apache build tree for either AFL++ or standalone
    (stdin-based) execution.

    A project directory looks like::

        dev/
          my_harness/
            harness.c               # your fuzzing harness source
            afl-input/              # seed corpus
              sample.txt
            compile_commands.json   # auto-generated for clangd
            fuzz_harness_afl        # built binary (after build)
            fuzz_harness_standalone # built binary (after build)

    When building in standalone mode, ``DevManager`` automatically creates
    an alternate Apache build tree compiled with plain ``clang`` (no AFL++
    instrumentation) to avoid runtime conflicts. This tree is cached and
    reused across builds.

    Args:
        httpd_root: Path to the Apache HTTPD source directory that harnesses
            will link against.

    CLI usage:

    .. code-block:: bash

        # Create a new project from the template
        apatchy dev init my_harness

        # Edit dev/my_harness/harness.c, then build
        apatchy dev build my_harness
        apatchy dev build my_harness --engine afl

        # List all projects and their build status
        apatchy dev list

    Example:
        .. code-block:: python

            from pathlib import Path
            from apatchy.managers.dev_manager import DevManager

            dm = DevManager(Path("httpd-2.4.58"))

            # Create a new project from the template
            project_dir = dm.init_project("my_harness")

            # Edit dev/my_harness/harness.c, then build
            dm.build_project("my_harness", engine="afl")
            dm.build_project("my_harness", engine="standalone")

            # List all projects and their build status
            for p in dm.list_projects():
                print(f"{p['name']}  built: {p['built']}")
    """

    def __init__(self, httpd_root: Path) -> None:
        self.httpd_root = httpd_root
        self.dev_dir = Config.DEV_DIR
        self.harness_builder = HarnessBuilder(httpd_root)

    def init_project(self, name: str) -> Path:
        """Create a new dev harness project directory with template and compile_commands.json."""
        project_dir = self.dev_dir / name

        if project_dir.exists():
            logger.error(f"Project '{name}' already exists at {project_dir}")
            raise FileExistsError(f"Project '{name}' already exists")

        project_dir.mkdir(parents=True)
        logger.info(f"Created project directory: {project_dir}")

        # Copy template
        harness_dest = project_dir / "harness.c"
        if TEMPLATE_FILE.exists():
            shutil.copy(TEMPLATE_FILE, harness_dest)
        else:
            logger.warning("Dev harness template not found, using fallback")
            harness_dest.write_text(_fallback_template())
        logger.info(f"Created {harness_dest}")

        # Create seed input directory
        input_dir = project_dir / "afl-input"
        input_dir.mkdir()
        (input_dir / "sample.txt").write_text("GET / HTTP/1.1\r\n\r\n")
        logger.info(f"Created {input_dir}")

        # Generate compile_commands.json for IDE support
        self._generate_compile_commands(project_dir)

        return project_dir

    def build_project(self, name: str, engine: str = "standalone") -> None:
        """Build a dev harness project."""
        project_dir = self.dev_dir / name
        harness_src = project_dir / "harness.c"

        if not harness_src.exists():
            logger.error(f"Project '{name}' not found at {project_dir}")
            raise FileNotFoundError(f"Project '{name}' not found")

        # Regenerate compile_commands.json
        self._generate_compile_commands(project_dir)

        # Standalone mode needs Apache compiled with plain clang (no AFL
        # instrumentation) to avoid runtime conflicts.
        if engine == "standalone":
            tree = AlternateBuildTree(self.httpd_root, "-standalone")
            standalone_root = tree.ensure_build(
                cc="clang",
                cflags="-g -O0 -fno-omit-frame-pointer -Wno-error=format",
                ldflags="",
            )
            harness_builder = HarnessBuilder(standalone_root)
        else:
            harness_builder = self.harness_builder

        # Build in the project directory (libtool writes .lo files relative to CWD)
        config_manager = ConfigManager()
        config = config_manager.generate_build_config()
        cflags = config["CFLAGS"]
        ldflags = config["LDFLAGS"]

        original_cwd = os.getcwd()
        try:
            os.chdir(project_dir)
            harness_builder.build(
                mode=engine,
                cflags=cflags,
                ldflags=ldflags,
                harness_name=str(harness_src),
            )
        finally:
            os.chdir(original_cwd)

        logger.info(f"Built {name} for engine: {engine}")

    def list_projects(self) -> List[Dict[str, str]]:
        """List all dev harness projects."""
        projects: List[Dict[str, str]] = []

        if not self.dev_dir.exists():
            return projects

        for d in sorted(self.dev_dir.iterdir()):
            harness = d / "harness.c"
            if not d.is_dir() or not harness.exists():
                continue

            # Check which engines have been built
            built = []
            for engine in ("afl", "libfuzzer", "standalone"):
                binary = d / f"fuzz_harness_{engine}"
                if binary.exists():
                    built.append(engine)

            has_cdb = (d / "compile_commands.json").exists()

            projects.append(
                {
                    "name": d.name,
                    "path": str(d),
                    "built": ", ".join(built) if built else "",
                    "compdb": "yes" if has_cdb else "no",
                }
            )

        return projects

    def _generate_compile_commands(self, project_dir: Path) -> None:
        """Generate compile_commands.json for IDE support."""
        harness_src = project_dir / "harness.c"
        includes = self.harness_builder.get_include_paths()

        entry = {
            "directory": str(project_dir.resolve()),
            "arguments": [
                "clang",
                "-g",
                "-O0",
                "-fno-omit-frame-pointer",
                *includes,
                "-c",
                str(harness_src.resolve()),
                "-o",
                str((project_dir / "harness.o").resolve()),
            ],
            "file": str(harness_src.resolve()),
        }

        cdb_path = project_dir / "compile_commands.json"
        cdb_path.write_text(json.dumps([entry], indent=2) + "\n")
        logger.info(f"Generated {cdb_path}")


def _fallback_template() -> str:
    """Inline fallback if the template file is missing."""
    return """\
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "apr_general.h"
#include "apr_pools.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    static int initialized = 0;
    if (!initialized) {
        if (apr_initialize() != APR_SUCCESS) return 0;
        initialized = 1;
    }

    apr_pool_t *pool;
    if (apr_pool_create(&pool, NULL) != APR_SUCCESS) return 0;

    /* TODO: Your fuzzing logic here */

    apr_pool_destroy(pool);
    return 0;
}

#ifndef LIBFUZZER_MODE
#include <unistd.h>
#ifndef __AFL_LOOP
#define __AFL_LOOP(x) 1
#endif
int main(int argc, char **argv) {
    uint8_t buf[1024 * 64];
    while (__AFL_LOOP(10000)) {
        ssize_t n = read(0, buf, sizeof(buf));
        if (n > 0) LLVMFuzzerTestOneInput(buf, (size_t)n);
    }
    return 0;
}
#endif
"""
