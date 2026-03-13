from typing import Dict, List

from apatchy.config import Config
from apatchy.core import toolchain_config
from apatchy.core.toolchain import DepStatus, build_name_index, build_registry
from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class ToolchainManager:  # noqa: D101
    def __init__(self, verbose: bool = False) -> None:
        self.toolchain_dir = Config.TOOLCHAIN_DIR
        self._registry = build_registry(self.toolchain_dir, verbose)
        self._index = build_name_index(self._registry)

    def check(self) -> List[DepStatus]:  # noqa: D102
        deps: List[DepStatus] = []
        for tool in self._registry:
            deps.extend(tool.check())
        self._write_deps_to_config(deps)
        return deps

    def setup(self, tool_name: str, force: bool = False, **kwargs) -> None:  # noqa: D102
        tool = self._index.get(tool_name)
        if not tool:
            logger.error(f"Unknown tool: {tool_name}")
            return
        tool.setup(force=force, **kwargs)

    def _write_deps_to_config(self, deps: List[DepStatus]) -> None:
        category_to_section = {
            "Build": "build",
            "Fuzzing": "fuzzing",
            "Coverage": "coverage",
            "Libraries": "libraries",
            "Profiling": "profiling",
            "GUI": "gui",
            "Docs": "docs",
        }
        groups: Dict[str, Dict[str, str]] = {}
        for dep in deps:
            if not dep.found or not dep.path:
                continue
            section = category_to_section.get(dep.category)
            if not section:
                continue
            key = self._normalize_key(dep.name)
            groups.setdefault(section, {})[key] = dep.path
        for section, entries in groups.items():
            toolchain_config.update_section(section, entries)

    @staticmethod
    def _normalize_key(name: str) -> str:
        idx = name.find(" (via ")
        if idx != -1:
            return name[:idx]
        return name
