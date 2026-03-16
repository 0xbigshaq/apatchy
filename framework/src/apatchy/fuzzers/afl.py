from pathlib import Path
from typing import List, Optional

from apatchy.core import toolchain_config
from apatchy.fuzzers.base import BaseFuzzer


class AflFuzzer(BaseFuzzer):
    """AFL++ fuzzing engine."""

    def start(  # noqa: D102
        self,
        harness: Path,
        seed_dir: Path,
        output_dir: Path,
        mutator: Optional[list[str]] = None,
        resume: bool = False,
        role: Optional[str] = None,
        name: Optional[str] = None,
        suppress: Optional[str] = None,
        timeout: Optional[int] = None,
        debug: bool = False,
    ) -> None:
        if role and not name:
            name = "main01" if role == "main" else "sec01"

        mode_label = f" ({role}: {name})" if role else ""

        try:
            core_pattern = Path("/proc/sys/kernel/core_pattern").read_text().strip()
            if core_pattern != "core":
                self.logger.error(
                    f"core_pattern is '{core_pattern}', expected 'core'. "
                    "Run: echo core | sudo tee /proc/sys/kernel/core_pattern"
                )
                return
        except OSError:
            pass

        self.logger.info(f"Starting AFL++{mode_label}...")

        env = self._build_env()
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
        env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=0"
        env["AFL_CRASH_EXITCODE"] = "66"
        env["AFL_SKIP_CPUFREQ"] = "1"
        if debug:
            env["AFL_DEBUG_CHILD"] = "1"
        if resume:
            env["AFL_AUTORESUME"] = "1"

        ubsan_opts = ["symbolize=0", "halt_on_error=0"]
        if suppress:
            supp_path = Path(suppress).resolve()
            if not supp_path.exists():
                self.logger.error(f"Suppression file not found: {supp_path}")
                return
            self.logger.info(f"Using UBSan suppression file: {supp_path}")
            ubsan_opts.append(f"suppressions={supp_path}")

        existing = env.get("UBSAN_OPTIONS", "")
        combined = ":".join(ubsan_opts)
        env["UBSAN_OPTIONS"] = f"{existing}:{combined}" if existing else combined

        if role == "main" and resume and not self._migrate_corpus_for_parallel(output_dir, name):
            return

        if mutator:
            resolved = []
            for m in mutator:
                p = Path(m).resolve()
                if not p.exists():
                    self.logger.error(f"Mutator library not found: {p}")
                    return
                resolved.append(str(p))
            env["AFL_CUSTOM_MUTATOR_LIBRARY"] = ";".join(resolved)
            env["AFL_CUSTOM_MUTATOR_ONLY"] = "1"
            self.logger.info(f"Using custom mutator(s): {', '.join(resolved)}")

        config_path = self.config_manager.get_httpd_config()
        if config_path:
            preload = self._resolve_preload_modules(config_path)
            if preload:
                env["AFL_PRELOAD"] = ":".join(preload)

        afl_fuzz = toolchain_config.resolve_tool("afl-fuzz") or "afl-fuzz"
        cmd = [afl_fuzz]

        if timeout is not None:
            timeout_ms = timeout * 1000
            cmd += ["-t", str(timeout_ms)]
            self.logger.info(f"Per-execution timeout: {timeout}s")

        if role == "main":
            cmd += ["-M", name]
        elif role == "secondary":
            cmd += ["-S", name]

        cmd += [
            "-i",
            str(seed_dir),
            "-o",
            str(output_dir),
            "--",
            str(harness),
        ]

        try:
            self.runner.run_command(cmd, env=env, check=True, capture_output=False)
        except Exception:
            self.logger.error("Failed to start AFL++. Is it installed?")

    def _migrate_corpus_for_parallel(self, output_dir: Path, instance_name: str) -> bool:
        """Rename 'default/' to the instance name so a solo run can resume in parallel mode."""
        from rich.console import Console

        console = Console()

        default_dir = output_dir / "default"
        target_dir = output_dir / instance_name

        if not default_dir.exists():
            return True

        if target_dir.exists():
            self.logger.warning(
                f"Both '{default_dir.name}/' and '{target_dir.name}/' exist in {output_dir}. "
                f"Will use '{target_dir.name}/' - the 'default/' corpus will be ignored."
            )
            return True

        queue_dir = default_dir / "queue"
        queue_count = sum(1 for _ in queue_dir.iterdir()) if queue_dir.exists() else 0

        console.print()
        console.print(f"  [bold]Existing solo corpus found:[/bold] {default_dir}/")
        console.print(f"  [bold]Queue entries:[/bold] {queue_count}")
        console.print()
        console.print("  AFL++ parallel mode uses named instance directories instead of 'default/'.")
        console.print("  To preserve your corpus, the directory needs to be renamed:")
        console.print(f"    [cyan]{default_dir.name}/[/cyan]  ->  [cyan]{instance_name}/[/cyan]")
        console.print()
        console.print("  [green]\\[y][/green] Rename and continue (corpus is preserved under the new name)")
        console.print("  [red]\\[n][/red] Abort (no changes made, you can back up manually first)")

        answer = console.input("\n  Rename? [y/N] ").strip().lower()

        if answer != "y":
            self.logger.info("Aborted. No changes were made.")
            return False

        default_dir.rename(target_dir)
        self.logger.info(f"Renamed {default_dir.name}/ -> {instance_name}/")
        return True

    def _resolve_preload_modules(self, config_path: Path) -> List[str]:
        """Parse LoadModule directives from the config and return .so paths."""
        modules = []
        for line in config_path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("LoadModule") and not stripped.startswith("#"):
                parts = stripped.split()
                if len(parts) >= 3:
                    so_path = self.work_dir / parts[2]
                    if so_path.exists():
                        modules.append(str(so_path))
                    else:
                        self.logger.warning(f"LoadModule references missing file: {parts[2]}")
        return modules
