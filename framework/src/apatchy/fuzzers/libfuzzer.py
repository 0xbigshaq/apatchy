from pathlib import Path

from apatchy.fuzzers.base import BaseFuzzer


class LibFuzzer(BaseFuzzer):
    """LibFuzzer engine."""

    def start(  # noqa: D102
        self,
        harness: Path,
        seed_dir: Path,
        output_dir: Path,
        resume: bool = False,
        workers: int = 1,
        **kwargs,
    ) -> None:
        instance_dir = output_dir / "default"
        queue_dir = instance_dir / "queue"
        crashes_dir = instance_dir / "crashes"
        queue_dir.mkdir(parents=True, exist_ok=True)
        crashes_dir.mkdir(parents=True, exist_ok=True)

        if not resume and seed_dir.exists():
            existing = set(f.name for f in queue_dir.iterdir() if f.is_file())
            for seed in seed_dir.iterdir():
                if seed.is_file() and seed.name not in existing:
                    dest = queue_dir / seed.name
                    dest.write_bytes(seed.read_bytes())

        self.logger.info("Starting LibFuzzer...")
        self.logger.info(f"Corpus:  {queue_dir}")
        self.logger.info(f"Crashes: {crashes_dir}")

        env = self._build_env(suppress=kwargs.get("suppress"), lsan_supp=kwargs.get("lsan_supp"))

        cmd = [
            str(harness),
            str(queue_dir),
            f"-artifact_prefix={crashes_dir}/",
        ]

        if workers > 1:
            cmd.append(f"-fork={workers}")
            self.logger.info(f"Parallel mode: {workers} workers (-fork={workers})")
        else:
            cmd.append("-keep_going=1000000")
            cmd.append("-print_new_func_on_new=1")

        verbose = kwargs.get("verbose", False)
        if verbose:
            import subprocess
            import sys

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
            try:
                for line in proc.stdout:
                    sys.stdout.write(line)
                    sys.stdout.flush()
            except KeyboardInterrupt:
                proc.terminate()
            proc.wait()
            return

        from apatchy.utils.libfuzzer_ui import LibFuzzerUI

        pulse_interval = kwargs.get("pulse_interval", 60)
        ui = LibFuzzerUI(
            crashes_dir=crashes_dir,
            output_dir=output_dir,
            workers=workers,
            pulse_interval=pulse_interval,
        )
        ui.run(cmd, env=env)
