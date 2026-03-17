"""Thin wrapper around :func:`subprocess.run` with logging.

Provides :meth:`ProcessRunner.run_command` (direct execution) and
:meth:`ProcessRunner.run_build` (scrolling Rich panel when not verbose)
used throughout the framework to execute external processes.
"""

import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from apatchy.utils.logger import get_logger

logger = get_logger(__name__)


class ProcessRunner:
    """Execute shell commands with automatic logging.

    Parameters
    ----------
    verbose : bool
        When *True*, :meth:`run_build` prints raw output to the terminal
        instead of rendering a Rich scrolling panel.
    """

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    @staticmethod
    def run_command(
        command: Union[str, List[str]],
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
        check: bool = True,
        stdin: Optional[Any] = None,
        capture_output: bool = True,
        stream: bool = False,
        label: str = "Building...",
    ) -> subprocess.CompletedProcess:
        """Run a shell command and log output.

        Parameters
        ----------
        stream : bool
            When *True*, show output in a Rich scrolling panel instead of
            capturing silently or printing raw.
        label : str
            Panel title used when *stream* is True.
        """
        if isinstance(command, list):
            cmd_str = " ".join(shlex.quote(arg) for arg in command)
        else:
            cmd_str = command
            command = shlex.split(command)

        if not stream:
            logger.info(f"Running: {cmd_str}")

        if stream:
            from apatchy.utils.ui import run_stream_panel

            returncode, output = run_stream_panel(
                command,
                cwd=str(cwd) if cwd else None,
                env=env,
                label=label,
            )
            if check and returncode != 0:
                logger.error(f"Command failed with exit code {returncode}")
                logger.error(f"Output:\n{output}")
                raise subprocess.CalledProcessError(
                    returncode,
                    command,
                    output=output,
                    stderr="",
                )
            return subprocess.CompletedProcess(
                command,
                returncode,
                stdout=output,
                stderr="",
            )

        try:
            # When capture_output is False, we let stdout/stderr go to terminal
            if capture_output:
                stdout_arg = subprocess.PIPE
                stderr_arg = subprocess.PIPE
            else:
                stdout_arg = None
                stderr_arg = None

            process = subprocess.run(
                command,
                cwd=cwd,
                env=env,
                check=check,
                text=True,
                stdout=stdout_arg,
                stderr=stderr_arg,
                input=stdin if isinstance(stdin, str) else None,
            )
            return process
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with exit code {e.returncode}")
            logger.error(f"Stdout: {e.stdout}")
            logger.error(f"Stderr: {e.stderr}")
            raise

    def run_build(
        self,
        command: Union[str, List[str]],
        label: str = "Building...",
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """Run a build command with appropriate output mode.

        When *self.verbose* is False the output is rendered inside a Rich
        scrolling panel.  When *self.verbose* is True the raw output streams
        directly to the terminal.
        """
        if self.verbose:
            return self.run_command(command, capture_output=False, **kwargs)
        return self.run_command(command, stream=True, label=label, **kwargs)
