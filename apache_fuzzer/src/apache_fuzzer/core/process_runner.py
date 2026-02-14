import subprocess
import shlex
from pathlib import Path
from typing import Optional, List, Union, Dict, Any
from apache_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

class ProcessRunner:
    @staticmethod
    def run_command(
        command: Union[str, List[str]], 
        cwd: Optional[Union[str, Path]] = None, 
        env: Optional[Dict[str, str]] = None, 
        check: bool = True, 
        stdin: Optional[Any] = None, 
        capture_output: bool = True
    ) -> subprocess.CompletedProcess:
        """
        Runs a shell command and logs output.
        """
        if isinstance(command, list):
            cmd_str = " ".join(shlex.quote(arg) for arg in command)
        else:
            cmd_str = command
            command = shlex.split(command)

        logger.info(f"Running: {cmd_str}")

        try:
            # When capture_output is False, we let stdout/stderr go to terminal
            # This is key for AFL fuzzing UI
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
