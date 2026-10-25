"""Docker adapter. Payload containers have no host mounts or network access."""
import json
import secrets
import subprocess
from typing import Any, Callable


def _read_container_file(container: str, path: str, limit: int) -> bytes | None:
    """Read bounded tmpfs data from a separate process after the worker exits."""
    process = subprocess.run(["docker", "exec", container, "head", "-c", str(limit + 1), path],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=5, check=False)
    if process.returncode:
        error = process.stderr.decode("utf-8", errors="replace").lower()
        if "no such file" in error:
            return None
        raise RuntimeError(f"Docker canary inspection failed: {error[-500:]}")
    if len(process.stdout) > limit:
        raise RuntimeError("Container file exceeds size limit")
    return process.stdout


class DockerSandbox:
    """Callable `code -> result` backed by a fresh RestrictedPython container."""

    def __init__(self, image: str = "sandbox-escape-finder:local", timeout: float = 8.0) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.image = image
        self.timeout = timeout
        self._last_state = None
        self._last_marker = None

    def pre_state(self) -> None:
        """A new container's writable tmpfs has no canary."""
        return None

    def snapshot(self) -> str | None:
        """Return the canary read by a separate process after payload execution."""
        return self._last_state

    @property
    def marker(self) -> str | None:
        return self._last_marker

    def __call__(self, code: str) -> dict[str, Any]:
        marker = secrets.token_hex(16)
        container_name = f"sandbox-escape-finder-{secrets.token_hex(8)}"
        self._last_marker = marker
        self._last_state = None
        command = ["docker", "create", "--name", container_name,
                   "--read-only", "--network", "none", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--pids-limit", "64",
                   "--memory", "128m", "--cpus", "0.5",
                   "--tmpfs", "/trial:rw,noexec,nosuid,size=8m,mode=1777",
                   "--user", "65534:65534", "--entrypoint", "sleep", self.image, "infinity"]
        try:
            created = subprocess.run(command, capture_output=True, text=True,
                                     timeout=10, check=False)
        except FileNotFoundError as exc:
            raise RuntimeError("Docker CLI is required for dynamic probes") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Docker container creation timed out") from exc
        if created.returncode:
            return {"executed": False, "status": "runner_error", "error_type": "DockerError",
                    "error": created.stderr[-500:], "oracle_observed": False}

        try:
            booted = subprocess.run(["docker", "start", container_name],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=5, check=False)
            if booted.returncode:
                return {"executed": False, "status": "runner_error", "error_type": "DockerStartError",
                        "oracle_observed": False}
            timed_out = False
            try:
                started = subprocess.run(["docker", "exec", "-i", container_name,
                                          "python", "-m", "sandbox_escape_finder.worker"],
                                         input=json.dumps({"code": code, "marker": marker}) + "\n",
                                         text=True, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, timeout=self.timeout,
                                         check=False)
            except subprocess.TimeoutExpired:
                timed_out = True
                started = None

            canary = _read_container_file(container_name, "/trial/outside/canary", 256)
            self._last_state = canary.decode("utf-8", errors="replace") if canary is not None else None
            raw_result = _read_container_file(container_name, "/trial/runner-result.json", 4096)
            if timed_out:
                return {"executed": False, "status": "timeout", "error_type": "TimeoutExpired",
                        "oracle_observed": True, "container_exit_code": None}
            if raw_result is None:
                return {"executed": False, "status": "runner_error", "error_type": "MissingResult",
                        "oracle_observed": True, "container_exit_code": started.returncode}
            result = json.loads(raw_result)
            if not isinstance(result, dict):
                raise ValueError("Worker result must be an object")
            result["oracle_observed"] = True
            result["container_exit_code"] = started.returncode
            return result
        finally:
            subprocess.run(["docker", "rm", "-f", container_name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5, check=False)


class CanaryOracle:
    """Verify a fresh per-run marker appeared beyond the logical allowed path."""

    def __init__(self, marker_provider: Callable[[], str | None]) -> None:
        self.marker_provider = marker_provider

    def __call__(self, pre_state: str | None, exec_result: dict[str, Any],
                 post_state: str | None) -> bool:
        if exec_result.get("oracle_observed") is False:
            return False
        marker = self.marker_provider()
        return bool(marker and pre_state is None and post_state == marker)
