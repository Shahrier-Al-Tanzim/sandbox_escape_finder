"""Docker adapter. Payload containers have no host mounts or network access."""
import json
import secrets
import subprocess


class DockerSandbox:
    """Callable `code -> result` backed by a fresh RestrictedPython container."""

    def __init__(self, image: str = "sandbox-escape-finder:local", timeout: float = 8.0):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.image = image
        self.timeout = timeout
        self._last_state = None
        self._last_marker = None

    def snapshot(self):
        """Return the previous run's observable canary state."""
        return self._last_state

    @property
    def marker(self):
        return self._last_marker

    def __call__(self, code: str) -> dict:
        marker = secrets.token_hex(16)
        container_name = f"sandbox-escape-finder-{secrets.token_hex(8)}"
        self._last_marker = marker
        self._last_state = None
        command = ["docker", "run", "--rm", "--name", container_name,
                   "-i", "--read-only", "--network", "none",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--pids-limit", "64", "--memory", "128m", "--cpus", "0.5",
                   "--tmpfs", "/trial:rw,noexec,nosuid,size=8m,mode=1777",
                   "--user", "65534:65534", self.image]
        try:
            process = subprocess.run(command, input=json.dumps({"code": code, "marker": marker}) + "\n",
                                     text=True, capture_output=True, timeout=self.timeout, check=False)
        except FileNotFoundError as exc:
            raise RuntimeError("Docker CLI is required for dynamic probes") from exc
        except subprocess.TimeoutExpired:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True,
                           text=True, timeout=5, check=False)
            return {"executed": False, "status": "timeout", "error_type": "TimeoutExpired"}
        if process.returncode != 0:
            return {"executed": False, "status": "runner_error", "error_type": "DockerError",
                    "error": process.stderr[-1000:]}
        try:
            result = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            return {"executed": False, "status": "runner_error", "error_type": type(exc).__name__}
        self._last_state = result.get("canary_after")
        return result


class CanaryOracle:
    """Verify a fresh per-run marker appeared beyond the logical allowed path."""

    def __init__(self, marker_provider):
        self.marker_provider = marker_provider

    def __call__(self, pre_state, exec_result, post_state) -> bool:
        marker = self.marker_provider()
        return bool(marker and pre_state is None and post_state == marker)
