"""These tests execute payloads only inside Docker, never on the host."""
import subprocess
import secrets
from pathlib import Path

import pytest

from sandbox_escape_finder import CanaryOracle, DockerSandbox, DynamicProber, load_corpus, summarize
from sandbox_escape_finder.runner import _read_container_file


def _docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, timeout=5, check=False).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="Docker Linux engine unavailable")
def test_full_corpus_against_restrictedpython() -> None:
    project_root = Path(__file__).resolve().parents[1]
    build = subprocess.run(["docker", "build", "-t", "sandbox-escape-finder:local", str(project_root)],
                           capture_output=True, text=True, timeout=180, check=False)
    assert build.returncode == 0, build.stderr[-2000:]
    sandbox = DockerSandbox()
    oracle = CanaryOracle(lambda: sandbox.marker)
    report = DynamicProber(sandbox, oracle, {"seed": 11}).run(load_corpus())

    assert len(report) == len(load_corpus())
    assert all(row["status"] not in {"runner_error", "timeout"} for row in report)
    assert any(row["status"] == "ok" for row in report)
    assert any(row["static_flag"] for row in report)
    assert all(not row["dynamic_escape"] for row in report if row["kind"] == "control")
    assert summarize(report)["total"] == len(report)


@pytest.mark.integration
@pytest.mark.skipif(not _docker_available(), reason="Docker Linux engine unavailable")
def test_external_oracle_catches_broken_container_policy() -> None:
    # This fixture deliberately writes the disposable canary using unrestricted
    # Python, but only inside a Docker container with no host mount or network.
    name = f"sandbox-escape-finder-toy-{secrets.token_hex(5)}"
    marker = secrets.token_hex(8)
    create = subprocess.run(
        ["docker", "create", "--name", name, "--network", "none", "--read-only",
         "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
         "--tmpfs", "/trial:rw,noexec,nosuid,size=8m,mode=1777", "--user", "65534:65534",
         "--entrypoint", "sleep", "sandbox-escape-finder:local", "infinity"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert create.returncode == 0, create.stderr
    try:
        subprocess.run(["docker", "start", name], capture_output=True, timeout=5, check=True)
        source = ("from pathlib import Path; p = Path('/trial/outside/canary'); "
                  "p.parent.mkdir(parents=True, exist_ok=True); p.write_text('" + marker + "')")
        subprocess.run(["docker", "exec", name, "python", "-c", source],
                       capture_output=True, timeout=5, check=True)
        observed = _read_container_file(name, "/trial/outside/canary", 256)
        assert CanaryOracle(lambda: marker)(None, {"oracle_observed": True}, observed.decode())
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                       timeout=5, check=False)
