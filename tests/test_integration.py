"""These tests execute payloads only inside Docker, never on the host."""
import subprocess
from pathlib import Path

import pytest

from sandbox_escape_finder import CanaryOracle, DockerSandbox, DynamicProber, load_corpus, summarize


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
