"""Compare AST indicators with observable effects of isolated execution."""
import random
import time
from typing import Any, Iterable

from .static import StaticAnalyzer


class DynamicProber:
    """Run attributed strings through a callable sandbox and a callable oracle.

    `sandbox_exec(code)` returns an execution result dict. If it exposes
    `snapshot()`, the oracle also receives the observed post-run state.
    `pre_state()` may be exposed when the backend has a meaningful baseline.
    """

    def __init__(self, sandbox_exec, oracle, config: dict[str, Any] | None = None):
        if not callable(sandbox_exec) or not callable(oracle):
            raise TypeError("sandbox_exec and oracle must be callable")
        self.sandbox_exec = sandbox_exec
        self.oracle = oracle
        self.config = config or {}
        self.analyzer = StaticAnalyzer(self.config)

    def run(self, payload_corpus: Iterable[str]) -> list[dict[str, Any]]:
        """Return one JSON-serializable comparison record per payload."""
        payloads = list(payload_corpus)
        if "seed" in self.config:
            random.Random(self.config["seed"]).shuffle(payloads)
        categories = self.config.get("categories")
        report = []
        for index, payload in enumerate(payloads):
            if categories is not None and getattr(payload, "technique", "custom") not in categories:
                continue
            started = time.perf_counter()
            try:
                findings = self.analyzer.scan(str(payload))
                static_error = None
            except SyntaxError as exc:
                findings = []
                static_error = f"SyntaxError: {exc.msg} at line {exc.lineno}"
            pre = self.sandbox_exec.pre_state() if hasattr(self.sandbox_exec, "pre_state") else None
            try:
                result = self.sandbox_exec(str(payload))
                if not isinstance(result, dict):
                    raise TypeError("sandbox_exec must return a dict")
            except Exception as exc:
                result = {"executed": False, "status": "runner_error",
                          "error_type": type(exc).__name__, "error": str(exc)[:1000]}
            post = self.sandbox_exec.snapshot() if hasattr(self.sandbox_exec, "snapshot") else None
            status = result.get("status", "runner_error")
            assessed = status not in {"runner_error", "timeout"}
            escaped = bool(self.oracle(pre, result, post)) if assessed else False
            flagged = bool(findings)
            if not assessed:
                comparison = "unassessed"
            elif escaped and not flagged:
                comparison = "static_false_negative"
            elif flagged and not escaped:
                comparison = "static_only"
            elif escaped:
                comparison = "both"
            else:
                comparison = "neither"
            report.append({"id": getattr(payload, "id", f"payload-{index}"),
                           "technique": getattr(payload, "technique", "custom"),
                           "source": getattr(payload, "source", "user supplied"),
                           "kind": getattr(payload, "kind", "attempt"),
                           "static_flag": flagged, "findings": findings,
                           "static_error": static_error, "executed": bool(result.get("executed")),
                           "status": status, "error_type": result.get("error_type"),
                           "error": result.get("error"), "dynamic_escape": escaped,
                           "comparison": comparison,
                           "elapsed_ms": round((time.perf_counter() - started) * 1000, 3)})
        return report


def summarize(report: list[dict[str, Any]]) -> dict[str, Any]:
    """Keep incomplete runs separate from empirical static/dynamic mismatches."""
    return {
        "total": len(report),
        "confirmed_escapes": [row["id"] for row in report if row["dynamic_escape"]],
        "static_only": [row["id"] for row in report if row["comparison"] == "static_only"],
        "static_false_negatives": [row["id"] for row in report if row["comparison"] == "static_false_negative"],
        "unassessed": [row["id"] for row in report if row["comparison"] == "unassessed"],
    }
