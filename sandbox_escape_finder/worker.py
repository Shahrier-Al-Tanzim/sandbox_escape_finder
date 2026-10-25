"""Runs inside a disposable Docker container; never execute this on the host."""
import json
import sys
from pathlib import Path

from RestrictedPython import compile_restricted
from RestrictedPython.Eval import default_guarded_getiter
from RestrictedPython.Guards import guarded_iter_unpack_sequence, safe_builtins, safer_getattr
from RestrictedPython.PrintCollector import PrintCollector


def run(code: str, marker: str) -> dict:
    """Execute one snippet under the documented RestrictedPython policy hooks."""
    allowed = Path("/trial/allowed")
    outside = Path("/trial/outside")
    allowed.mkdir(parents=True, exist_ok=True)
    outside.mkdir(parents=True, exist_ok=True)
    canary = outside / "canary"
    # Every container is new; a preexisting canary indicates setup failure.
    if canary.exists():
        raise RuntimeError("Canary already exists")

    result = {"executed": False, "status": "compile_error", "error_type": None,
              "error": None, "canary_before": None, "canary_after": None}
    try:
        bytecode = compile_restricted(code, filename="<payload>", mode="exec")
    except Exception as exc:
        result["error_type"] = type(exc).__name__
        result["error"] = str(exc)[:1000]
        return result

    globals_dict = {
        "__builtins__": dict(safe_builtins),
        "__name__": "restricted_payload",
        "_getattr_": safer_getattr,
        "_getitem_": lambda obj, index: obj[index],
        "_getiter_": default_guarded_getiter,
        "_iter_unpack_sequence_": guarded_iter_unpack_sequence,
        "_print_": PrintCollector,
        "CANARY_PATH": str(canary),
        "MARKER": marker,
    }
    result["executed"] = True
    result["status"] = "ok"
    try:
        exec(bytecode, globals_dict)
    except Exception as exc:
        result["status"] = "runtime_error"
        result["error_type"] = type(exc).__name__
        result["error"] = str(exc)[:1000]
    if canary.is_file():
        result["canary_after"] = canary.read_text(encoding="utf-8", errors="replace")[:256]
    return result


def main() -> None:
    request = json.loads(sys.stdin.readline())
    if not isinstance(request.get("code"), str) or not isinstance(request.get("marker"), str):
        raise ValueError("Invalid request")
    if len(request["code"]) > 20000 or len(request["marker"]) > 100:
        raise ValueError("Request exceeds size limit")
    result = run(request["code"], request["marker"])
    Path("/trial/runner-result.json").write_text(json.dumps(result), encoding="utf-8")


if __name__ == "__main__":
    main()
