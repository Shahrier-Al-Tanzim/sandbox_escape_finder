from sandbox_escape_finder.runner import CanaryOracle
from io import StringIO


def test_canary_oracle_detects_broken_toy_sandbox() -> None:
    # The toy sandbox deliberately grants a file-like writer in memory.
    marker = "test-marker"
    canary = StringIO()

    def toy_sandbox(code):
        exec(code, {"open": lambda *args: canary, "MARKER": marker, "CANARY_PATH": "toy"})

    # A contained toy run cannot change the observed state.
    oracle = CanaryOracle(lambda: marker)
    assert not oracle(None, {"status": "ok"}, None)
    toy_sandbox("open(CANARY_PATH, 'w').write(MARKER)")
    assert oracle(None, {"status": "ok"}, canary.getvalue())
    assert not oracle(None, {"status": "ok"}, "wrong")
    assert not oracle(marker, {"status": "ok"}, marker)
