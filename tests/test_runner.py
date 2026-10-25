from sandbox_escape_finder.runner import CanaryOracle


def test_canary_oracle_detects_broken_toy_sandbox(tmp_path) -> None:
    # The toy sandbox deliberately grants open(), making the outside write possible.
    marker = "test-marker"
    canary = tmp_path / "outside" / "canary"
    canary.parent.mkdir()

    def toy_sandbox(code):
        exec(code, {"open": open, "MARKER": marker, "CANARY_PATH": str(canary)})

    # A contained toy run cannot change the observed state.
    oracle = CanaryOracle(lambda: marker)
    assert not oracle(None, {"status": "ok"}, None)
    toy_sandbox("open(CANARY_PATH, 'w').write(MARKER)")
    assert oracle(None, {"status": "ok"}, canary.read_text())
    assert not oracle(None, {"status": "ok"}, "wrong")
    assert not oracle(marker, {"status": "ok"}, marker)
