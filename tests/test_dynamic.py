from sandbox_escape_finder import CanaryOracle, DynamicProber, Payload, summarize


class ToySandbox:
    def __init__(self):
        self.marker = "toy-marker"
        self.state = None

    def __call__(self, code):
        # An intentionally broken policy: a raw file-effect signal is granted.
        self.state = self.marker if "ESCAPE" in code else None
        return {"executed": True, "status": "ok"}

    def snapshot(self):
        return self.state


def test_prober_reports_static_only_and_static_false_negative() -> None:
    sandbox = ToySandbox()
    oracle = CanaryOracle(lambda: sandbox.marker)
    corpus = [Payload("x.__class__", id="blocked", technique="subclass_traversal",
                      goal="canary_write"),
              Payload("ESCAPE", id="missed", technique="custom")]
    report = DynamicProber(sandbox, oracle).run(corpus)

    assert [row["comparison"] for row in report] == ["static_only", "static_false_negative"]
    assert summarize(report)["static_false_negatives"] == ["missed"]
    assert summarize(report)["static_false_positives"] == ["blocked"]


def test_capability_probe_is_not_counted_as_write_canary_false_positive() -> None:
    sandbox = ToySandbox()
    row = DynamicProber(sandbox, CanaryOracle(lambda: sandbox.marker)).run(
        [Payload("x.__class__", id="read-only", technique="subclass_traversal",
                 goal="capability_probe")]
    )[0]
    assert row["comparison"] == "static_only"
    assert summarize([row])["static_only"] == ["read-only"]
    assert summarize([row])["static_false_positives"] == []


def test_unavailable_runner_is_unassessed() -> None:
    def unavailable(code):
        raise RuntimeError("Docker unavailable")

    report = DynamicProber(unavailable, lambda *args: False).run(["x.__class__"])
    assert report[0]["comparison"] == "unassessed"
    assert report[0]["status"] == "runner_error"


def test_canary_hit_survives_worker_timeout() -> None:
    class TimedOutSandbox(ToySandbox):
        def __call__(self, code):
            self.state = self.marker
            return {"executed": False, "status": "timeout", "oracle_observed": True}

    sandbox = TimedOutSandbox()
    row = DynamicProber(sandbox, CanaryOracle(lambda: sandbox.marker)).run(["ESCAPE"])[0]
    assert row["dynamic_escape"]
    assert row["comparison"] == "static_false_negative"
