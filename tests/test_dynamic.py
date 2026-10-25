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
    corpus = [Payload("x.__class__", id="blocked", technique="subclass_traversal"),
              Payload("ESCAPE", id="missed", technique="custom")]
    report = DynamicProber(sandbox, oracle).run(corpus)

    assert [row["comparison"] for row in report] == ["static_only", "static_false_negative"]
    assert summarize(report)["static_false_negatives"] == ["missed"]


def test_unavailable_runner_is_unassessed() -> None:
    def unavailable(code):
        raise RuntimeError("Docker unavailable")

    report = DynamicProber(unavailable, lambda *args: False).run(["x.__class__"])
    assert report[0]["comparison"] == "unassessed"
    assert report[0]["status"] == "runner_error"
