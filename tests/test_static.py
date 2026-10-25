import pytest

from sandbox_escape_finder import StaticAnalyzer


@pytest.mark.parametrize(
    ("source", "technique"),
    [
        ("().__class__.__bases__[0].__subclasses__()", "subclass_traversal"),
        ("def f():\n    return 1\nf.__globals__", "function_internals"),
        ("__builtins__['__import__']('os')", "builtins_recovery"),
        ("(x for x in ()).gi_frame.f_globals", "frame_introspection"),
        ('"{0.__class__}".format(())', "format_traversal"),
        ("eval('1 + 1')", "dynamic_execution"),
        ("import os", "forbidden_import"),
    ],
)
def test_known_techniques_are_detected(source: str, technique: str) -> None:
    findings = StaticAnalyzer().scan(source)

    matching = [finding for finding in findings if finding["technique"] == technique]
    assert matching
    assert matching[0]["lineno"] >= 1
    assert matching[0]["col_offset"] >= 0
    assert matching[0]["end_lineno"] >= matching[0]["lineno"]
    assert matching[0]["source"]


def test_literal_getattr_is_detected_without_evaluating_source() -> None:
    findings = StaticAnalyzer().scan("getattr(lambda: None, '__glo' + 'bals__')")

    assert any(finding["technique"] == "function_internals" for finding in findings)


def test_plain_strings_and_safe_source_do_not_match() -> None:
    source = "message = 'Documentation mentions __globals__ but uses no access'\nresult = 2 + 2"

    assert StaticAnalyzer().scan(source) == []


@pytest.mark.parametrize(
    ("technique", "source"),
    [
        ("subclass_traversal", "value = obj.__classroom__"),
        ("function_internals", "value = obj.__globals_backup__"),
        ("builtins_recovery", "label = '__builtins__'"),
        ("frame_introspection", "value = obj.frame_count"),
        ("format_traversal", 'result = "{0.__classroom__}".format(person)'),
        ("dynamic_execution", "result = execute_plan()"),
        ("forbidden_import", "import math"),
    ],
)
def test_each_detector_has_a_negative_case(technique: str, source: str) -> None:
    config = {"detectors": [technique], "allowed_imports": ["math"]}
    assert StaticAnalyzer(config).scan(source) == []


def test_detector_configuration_and_import_allow_list() -> None:
    source = "import math\neval('1')"
    analyzer = StaticAnalyzer({"enabled_detectors": ["forbidden_import"], "allowed_imports": ["math"]})

    assert analyzer.scan(source) == []


@pytest.mark.parametrize("config", [{"detectors": ["unknown"]}, {"confidence_threshold": 2}])
def test_invalid_configuration_is_rejected(config: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        StaticAnalyzer(config)


def test_invalid_python_is_reported_to_the_caller() -> None:
    with pytest.raises(SyntaxError):
        StaticAnalyzer().scan("def broken(:\n")
