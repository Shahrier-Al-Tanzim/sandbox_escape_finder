import sandbox_escape_finder


def test_public_import_is_safe() -> None:
    assert sandbox_escape_finder.__version__ == "0.1.0"
    assert "StaticAnalyzer" in sandbox_escape_finder.__all__
