import pytest

from sandbox_escape_finder import load_corpus
from sandbox_escape_finder.static import StaticAnalyzer


def test_corpus_is_attributed_and_parseable() -> None:
    corpus = load_corpus()

    assert len(corpus) >= 10
    assert len({payload.id for payload in corpus}) == len(corpus)
    assert all(payload.source and payload.technique for payload in corpus)
    assert all(payload.goal != "unspecified" and payload.provenance != "custom"
               for payload in corpus)
    assert sum(payload.provenance == "catalog_adaptation" for payload in corpus) >= 10
    assert all("/blob/" in payload.source for payload in corpus
               if payload.provenance == "catalog_adaptation")
    assert all(payload.goal == "control" for payload in corpus if payload.kind == "control")
    assert all(isinstance(StaticAnalyzer().scan(payload), list) for payload in corpus)


def test_seed_and_category_filter_are_reproducible() -> None:
    config = {"seed": 42, "categories": ["subclass_traversal", "control"]}
    first = load_corpus(config)

    assert [payload.id for payload in first] == [payload.id for payload in load_corpus(config)]
    assert all(payload.technique in config["categories"] for payload in first)


def test_custom_payloads_are_supported_and_validated() -> None:
    corpus = load_corpus({"custom_payloads": [{"id": "custom-1", "technique": "custom",
                                               "source": "local test", "code": "answer = 1"}]})
    assert corpus[-1].id == "custom-1"

    with pytest.raises(ValueError):
        load_corpus({"custom_payloads": [{"id": "subclasses-direct", "code": "x = 1"}]})

    with pytest.raises(ValueError):
        load_corpus({"custom_payloads": [{"id": "bad-goal", "code": "x = 1", "goal": "magic"}]})
