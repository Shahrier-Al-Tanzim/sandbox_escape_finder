"""Attributed, deterministic corpus; loading never executes payloads."""
import json
import random
from importlib.resources import files


class Payload(str):
    def __new__(cls, code, *, id="custom", technique="custom", source="user supplied", kind="attempt"):
        if not isinstance(code, str) or not code.strip():
            raise ValueError("Payload code must be a nonempty string")
        if not all(isinstance(value, str) and value for value in (id, technique, source, kind)):
            raise ValueError("Payload attribution fields must be nonempty strings")
        obj = super().__new__(cls, code)
        obj.id, obj.technique, obj.source, obj.kind = id, technique, source, kind
        return obj


def load_corpus(config=None):
    """Load built-in and custom payloads, filter, then optionally seed-shuffle."""
    config = config or {}
    rows = json.loads(files("sandbox_escape_finder").joinpath("corpus.json").read_text(encoding="utf-8"))
    rows.extend(config.get("custom_payloads", []))
    payloads = [Payload(row) if isinstance(row, str) else Payload(**row) for row in rows]
    ids = [p.id for p in payloads]
    if len(set(ids)) != len(ids):
        raise ValueError("Payload IDs must be unique")
    categories = config.get("categories")
    payloads = [p for p in payloads if categories is None or p.technique in categories]
    if "seed" in config:
        random.Random(config["seed"]).shuffle(payloads)
    return payloads
