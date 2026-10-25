"""Payloads are strings with optional attribution metadata."""
import json
from importlib.resources import files


class Payload(str):
    def __new__(cls, code, *, id="custom", technique="custom", source="user supplied", kind="attempt"):
        obj = super().__new__(cls, code)
        obj.id, obj.technique, obj.source, obj.kind = id, technique, source, kind
        return obj


def load_corpus(config=None):
    config = config or {}
    rows = json.loads(files("sandbox_escape_finder").joinpath("corpus.json").read_text(encoding="utf-8"))
    rows.extend(config.get("custom_payloads", []))
    payloads = [Payload(row) if isinstance(row, str) else Payload(**row) for row in rows]
    categories = config.get("categories")
    return [p for p in payloads if categories is None or p.technique in categories]
