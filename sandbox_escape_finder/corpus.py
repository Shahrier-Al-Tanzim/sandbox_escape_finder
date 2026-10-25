"""Attributed, deterministic corpus; loading never executes payloads."""
import json
import random
from importlib.resources import files
from typing import Any


class Payload(str):
    def __new__(cls, code: str, *, id: str = "custom", technique: str = "custom",
                source: str = "user supplied", kind: str = "attempt",
                goal: str = "unspecified", provenance: str = "custom") -> "Payload":
        if not isinstance(code, str) or not code.strip():
            raise ValueError("Payload code must be a nonempty string")
        if not all(isinstance(value, str) and value for value in
                   (id, technique, source, kind, goal, provenance)):
            raise ValueError("Payload attribution fields must be nonempty strings")
        if goal not in {"canary_write", "capability_probe", "control", "unspecified"}:
            raise ValueError(f"Unsupported payload goal: {goal}")
        if provenance not in {"catalog_adaptation", "task_inspired", "local_variant",
                              "local_control", "custom"}:
            raise ValueError(f"Unsupported payload provenance: {provenance}")
        obj = super().__new__(cls, code)
        obj.id, obj.technique, obj.source, obj.kind = id, technique, source, kind
        obj.goal, obj.provenance = goal, provenance
        return obj


def load_corpus(config: dict[str, Any] | None = None) -> list[Payload]:
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
