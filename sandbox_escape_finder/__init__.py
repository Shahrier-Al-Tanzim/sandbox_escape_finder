"""Static analysis utilities for evaluating Python sandbox policies.

Importing this package never executes a payload.
"""
from .static import StaticAnalyzer
from .corpus import Payload, load_corpus
from .runner import DockerSandbox, CanaryOracle
from .dynamic import DynamicProber, summarize

__version__ = "0.1.0"

__all__ = ["StaticAnalyzer", "DynamicProber", "Payload", "load_corpus",
           "DockerSandbox", "CanaryOracle", "summarize"]
