"""Syntactic indicators, not a proof that a program can or cannot escape."""
import ast
import string
from typing import Any

ATTRIBUTES = {
    "subclass_traversal": {"__class__", "__base__", "__bases__", "__mro__", "__subclasses__"},
    "function_internals": {"__globals__", "__closure__", "__code__", "cell_contents"},
    "builtins_recovery": {"__builtins__", "__builtin__", "__import__"},
    "frame_introspection": {"gi_frame", "cr_frame", "ag_frame", "f_globals", "f_builtins",
                            "f_back", "tb_frame", "__traceback__"},
}
TECHNIQUES = set(ATTRIBUTES) | {"format_traversal", "dynamic_execution", "forbidden_import"}


def _literal_string(node: ast.AST) -> str | None:
    """Bounded constant folding; never evaluate user code."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value[:4096]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal_string(node.left), _literal_string(node.right)
        if left is not None and right is not None:
            return (left + right)[:4096]
    return None


class StaticAnalyzer:
    """Find syntactic indicators of known Python sandbox escape techniques.

    Findings identify potentially risky source constructs; they never prove an
    escape can succeed under a particular policy.
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        config = config or {}
        if "detectors" in config and "enabled_detectors" in config:
            raise ValueError("Specify either detectors or enabled_detectors, not both")
        self.enabled = set(config.get("detectors", config.get("enabled_detectors", TECHNIQUES)))
        if self.enabled - TECHNIQUES:
            raise ValueError(f"Unknown detectors: {self.enabled - TECHNIQUES}")
        self.threshold = float(config.get("confidence_threshold", 0.7))
        if not 0 <= self.threshold <= 1:
            raise ValueError("confidence_threshold must be between 0 and 1")
        self.allowed_imports = set(config.get("allowed_imports", []))

    def scan(self, source_code: str) -> list[dict[str, Any]]:
        """Return JSON-serializable AST findings. Invalid Python raises SyntaxError."""
        tree = ast.parse(source_code)
        findings = []
        seen = set()

        def add(technique: str, node: ast.AST, confidence: float, reason: str) -> None:
            key = (technique, node.lineno, node.col_offset)
            if technique not in self.enabled or confidence < self.threshold or key in seen:
                return
            seen.add(key)
            findings.append({"technique": technique, "node_type": type(node).__name__,
                             "node": ast.dump(node, include_attributes=False),
                             "lineno": node.lineno, "col_offset": node.col_offset,
                             "end_lineno": node.end_lineno, "end_col_offset": node.end_col_offset,
                             "source": ast.get_source_segment(source_code, node),
                             "confidence": confidence, "reason": reason})

        def check_name(name: str | None, node: ast.AST, confidence: float = 0.95) -> None:
            for technique, names in ATTRIBUTES.items():
                if name in names:
                    add(technique, node, confidence, f"Sensitive access: {name}")

        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                check_name(node.attr, node)
            elif isinstance(node, ast.Name):
                check_name(node.id, node)
            elif isinstance(node, ast.Subscript):
                check_name(_literal_string(node.slice), node, 0.8)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = [n.name for n in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                if any(m.split(".")[0] not in self.allowed_imports for m in modules):
                    add("forbidden_import", node, 0.85, "Import outside configured allow list")
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in {"getattr", "hasattr"} and len(node.args) > 1:
                        check_name(_literal_string(node.args[1]), node, 0.9)
                    if node.func.id in {"eval", "exec", "compile"}:
                        add("dynamic_execution", node, 0.85, "Runtime code evaluation")
                if isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "format_map"}:
                    template = _literal_string(node.func.value)
                    if template is not None:
                        try:
                            fields = [f for _, f, _, _ in string.Formatter().parse(template) if f]
                        except ValueError:
                            fields = []
                        if any(any(name in field for names in ATTRIBUTES.values() for name in names)
                               for field in fields):
                            add("format_traversal", node, 0.9, "Format field traverses sensitive attributes")
        return sorted(findings, key=lambda f: (f["lineno"], f["col_offset"], f["technique"]))
