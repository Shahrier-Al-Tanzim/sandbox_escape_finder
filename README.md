# SandboxEscapeFinder

SandboxEscapeFinder evaluates a local Python execution policy in two ways. The AST analyzer flags source constructs associated with known escape techniques. The dynamic prober runs attributed attempts against a real `RestrictedPython` policy inside fresh Docker containers and checks a disposable canary. An AST finding is a suspicion; a canary hit is an observed policy failure in this test setup.

`RestrictedPython` describes itself as a tool for constructing a restricted Python environment, not an operating-system sandbox. The container supplies the process and filesystem boundary for these tests.

## Install and run

Use Python 3.11 and Docker Desktop with the Linux engine running. The project pins `RestrictedPython==8.1` and uses the same version in the Docker image.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
docker build -t sandbox-escape-finder:local .
.\.venv\Scripts\python.exe examples\quickstart.py --output report.json
.\.venv\Scripts\python.exe -m pytest -q
```

The equivalent POSIX commands use `./.venv/bin/python` and `examples/quickstart.py`. `pytest` builds the Docker image in its integration test. Unit tests can be run without Docker using `pytest -q -m "not integration"`. If Docker is unavailable, the integration test is skipped and the quickstart reports runner errors; it never executes payloads on the host.

## Public API

```python
from sandbox_escape_finder import (
    StaticAnalyzer, DynamicProber, DockerSandbox, CanaryOracle, load_corpus,
    summarize,
)

config = {"seed": 11, "confidence_threshold": 0.7}
analyzer = StaticAnalyzer(config)
findings = analyzer.scan("().__class__.__bases__[0].__subclasses__()")

sandbox_exec = DockerSandbox(image="sandbox-escape-finder:local")
oracle = CanaryOracle(lambda: sandbox_exec.marker)
prober = DynamicProber(sandbox_exec, oracle, config)
report = prober.run(load_corpus())
comparison = summarize(report)
```

`StaticAnalyzer.scan(source_code)` returns dictionaries with technique, AST node type and dump, source excerpt, start/end line and column, confidence, and reason. Invalid source raises `SyntaxError`. `config` can set `detectors` (or `enabled_detectors`), `confidence_threshold`, and `allowed_imports`. Detection uses AST structure and bounded literal folding.

`load_corpus(config)` loads seeded payloads plus `custom_payloads`, filters on `categories`, and can deterministically shuffle with `seed`. Each payload is a `str` with `id`, `technique`, `source`, and `kind` attributes. For example:

```python
custom = {"id": "my-test", "technique": "custom", "source": "local", "code": "answer = 1"}
payloads = load_corpus({"custom_payloads": [custom], "categories": ["custom"]})
```

`DynamicProber.run(payload_corpus)` accepts an iterable of strings and returns one dictionary per payload. It records static findings and flag, whether restricted execution began, status (`ok`, `compile_error`, `runtime_error`, `timeout`, or `runner_error`), error type, canary verdict, elapsed milliseconds, and comparison class. `static_only` means the AST flagged an attempt and the oracle saw no escape; status shows how it was stopped. `static_false_negative` means the oracle saw an escape that the AST missed. `unassessed` marks runner errors and timeouts. These are per-corpus comparisons, not estimated population error rates.

## Technique classes and policy behavior

| Detector | What it looks for | Relevant RestrictedPython control |
|---|---|---|
| `subclass_traversal` | Class, base, MRO, and subclass attribute chains | The compiler rejects underscore-prefixed attribute access. |
| `function_internals` | `__globals__`, `__closure__`, code objects, closure cells | The compiler rejects private attributes; guarded `getattr` also denies underscore attributes. |
| `builtins_recovery` | `__builtins__` and `__import__` | The compiler rejects private names; execution receives only `safe_builtins`. |
| `frame_introspection` | Generator, coroutine, traceback, and frame attributes | Private frame paths are rejected at compile time or denied by the attribute guard. |
| `format_traversal` | Sensitive format-field attribute paths | The supplied `safer_getattr` guard denies `str.format` access at runtime. |
| `dynamic_execution` | Direct `eval`, `exec`, or `compile` | These are absent from `safe_builtins`; embedded private names can also be rejected by the compiler. |
| `forbidden_import` | Imports outside `allowed_imports` | The policy supplies no `__import__` hook, so imports fail at runtime. |

These are syntactic indicators. They can flag blocked code and miss obfuscated or novel paths. Results depend on the `RestrictedPython` version and globals/guards supplied by the host application.

## Isolation and oracle

Each `DockerSandbox(code)` call starts a new Linux container with an unprivileged user, read-only root filesystem, no network, no added capabilities, `no-new-privileges`, CPU/memory/PID limits, timeout, and small writable tmpfs at `/trial`. No host directory is mounted. The worker uses `compile_restricted`, `safe_builtins`, `safer_getattr`, guarded iteration, and no import hook.

The logical allowed directory is `/trial/allowed`. The canary path is `/trial/outside/canary` inside the disposable container. The worker gives restricted code the path and a random marker; `CanaryOracle` returns true when the post-run canary equals that marker and the baseline was empty. This measures an effect outside the Python policy's allowed directory. It does not mean the Docker container was escaped. The trusted worker reads the canary, so a payload that compromises the worker could tamper with its report. Separate Docker filesystem inspection would provide stronger evidence against that threat.

## Observed results

Full corpus run on 2026-10-25: Python 3.11.14, `RestrictedPython==8.1`, Docker Linux engine 28.5.1, `seed=11`. All 15 payloads were assessed. No canary write was observed. These are observations for this policy and corpus, not a proof of general security.

| Payload | Technique | Static flag | Execution status | Dynamic escape |
|---|---|---:|---|---:|
| `subclasses-direct` | subclass traversal | Yes | compile error | No |
| `mro-subclasses` | subclass traversal | Yes | compile error | No |
| `globals-direct` | function internals | Yes | compile error | No |
| `closure-cell` | function internals | Yes | compile error | No |
| `builtins-open` | builtins recovery | Yes | compile error | No |
| `builtin-import` | builtins recovery | Yes | compile error | No |
| `generator-frame` | frame introspection | Yes | compile error | No |
| `exception-traceback` | frame introspection | Yes | compile error | No |
| `format-class` | format traversal | Yes | runtime error | No |
| `format-map` | format traversal | Yes | runtime error | No |
| `eval-builtins` | dynamic execution | Yes | compile error | No |
| `exec-open` | dynamic execution | Yes | compile error | No |
| `direct-import` | forbidden import | Yes | runtime error | No |
| `safe-arithmetic` | control | No | ok | No |
| `safe-list` | control | No | ok | No |

The 13 attempts are `static_only`: flagged by AST, blocked by compilation or runtime policy, and not confirmed as escapes. The two controls are neither flagged nor escaping. The intentionally broken toy sandbox test writes a canary and verifies that the oracle reports a positive result.

## References and attribution

The payloads in `corpus.json` are short adaptations of technique classes described in the catalogs below. Each payload's `source` field identifies its source; code is adapted for the local marker test.

- [RestrictedPython documentation](https://restrictedpython.readthedocs.io/en/latest/)
- [RestrictedPython basic usage](https://restrictedpython.readthedocs.io/en/latest/usage/basic_usage.html)
- [RestrictedPython policies and guards](https://restrictedpython.readthedocs.io/en/latest/usage/policy.html)
- [Pyjailbreaker technique catalog](https://github.com/jailctf/pyjailbreaker)
- [python_sandbox_escapes catalog](https://github.com/moshekaplan/python_sandbox_escapes)

See [plan.md](plan.md) for the staged implementation and Git history.
