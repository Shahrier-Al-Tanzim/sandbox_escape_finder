# SandboxEscapeFinder

SandboxEscapeFinder is a defensive research tool for evaluating a local
`RestrictedPython` policy. It has two parts:

- `StaticAnalyzer` examines Python source as an AST and reports indicators of
  known sandbox-escape technique classes.
- `DynamicProber` (added in the later implementation stages) runs a small,
  attributed corpus in fresh, disposable containers and uses an automated
  canary oracle to measure policy failures.

RestrictedPython is a source transformation and policy-building library, not a
complete operating-system sandbox. The dynamic runner therefore adds
container-level isolation and never mounts a host directory into a payload
container.

## Development install

This project is tested with Python 3.11.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest
```

The Docker-dependent integration suite needs a running Docker Desktop Linux
engine. Unit tests do not need Docker.

## Project status

See [plan.md](plan.md) for the staged implementation and validation plan. The
final README will include the public dynamic API, corpus attribution, complete
results table, and a runnable quickstart.

## Safety boundary

Run payloads only through the supplied isolated runner. Do not point a canary
at a real system path, mount the project or a host directory into a payload
container, or use this tool against a live service.

## Sources

- [RestrictedPython documentation](https://restrictedpython.readthedocs.io/)
- [Pyjailbreaker technique catalog](https://github.com/jailctf/pyjailbreaker)
- [python_sandbox_escapes catalog](https://github.com/moshekaplan/python_sandbox_escapes)
