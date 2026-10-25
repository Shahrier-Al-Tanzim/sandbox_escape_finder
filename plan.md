# SandboxEscapeFinder implementation plan

## Completion record (2026-10-25)

Stages 1 through 7 are implemented and merged on `main`. Each stage has its
own branch and focused commit on the public GitHub repository
`Shahrier-Al-Tanzim/sandbox_escape_finder`. The existing empty repository used
an underscore in its name, so that is the published remote name. The final
local check passed 28 tests, including the full Docker corpus integration
test; the quickstart produced one AST finding and 15 per-payload reports with
no unassessed runs. All seven branches and `main` are pushed. Merges were
performed locally after stage tests, so there are no pull requests for these
already merged stages. A follow-up `test/detector-negative-cases` branch added
negative examples for each detector and is also merged and pushed.

## Goal and definition of done

Build an installable Python package that combines an AST-based detector with a
safe, reproducible dynamic prober for a local `RestrictedPython` policy. The
finished project must provide the required `StaticAnalyzer` and
`DynamicProber` APIs, an attributed corpus of at least ten payloads, an
automated canary oracle, a quickstart, tests, and documentation that explains
the results and limitations. It must be possible to explain every submitted
line of code.

This is a defensive evaluation of a local, disposable sandbox. Payloads will
never be run against a live service, a real system path, or a host-mounted
directory.

## Working agreement and GitHub workflow

The repository will use `main` as the protected, reviewable branch. Each stage
will be developed on its own branch, tested locally, and merged through a pull
request (or an equivalent reviewed merge):

1. `chore/stage-01-foundation`
2. `feat/stage-02-static-analyzer`
3. `feat/stage-03-payload-corpus`
4. `feat/stage-04-isolated-runner`
5. `feat/stage-05-dynamic-prober`
6. `test/stage-06-verification`
7. `docs/stage-07-documentation`

Before creating a remote repository, we will confirm its owner/name and
visibility. Until then, all work remains local. Every stage gets a focused
commit, a test result recorded in the pull request, and a short explanation of
what changed and what remains. No stage is merged while its pass conditions
fail.

## Stage 1: foundation and reproducible environment

Create the package layout, `pyproject.toml`, pinned Python/RestrictedPython
dependencies after checking compatibility, a `.gitignore`, a Docker build
context, and a minimal README. Preserve the supplied task specification and
record the exact RestrictedPython version and Python version used. Audit the
existing scaffolding before reusing it; incomplete or untested code is not
treated as finished implementation.

Pass conditions: `pip install -e .` succeeds in a clean virtual environment,
the package imports without running any payload, and a basic test command
starts successfully.

## Stage 2: AST static analyzer

Implement `StaticAnalyzer(config).scan(source_code)` using Python's `ast`
module. Findings will be JSON-serializable records containing the named
technique, node type and dump/source excerpt, start/end line and column, a
confidence score, and a short reason. Syntax errors will be reported clearly.

The first detector set will cover at least these six classes:

- subclass/MRO traversal (`__class__`, `__base__`, `__bases__`, `__mro__`,
  `__subclasses__`);
- function internals (`__globals__`, `__closure__`, `__code__`,
  `cell_contents`);
- builtins/import recovery (`__builtins__`, `__import__`);
- generator, coroutine, traceback, and frame inspection (`gi_frame`,
  `cr_frame`, `f_globals`, `f_builtins`, `f_back`, and related names);
- format-string attribute traversal (`format`/`format_map` fields that reach
  sensitive attributes);
- dynamic evaluation and import policy bypass (`eval`, `exec`, `compile`, and
  imports outside the configured allow list).

Detection will use AST structure and bounded literal folding for constructs
such as `getattr(x, "__globals__")`; regexes will not be the detector. The
configuration will control enabled detectors, confidence threshold, and import
allow list.

Pass conditions: positive and negative unit cases exist for every detector,
locations point to the correct AST nodes, detector order is deterministic, and
ordinary code with similarly named prose strings is not incorrectly treated as
an attribute access.

## Stage 3: attributed payload corpus

Study and cite the RestrictedPython documentation and the two supplied
technique catalogs. Create a versioned corpus with at least ten benignly
contained escape-attempt programs spanning the six classes. Each item will
have a stable ID, source technique, catalog URL/reference, code, expected
static technique, and a safety category. Include ordinary safe controls and
allow additional user payloads through configuration.

The corpus is evidence for testing, not a promise that a payload escapes. We
will avoid payloads whose only purpose is destructive host activity; the only
effect we measure is a disposable canary marker inside the test container.

Pass conditions: the loader returns at least ten attributed items, rejects
malformed metadata, honors category filters and a seed, and every corpus item
is statically analyzable without importing or executing it.

## Stage 4: isolated execution runner and oracle

Implement a documented `sandbox_exec: str -> result` adapter around the
official RestrictedPython restricted-compile/exec flow, with explicit guarded
globals, builtins, imports, attribute access, and resource limits. Run each
payload in a fresh Docker container (or an equivalently isolated subprocess
only when the container backend is unavailable and the run is clearly marked
limited).

The default container will use a read-only root filesystem, no network, no
capabilities, an unprivileged user, a small CPU/memory/PID/time budget, no host
mounts, and a disposable writable temporary filesystem. The canary path will
be generated per run and placed only inside the disposable container. A
payload cannot write to the host through a mounted directory.

Implement `CanaryOracle(pre_state, exec_result, post_state)` as a callable that
checks a cryptographically random marker or file hash at the expected canary
location. Capture execution status, exception class, stdout/stderr limits,
timeout, and container exit status without returning arbitrary objects across
the boundary.

Pass conditions: a normal permitted expression executes, a denied operation is
contained, a deliberately broken toy sandbox changes the canary and is caught,
timeouts are stopped, and host-side canary paths remain unchanged.

## Stage 5: dynamic prober and comparison report

Implement `DynamicProber(sandbox_exec, oracle, config).run(payload_corpus)`.
For every item it will record stable payload metadata, static findings and
static flag, execution/timeout/error status, elapsed time, oracle result, and
the seed/config used. Runs will be deterministic in ordering and randomization
when the same seed is supplied.

Add derived false-positive and false-negative analysis:

- static false positive: statically flagged but the oracle reports no escape;
- dynamic false negative: oracle confirms an escape but no relevant static
  finding exists.

The report will distinguish “could not execute” from “executed and did not
escape”; neither is silently counted as a safe result.

Pass conditions: the full corpus runs through the same public API, reports
contain all required fields, repeated seeded runs have the same ordering and
verdicts, and the two mismatch sets are populated correctly on controlled
fixtures.

## Stage 6: verification and end-to-end tests

Add unit tests for all AST detector classes, configuration validation, corpus
metadata, deterministic seeding, and oracle correctness. Add an end-to-end
test that builds/runs the pinned RestrictedPython container and exercises the
complete corpus. Mark Docker-dependent tests explicitly so unit tests remain
usable when Docker is unavailable; an end-to-end result must never be faked.

Run formatting/lint checks, `pytest`, package installation in a clean
environment, and the quickstart. Save the exact commands and results in the
release checklist. Review the code for secret leakage, accidental host mounts,
unbounded output, path traversal, and swallowed exceptions.

Pass conditions: all non-integration tests pass locally, the Docker integration
test passes on a running Docker engine, and the quickstart produces findings,
per-payload reports, and mismatch summaries.

## Stage 7: README, quickstart, and research handoff

Write `examples/quickstart.py` that runs the analyzer and prober and prints a
compact JSON report. The README will contain installation, API usage, the
architecture, each technique's meaning, the RestrictedPython policy boundary,
the canary/oracle design, isolation assumptions, configuration examples, and a
results table with payload, technique, static flag, execution status, and
dynamic escape result.

Document limitations explicitly: AST indicators are heuristics, a policy
library is not a complete operating-system sandbox, and “no escape observed”
is not a proof of security. Cite the official RestrictedPython documentation
and the two payload catalogs used to attribute the corpus.

Pass conditions: a new user can install and run the quickstart from the README,
the public API snippet works, all claims match recorded test evidence, and the
final review can explain every detector, isolation control, and oracle field.

## Final release checklist

- [ ] Every stage branch has a focused commit and review record.
- [ ] `main` contains only merged, tested work; the remote repository URL and
      visibility are recorded.
- [ ] `pip install -e .` works in a clean environment.
- [ ] Static analyzer has six named technique classes with positive/negative
      tests and source locations.
- [ ] Corpus has at least ten attributed payloads and safe controls.
- [ ] Dynamic runs use fresh disposable isolation and an automated canary oracle.
- [ ] Reports include static verdict, execution status, timing, oracle result,
      and false-positive/false-negative comparisons.
- [ ] Quickstart and README are complete and evidence-backed.
- [ ] Docker and non-Docker test results are clearly distinguished.
- [ ] No test can modify a real host path or contact a live service.

## Immediate next action

After this plan is reviewed, initialize Git locally, create the initial
`main` commit containing the plan and task specification, then begin
`chore/stage-01-foundation`. The GitHub remote and branch publication will be
done only after its repository owner, name, and visibility are known.
