# SandboxEscapeFinder implementation plan

## Completion record (2026-10-25)

Stages 1 through 7 are implemented and merged on `main`. Each stage has its
own branch and focused commit on the public GitHub repository
`Shahrier-Al-Tanzim/sandbox_escape_finder`. The existing empty repository used
an underscore in its name, so that is the published remote name. The final
local check passed 30 tests, including the full Docker corpus integration
test; the quickstart produced one AST finding and 15 per-payload reports with
no unassessed runs. All seven branches and `main` are pushed. Merges were
performed locally after stage tests, so there are no pull requests for these
already merged stages. A follow-up `test/detector-negative-cases` branch added
negative examples for each detector and is also merged and pushed.

The 2026-10-25 audit found that the original canary was observed by the same
worker that executed restricted code. The follow-up `fix/audit-oracle-and-plan`
branch changes this to a separate Docker process that reads the disposable
container's tmpfs after the worker exits. An intentionally broken container
fixture confirms that this external observer sees a canary write. The audit
also corrected the report and plan wording below to match tested behavior.

Stage 8 on `feat/stage-08-probe-validity` audited corpus provenance against
specific upstream files and separated write-canary attempts from read-only
capability probes. The extended corpus contains 17 attempts and two controls;
11 attempts are catalog adaptations. All 19 rows were assessed in the Docker
run, with no observed canary write. All 33 tests and the quickstart passed.
The source links and goal-aware comparison are recorded in `corpus.json`, the
report, and the README.

## Requirement cross-check

| `task.md` requirement | Implementation evidence | Status |
|---|---|---|
| Required public API | `StaticAnalyzer.scan` and `DynamicProber.run` in the installable package | Met |
| At least five AST technique classes with locations | Seven named detectors; positive and negative cases in `tests/test_static.py` | Met |
| Isolated real RestrictedPython execution | `worker.py` uses `compile_restricted`; `runner.py` uses a fresh restricted Docker container per payload | Met |
| Automated oracle | Separate Docker process reads the disposable canary; toy positive in `tests/test_integration.py` | Met |
| At least ten attributed payloads and custom entries | Seventeen attempts plus two controls in `corpus.json`, including 11 adaptations linked to specific catalog files; `load_corpus` accepts `custom_payloads` | Met |
| Static/dynamic mismatch analysis | Per-row `comparison` and `goal`; `summarize` lists all static-only IDs, goal-eligible false positives, false negatives, and unassessed runs | Met |
| Seed-driven reproducibility | `seed` controls deterministic ordering and appears in each report row | Met |
| Quickstart, tests, README, results table | `examples/quickstart.py`, 33 passing tests, and documented 19-row results table | Met |

The result is an empirical check of this policy and corpus. No canary escape
was observed in the full RestrictedPython run; that cannot establish the
security of arbitrary Python sandboxes or novel payloads.

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

The repository uses `main` as the reviewable branch. Each stage was developed
on its own branch, tested locally, and merged after verification:

1. `chore/stage-01-foundation`
2. `feat/stage-02-static-analyzer`
3. `feat/stage-03-payload-corpus`
4. `feat/stage-04-isolated-runner`
5. `feat/stage-05-dynamic-prober`
6. `test/stage-06-verification`
7. `docs/stage-07-documentation`

The repository owner and public visibility were confirmed before publishing.
Each stage has a focused commit in Git history. There are no pull requests for
the stages merged locally; the test runs and this audit record are the review
evidence.

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
have a stable ID, source technique, catalog URL/reference, code, and kind.
Include ordinary safe controls and
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
mounts, and a disposable writable temporary filesystem. A fresh marker is
generated per run; the canary path exists only inside the disposable container. A
payload cannot write to the host through a mounted directory.

Implement `CanaryOracle(pre_state, exec_result, post_state)` as a callable that
checks a cryptographically random marker or file hash at the expected canary
location. Discard worker stdout/stderr, bound the files used for observation,
and capture execution status, exception class, timeout, and container exit
status without returning arbitrary objects across the boundary.

Pass conditions: a normal permitted expression executes, a denied operation is
contained, a deliberately broken toy sandbox changes the canary and is caught,
timed-out containers are removed, and payloads have no host-mounted paths.

## Stage 5: dynamic prober and comparison report

Implement `DynamicProber(sandbox_exec, oracle, config).run(payload_corpus)`.
For every item it will record stable payload metadata, static findings and
static flag, execution/timeout/error status, elapsed time, oracle result, and
the seed used. Runs will be deterministic in ordering and randomization
when the same seed is supplied.

Add derived false-positive and false-negative analysis:

- static-only observation: statically flagged but the oracle reports no escape;
- operational static false positive: a static-only observation whose payload
  actually attempted the write-canary effect;
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

Run syntax and whitespace checks, `pytest`, package installation in a clean
environment, and the quickstart. Record the results in the completion record.
Review the code for accidental host mounts, unbounded output, and swallowed
exceptions.

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

## Stage 8: make the experiment interpretable

The initial corpus mixes programs that try to write the canary with programs
that only inspect a class, frame, or format field. The latter cannot produce a
positive write-canary result even in a permissive policy. Calling every
flagged-but-negative row a static false positive therefore overstates what the
experiment established. Several entries also cite only a catalog homepage,
which is too broad for a research handoff.

On `feat/stage-08-probe-validity`:

1. Check every built-in payload against the two named upstream catalogs. Link
   to a specific source file or example and label a payload as a catalog
   adaptation, task-inspired probe, local variant, or local control. Keep at
   least ten distinct catalog-attributed attempts.
2. Give each payload an explicit goal: `canary_write`, `capability_probe`, or
   `control`.
   Include goal and provenance in per-payload reports. Preserve `static_only`
   for every flagged, non-escaping row, but use `static_false_positives` only
   for probes that actually attempt the write-canary effect. Explain that even
   this is an operational label for this corpus, not a general error rate.
3. Make write-capable catalog adaptations attempt the disposable canary where
   feasible. Keep read-only capability probes visible rather than treating
   their negative canary result as evidence of safety.
4. Add tests for attribution metadata, goal-sensitive comparison, and the full
   Docker corpus. Regenerate the README results table from a fresh run.

Pass conditions: all catalog-attributed items have a specific source link,
all rows state what effect was tested, the two mismatch summaries follow that
goal, tests and quickstart pass, and the published table matches the new
report. These changes improve the strength of the evaluation while keeping
the task's public API and isolation boundary intact.

## Final release checklist

- [x] Every stage branch has a focused commit; test and audit results are
      recorded above. No pull requests were opened for locally merged stages.
- [x] `main` contains merged, tested work; the remote repository is
      [public on GitHub](https://github.com/Shahrier-Al-Tanzim/sandbox_escape_finder).
- [x] `pip install -e .` works in a clean environment.
- [x] Static analyzer has seven named technique classes with positive/negative
      tests and source locations.
- [x] Corpus has 17 attributed attempts, including 11 catalog adaptations,
      plus two safe controls.
- [x] Dynamic runs use fresh disposable isolation and an automated canary oracle.
- [x] Reports include static verdict, execution status, timing, oracle result,
      and false-positive/false-negative comparisons.
- [x] Quickstart and README are complete and evidence-backed.
- [x] Docker and non-Docker test results are clearly distinguished.
- [x] Payloads cannot modify a host path or contact a live service.

## Next maintenance step

For any new detector, add both positive and negative AST cases, an attributed
corpus example, and a Docker integration run. Recheck the results table when
the pinned Python or RestrictedPython version changes.
