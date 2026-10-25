"""Run the documented AST scan and full Docker-isolated corpus."""
import argparse
import json
import sys
from pathlib import Path

from sandbox_escape_finder import (
    CanaryOracle, DockerSandbox, DynamicProber, StaticAnalyzer, load_corpus, summarize,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SandboxEscapeFinder quickstart")
    parser.add_argument("--output", type=Path, help="Save the JSON report to this file")
    parser.add_argument("--seed", type=int, default=11)
    args = parser.parse_args()

    config = {"seed": args.seed}
    source = "().__class__.__bases__[0].__subclasses__()"
    findings = StaticAnalyzer(config).scan(source)
    sandbox_exec = DockerSandbox()
    oracle = CanaryOracle(lambda: sandbox_exec.marker)
    report = DynamicProber(sandbox_exec, oracle, config).run(load_corpus())
    document = {"source": source, "findings": findings,
                "report": report, "summary": summarize(report)}
    rendered = json.dumps(document, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote {len(report)} payload results to {args.output}")
        print(json.dumps(document["summary"], indent=2))
    else:
        print(rendered)
    if document["summary"]["unassessed"]:
        print("Some payloads were unassessed; check Docker and the image build.", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
