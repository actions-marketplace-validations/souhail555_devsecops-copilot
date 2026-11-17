"""Command line entry point.

    python -m copilot scan <path> [--out DIR] [--frameworks NCA_ECC,CRA,...] [--fail-on high]
"""
import argparse
import os
import sys

from . import __version__, compliance, report, sbom
from .rules import SEVERITY_ORDER
from .scanners import scan_repo


def main(argv=None):
    p = argparse.ArgumentParser(prog="copilot", description="DevSecOps Copilot - code security & GCC/EU compliance scanner")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a repository")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--out", default="copilot-report")
    s.add_argument("--frameworks", default="NCA_ECC,CRA,NIS2,DORA,GDPR",
                   help="comma separated: NCA_ECC,CRA,NIS2,DORA,GDPR")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="high",
                   help="exit with code 1 if a finding at or above this severity exists (CI gate)")
    s.add_argument("--project", default=None)
    args = p.parse_args(argv)

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    project = args.project or os.path.basename(root)
    os.makedirs(args.out, exist_ok=True)

    findings, components, files = scan_repo(root)
    bom = sbom.build(components, project)
    frameworks, note = compliance.evaluate(findings, args.frameworks.split(","), sbom_generated=True)
    stats = {"files": files, "components": len(bom["components"])}

    report.write_json(os.path.join(args.out, "sbom.cdx.json"), bom)
    report.write_json(os.path.join(args.out, "findings.json"),
                      {"project": project, "stats": stats, "findings": findings, "frameworks": frameworks})
    report.write_sarif(os.path.join(args.out, "results.sarif"), findings)
    report.write_html(os.path.join(args.out, "report.html"), project, findings, frameworks, note, stats)

    counts = {sv: sum(1 for f in findings if f["severity"] == sv) for sv in SEVERITY_ORDER}
    print(f"DevSecOps Copilot v{__version__}  |  {project}")
    print(f"  files scanned: {files}   components: {stats['components']}")
    print("  findings: " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    for fid, fw in frameworks.items():
        print(f"  {fid:<8} readiness {fw['score']:>3}%")
    print(f"  report: {os.path.join(args.out, 'report.html')}")

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f["severity"]] >= threshold for f in findings):
            print(f"  FAILED: findings at or above '{args.fail_on}'")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
