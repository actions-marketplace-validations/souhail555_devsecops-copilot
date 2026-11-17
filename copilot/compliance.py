"""Map findings to regulatory controls (GCC + EU)."""
import json
import os

_DATA = os.path.join(os.path.dirname(__file__), "compliance.json")


def load():
    with open(_DATA, encoding="utf-8") as fh:
        return json.load(fh)


def evaluate(findings, selected=None, sbom_generated=False):
    """Annotate findings with controls and return per-framework results."""
    data = load()
    fws = data["frameworks"]
    mapping = data["mapping"]
    selected = [f for f in (selected or fws.keys()) if f in fws]

    for f in findings:
        f["controls"] = {fw: mapping.get(f["category"], {}).get(fw, []) for fw in selected}
        f["controls"] = {k: v for k, v in f["controls"].items() if v}

    results = {}
    for fw in selected:
        controls = []
        for cid, label in fws[fw]["controls"].items():
            hits = [f for f in findings if cid in f["controls"].get(fw, [])]
            status = "issues" if hits else "no_issues"
            evidence = []
            if fw == "CRA" and cid == "AnnexI-II(1)" and sbom_generated:
                evidence.append("sbom.cdx.json")
            controls.append({"id": cid, "label": label, "status": status,
                             "findings": len(hits), "evidence": evidence,
                             "worst": max((h["severity"] for h in hits),
                                          key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}[s],
                                          default=None)})
        ok = sum(1 for c in controls if c["status"] == "no_issues")
        results[fw] = {"name": fws[fw]["name"], "region": fws[fw]["region"],
                       "controls": controls,
                       "score": round(100 * ok / len(controls)) if controls else 100}
    return results, data["_note"]
