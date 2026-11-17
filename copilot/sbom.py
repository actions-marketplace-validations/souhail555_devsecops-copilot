"""Minimal CycloneDX 1.5 SBOM generator (CRA Annex I Part II(1))."""
import uuid
from datetime import datetime, timezone

from . import __version__


def build(components, project_name):
    seen, comps = set(), []
    for c in components:
        key = (c["ecosystem"], c["name"].lower(), c["version"])
        if key in seen:
            continue
        seen.add(key)
        purl = f"pkg:{c['ecosystem']}/{c['name']}" + (f"@{c['version']}" if c["version"] else "")
        item = {"type": "library", "name": c["name"], "purl": purl,
                "properties": [{"name": "copilot:source", "value": c["source"]}]}
        if c["version"]:
            item["version"] = c["version"]
        comps.append(item)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": [{"vendor": "DevSecOps Copilot", "name": "copilot", "version": __version__}],
            "component": {"type": "application", "name": project_name},
        },
        "components": comps,
    }
