"""Repository scanners: pattern rules, Dockerfiles, dependency manifests."""
import json
import os
import re

from .rules import RULES, FILE_RULES

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
             ".next", "vendor", "target", ".idea", ".vscode", "copilot-report"}
MAX_FILE_BYTES = 1_000_000
IGNORE_MARK = "copilot:ignore"
# Files produced by this tool (never scan our own output)
GENERATED_FILES = {"findings.json", "results.sarif", "sbom.cdx.json", "report.html"}


def _finding(rule, path, line, snippet):
    return {
        "rule_id": rule["id"], "category": rule["category"], "severity": rule["severity"],
        "title": rule["title"], "desc": rule["desc"], "fix": rule["fix"],
        "file": path, "line": line, "snippet": snippet.strip()[:200],
    }


def _mask(text):
    """Mask long secret-looking tokens so reports never re-leak secrets."""
    text = re.sub(r"(['\"])([^'\"]{0,4})[^'\"]{4,}(['\"])", r"\1\2********\3", text)
    return re.sub(r"\b(AKIA|ASIA|ghp_|xox[baprs]-|sk_live_)[A-Za-z0-9_\-]{6,}", r"\1********", text)


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in GENERATED_FILES:
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield full, os.path.relpath(full, root).replace("\\", "/")


def _ext(name):
    base = os.path.basename(name).lower()
    if base.startswith(".env"):
        return ".env"
    return os.path.splitext(base)[1]


def scan_patterns(full, rel, text):
    out = []
    ext = _ext(rel)
    lines = text.splitlines()
    for rule in RULES:
        if ext not in rule["ext"]:
            continue
        for i, line in enumerate(lines, 1):
            if IGNORE_MARK in line:
                continue
            if rule["regex"].search(line):
                snippet = _mask(line) if rule["category"] == "secrets" else line
                out.append(_finding(rule, rel, i, snippet))
    return out


def scan_dockerfile(rel, text):
    out = []
    lines = text.splitlines()
    has_user = any(re.match(r"\s*USER\s+(?!root\b|0\b)\S+", l, re.I) for l in lines)
    if not has_user:
        out.append(_finding(FILE_RULES["CON001"], rel, 1, "(no non-root USER instruction)"))
    for i, l in enumerate(lines, 1):
        m = re.match(r"\s*FROM\s+(\S+)", l, re.I)
        if m:
            img = m.group(1)
            if img.lower() == "scratch" or "@sha256:" in img:
                continue
            tag = img.split("/")[-1]
            if ":" not in tag or tag.endswith(":latest"):
                out.append(_finding(FILE_RULES["CON002"], rel, i, l))
    return out


def parse_dependencies(rel, text):
    """Return (components, findings). Components feed the SBOM."""
    comps, out = [], []
    base = os.path.basename(rel).lower()
    if base.startswith("requirements") and base.endswith(".txt"):
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*(\[.*\])?\s*(==|>=|<=|~=|>|<)?\s*([^;\s]*)", line)
            if not m:
                continue
            name, op, ver = m.group(1), m.group(3), m.group(4)
            pinned = op == "==" and bool(ver)
            comps.append({"ecosystem": "pypi", "name": name, "version": ver if pinned else "", "source": rel})
            if not pinned:
                out.append(_finding(FILE_RULES["DEP001"], rel, i, raw))
    elif base == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return comps, out
        lines = text.splitlines()
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section) or {}).items():
                ver = str(ver)
                pinned = bool(re.match(r"^\d+\.\d+\.\d+", ver))
                comps.append({"ecosystem": "npm", "name": name,
                              "version": ver if pinned else "", "source": rel})
                if not pinned:
                    line_no = next((i for i, l in enumerate(lines, 1) if f'"{name}"' in l), 1)
                    out.append(_finding(FILE_RULES["DEP001"], rel, line_no, f'"{name}": "{ver}"'))
    return comps, out


def scan_repo(root):
    findings, components, files_scanned = [], [], 0
    for full, rel in iter_files(root):
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        if "\x00" in text[:1024]:
            continue  # binary
        files_scanned += 1
        findings += scan_patterns(full, rel, text)
        base = os.path.basename(rel).lower()
        if base == "dockerfile" or base.startswith("dockerfile."):
            findings += scan_dockerfile(rel, text)
        comps, dep_findings = parse_dependencies(rel, text)
        components += comps
        findings += dep_findings
    return findings, components, files_scanned
