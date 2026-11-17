"""Report writers: JSON, SARIF 2.1.0 (GitHub code scanning) and a bilingual HTML audit report."""
import html
import json
from datetime import datetime, timezone

from . import __version__
from .rules import SEVERITY_ORDER

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SEV_LABEL = {
    "critical": {"en": "Critical", "ar": "حرجة"}, "high": {"en": "High", "ar": "عالية"},
    "medium": {"en": "Medium", "ar": "متوسطة"}, "low": {"en": "Low", "ar": "منخفضة"},
}


def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


def write_sarif(path, findings):
    rules, seen = [], set()
    for f in findings:
        if f["rule_id"] in seen:
            continue
        seen.add(f["rule_id"])
        rules.append({
            "id": f["rule_id"], "name": f["title"]["en"],
            "shortDescription": {"text": f["title"]["en"]},
            "fullDescription": {"text": f["desc"]["en"]},
            "help": {"text": f"{f['fix']['en']}\n\n{f['fix']['ar']}"},
            "properties": {"tags": ["security", f["category"]],
                           "security-severity": {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}[f["severity"]]},
        })
    results = []
    for f in findings:
        ctrl = "; ".join(f"{fw}: {', '.join(c)}" for fw, c in f.get("controls", {}).items())
        results.append({
            "ruleId": f["rule_id"], "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['title']['en']} | {f['title']['ar']}" + (f" | Controls: {ctrl}" if ctrl else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                                "region": {"startLine": f["line"]}}}],
        })
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "DevSecOps Copilot", "version": __version__,
                                           "informationUri": "https://example.com/devsecops-copilot",
                                           "rules": rules}},
                       "results": results}]}
    write_json(path, sarif)


# ---------------------------------------------------------------- HTML
def _e(s):
    return html.escape(str(s))


def _t(d):
    return f'<span class="l-ar">{_e(d["ar"])}</span><span class="l-en">{_e(d["en"])}</span>'


def _tt(ar, en):
    return _t({"ar": ar, "en": en})


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#14181f;--muted:#5b6472;--line:#e3e6eb;--accent:#0f766e;
--crit:#b42318;--high:#c2410c;--med:#a16207;--low:#475569;--ok:#15803d;--code:#f1f3f5}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0e1116;--card:#161b22;--ink:#e6e9ee;
--muted:#9aa4b2;--line:#2a313b;--accent:#2dd4bf;--crit:#f87171;--high:#fb923c;--med:#facc15;--low:#94a3b8;--ok:#4ade80;--code:#0b0e13}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 "Segoe UI",Tahoma,"Noto Sans Arabic",system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:24px}
h1{margin:0;font-size:24px}h2{font-size:18px;margin:32px 0 12px}.muted{color:var(--muted);font-size:13px}
button{background:var(--accent);color:#fff;border:0;border-radius:8px;padding:8px 14px;font:inherit;cursor:pointer}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.num{font-size:28px;font-weight:700;font-variant-numeric:tabular-nums}
.crit,.critical{color:var(--crit)}.high{color:var(--high)}.med,.medium{color:var(--med)}.low{color:var(--low)}.ok{color:var(--ok)}
.fw{margin-bottom:12px}.fw summary{cursor:pointer;display:flex;justify-content:space-between;gap:12px;align-items:center;list-style:none}
.bar{height:8px;background:var(--line);border-radius:99px;overflow:hidden;margin-top:6px;width:180px;max-width:40vw}
.bar i{display:block;height:100%;background:var(--accent)}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:14px}
th,td{text-align:start;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.finding{border-inline-start:4px solid var(--line)}.finding.s-critical{border-inline-start-color:var(--crit)}
.finding.s-high{border-inline-start-color:var(--high)}.finding.s-medium{border-inline-start-color:var(--med)}
.finding.s-low{border-inline-start-color:var(--low)}
.finding h3{margin:0 0 4px;font-size:16px}code,pre{font-family:Consolas,"Cascadia Code",monospace;direction:ltr;text-align:left}
pre{background:var(--code);padding:10px;border-radius:8px;overflow-x:auto;font-size:13px;margin:8px 0}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}.tag{font-size:12px;background:var(--code);padding:2px 8px;border-radius:6px}
.list{display:flex;flex-direction:column;gap:12px}
html[lang=ar] .l-en,html[lang=en] .l-ar{display:none}
.note{font-size:13px;color:var(--muted);border:1px dashed var(--line);padding:12px;border-radius:8px;margin-top:32px}
"""


def write_html(path, project, findings, frameworks, note, stats):
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    sev_cls = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}
    cards = "".join(
        f'<div class="card"><div class="num {sev_cls[s]}">{counts[s]}</div>{_t(SEV_LABEL[s])}</div>'
        for s in SEVERITY_ORDER)

    fw_html = []
    for fid, fw in frameworks.items():
        rows = []
        for c in fw["controls"]:
            if c["status"] == "issues":
                st = f'<span class="pill {c["worst"]}">{_tt("تحتاج معالجة", "Action needed")} ({c["findings"]})</span>'
            else:
                st = f'<span class="pill ok">{_tt("لا توجد ملاحظات", "No issues found")}</span>'
            ev = f' <span class="tag">📎 {_e(", ".join(c["evidence"]))}</span>' if c["evidence"] else ""
            rows.append(f'<tr><td><code>{_e(c["id"])}</code></td><td>{_t(c["label"])}{ev}</td><td>{st}</td></tr>')
        open_attr = " open" if fid in ("NCA_ECC", "CRA") else ""
        fw_html.append(f"""
<details class="card fw"{open_attr}><summary><div><strong>{_t(fw["name"])}</strong>
<div class="muted">{_e(fw["region"])}</div></div><div style="text-align:end"><span class="num">{fw["score"]}%</span>
<div class="bar"><i style="width:{fw["score"]}%"></i></div></div></summary>
<table><thead><tr><th>{_tt("الضابط", "Control")}</th><th>{_tt("الوصف", "Description")}</th><th>{_tt("الحالة", "Status")}</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></details>""")

    items = []
    for f in sorted(findings, key=lambda x: (-SEVERITY_ORDER[x["severity"]], x["file"], x["line"])):
        tags = "".join(f'<span class="tag">{_e(fw)} {_e(c)}</span>'
                       for fw, cs in f.get("controls", {}).items() for c in cs)
        items.append(f"""
<div class="card finding s-{f["severity"]}"><div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap">
<h3>{_t(f["title"])}</h3><span class="pill {f["severity"]}">{_t(SEV_LABEL[f["severity"]])} · {_e(f["rule_id"])}</span></div>
<div class="muted"><code>{_e(f["file"])}:{f["line"]}</code></div>
<pre>{_e(f["snippet"])}</pre>
<div>{_t(f["desc"])}</div>
<div style="margin-top:6px"><strong>{_tt("طريقة الإصلاح:", "How to fix:")}</strong> {_t(f["fix"])}</div>
<div class="tags">{tags}</div></div>""")
    if not items:
        items.append(f'<div class="card ok">{_tt("لم يتم العثور على ملاحظات 🎉", "No findings 🎉")}</div>')

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Compliance Report · {_e(project)}</title>
<style>{CSS}</style></head><body><div class="wrap">
<header><div><h1>{_tt("تقرير الأمن والامتثال", "Security & Compliance Report")}</h1>
<div class="muted">{_e(project)} · {now} · {stats["files"]} {_tt("ملف", "files")} · {stats["components"]} {_tt("مكوّن", "components")} · DevSecOps Copilot v{__version__}</div></div>
<button onclick="toggleLang()">English / العربية</button></header>
<div class="grid">{cards}<div class="card"><div class="num">{len(findings)}</div>{_tt("إجمالي الملاحظات", "Total findings")}</div></div>
<h2>{_tt("جاهزية الامتثال حسب الإطار التنظيمي", "Compliance readiness by framework")}</h2>
{"".join(fw_html)}
<h2>{_tt("الملاحظات التفصيلية", "Detailed findings")}</h2>
<div class="list">{"".join(items)}</div>
<div class="note">{_tt("تنبيه: هذا الربط بين الملاحظات والضوابط التنظيمية استرشادي ويجب مراجعته من مختص امتثال معتمد قبل اعتماده كدليل تدقيق. نسبة الجاهزية تعكس فقط الضوابط القابلة للفحص آلياً من الكود.",
     note + " The readiness score reflects only controls that can be checked automatically from code.")}</div>
</div><script>
function toggleLang(){{var h=document.documentElement;var ar=h.lang==='ar';h.lang=ar?'en':'ar';h.dir=ar?'ltr':'rtl';
try{{localStorage.setItem('copilot-lang',h.lang)}}catch(e){{}}}}
try{{var l=localStorage.getItem('copilot-lang');if(l==='en')toggleLang();}}catch(e){{}}
</script></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
