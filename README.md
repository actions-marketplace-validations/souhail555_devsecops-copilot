# DevSecOps Copilot · v0.1.0 (MVP)

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-DevSecOps%20Copilot-2ea44f?logo=github)](https://github.com/marketplace/actions/devsecops-copilot)
[![Release](https://img.shields.io/github/v/release/souhail555/devsecops-copilot)](https://github.com/souhail555/devsecops-copilot/releases/latest)
[![DevSecOps Copilot](https://github.com/souhail555/devsecops-copilot/actions/workflows/devsecops-copilot.yml/badge.svg)](https://github.com/souhail555/devsecops-copilot/actions/workflows/devsecops-copilot.yml)

منصة فحص أمني للكود تربط كل ثغرة مباشرة بالضوابط التنظيمية في **الخليج** و**أوروبا**، وتُخرج تقرير امتثال ثنائي اللغة (عربي/إنجليزي) جاهزاً للمراجعة.

Code security scanner that maps every finding to **GCC** and **EU** regulatory controls and produces a bilingual, audit-oriented report.

## الأطر المدعومة · Supported frameworks

| Framework | Region |
|---|---|
| NCA ECC (الضوابط الأساسية للأمن السيبراني) | 🇸🇦 GCC |
| EU Cyber Resilience Act (CRA) | 🇪🇺 EU |
| NIS2 | 🇪🇺 EU |
| DORA (financial sector) | 🇪🇺 EU |
| GDPR | 🇪🇺 EU |

> ⚠️ الربط بين الملاحظات والضوابط **استرشادي** ويجب مراجعته من مختص امتثال معتمد قبل استخدامه كدليل تدقيق. يمكن تعديله من `copilot/compliance.json`.

## ما الذي يفحصه · What it checks
- **Secrets:** AWS keys, private keys, API tokens, GitHub/Slack/Stripe tokens, hardcoded passwords (masked in reports)
- **Injection:** SQL string building, eval/exec, shell command execution
- **Crypto/TLS:** MD5/SHA-1, disabled certificate verification
- **Config:** debug mode, wildcard CORS
- **Deserialization & XSS:** pickle/yaml.load/unserialize, innerHTML/dangerouslySetInnerHTML
- **Containers:** Dockerfile running as root, unpinned base images
- **Supply chain:** unpinned dependencies + **CycloneDX SBOM** (CRA Annex I Part II)

## التشغيل · Usage
Python 3.12+ — بدون أي اعتماديات خارجية (stdlib only).

```bash
python -m copilot scan path/to/repo --out copilot-report --fail-on high
```

المخرجات · Outputs (in `copilot-report/`):
- `report.html` — تقرير الامتثال ثنائي اللغة · bilingual compliance report
- `findings.json` — كل النتائج مع الضوابط المرتبطة
- `results.sarif` — لعرض النتائج داخل GitHub Code Scanning
- `sbom.cdx.json` — قائمة المكونات البرمجية (CycloneDX 1.5)

Exit code `1` when a finding at or above `--fail-on` exists (CI gate). Add `copilot:ignore` on a line to suppress it.

## GitHub Actions
See [examples/github-workflow.yml](examples/github-workflow.yml).

## Demo
```bash
python -m copilot scan vscode-extension/test/fixtures/vulnerable-app --out examples/sample-report
```
`examples/vulnerable-app` is the fixed version of the same app (0 findings); the intentionally vulnerable original lives in `vscode-extension/test/fixtures/vulnerable-app`.

## Roadmap
1. AI layer (Claude): شرح سياقي بالعربية + اقتراح patch تلقائي في الـ Pull Request
2. SAMA CSF, UAE IA Standards, Qatar NIA, ADHICS
3. Vulnerable dependency lookup (OSV database)
4. Integrate Semgrep / Gitleaks / Trivy engines for deeper coverage
5. Web dashboard + multi-tenant SaaS (EU & GCC hosting) + on-prem edition
6. Audit-ready PDF export and evidence history

## VS Code extension · إضافة VS Code
مجلد `vscode-extension/` — تُظهر الثغرات مباشرة أثناء كتابة الكود:
- خط أحمر/أصفر تحت السطر المصاب + لوحة Problems
- عند تمرير الماوس: شرح بالعربية أو الإنجليزية + الضوابط المرتبطة (NCA / CRA / NIS2 / DORA / GDPR)
- Quick Fix (`Ctrl+.`): تجاهل الملاحظة أو فتح التقرير
- شريط الحالة: عدد الملاحظات ونسبة الجاهزية — اضغط لفتح التقرير داخل VS Code
- فحص تلقائي عند الحفظ

**التجربة:** افتح مجلد `devsecops-copilot` في VS Code واضغط **F5** — تُفتح نافذة جديدة على `examples/vulnerable-app` مع الإضافة مفعّلة.

**الاختبار:** `cd vscode-extension && node test/run.js`
**التغليف (.vsix):** `cd vscode-extension && npm run package`

Settings: `devsecopsCopilot.language` (ar/en), `pythonPath`, `frameworks`, `scanOnSave`, `minimumSeverity`.
