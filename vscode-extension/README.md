# DevSecOps Copilot for VS Code

Inline code security findings mapped to **GCC** (NCA ECC) and **EU** (CRA, NIS2, DORA, GDPR) compliance controls, in Arabic and English.

تُظهر الثغرات الأمنية مباشرة أثناء كتابة الكود، مع ربط كل ملاحظة بالضوابط التنظيمية في الخليج وأوروبا.

## Features · المزايا
- Red/yellow squiggles on affected lines + entries in the **Problems** panel
- Hover: explanation in Arabic or English + mapped controls (NCA / CRA / NIS2 / DORA / GDPR)
- Quick Fix (`Ctrl+.`): ignore the finding or open the report
- Status bar: finding count and readiness score; click to open the bilingual report inside VS Code
- Automatic scan on save

## What it checks
Secrets, injection (SQL / eval / shell), weak crypto and disabled TLS verification, debug mode and wildcard CORS, unsafe deserialization and XSS, Dockerfile issues, unpinned dependencies + CycloneDX SBOM.

## Requirements
Python 3.12+ on your `PATH` (or set `devsecopsCopilot.pythonPath`). The scan engine is bundled; no other dependencies.

## Settings
| Setting | Default | Description |
|---|---|---|
| `devsecopsCopilot.language` | `ar` | `ar` (العربية) or `en` |
| `devsecopsCopilot.pythonPath` | `python` | Python 3.12+ interpreter |
| `devsecopsCopilot.frameworks` | all | Frameworks to map findings to |
| `devsecopsCopilot.scanOnSave` | `true` | Re-scan when a file is saved |
| `devsecopsCopilot.minimumSeverity` | `low` | Hide findings below this severity |

Add `copilot:ignore` on a line to suppress it.

> ⚠️ The mapping between findings and controls is for guidance only. A qualified compliance professional should review it before it is used as audit evidence.

Also available as a GitHub Action: [DevSecOps Copilot on GitHub Marketplace](https://github.com/marketplace/actions/devsecops-copilot).
