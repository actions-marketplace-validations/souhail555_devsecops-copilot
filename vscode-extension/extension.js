// DevSecOps Copilot — VS Code extension
// Runs the Python scan engine, shows findings inline (squiggles + Problems panel),
// bilingual hovers with mapped compliance controls, quick fixes and a report view.
"use strict";

const vscode = require("vscode");
const cp = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const SOURCE = "DevSecOps Copilot";
const SEV_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const SEV_LABEL = {
  critical: { ar: "حرجة", en: "Critical" }, high: { ar: "عالية", en: "High" },
  medium: { ar: "متوسطة", en: "Medium" }, low: { ar: "منخفضة", en: "Low" },
};
const HASH_COMMENT = new Set(["python", "yaml", "shellscript", "dockerfile", "ruby", "properties",
  "toml", "ini", "dotenv", "terraform", "makefile", "r", "perl", "powershell"]);

let diagnostics, statusItem, output;
let state = { root: null, outDir: null, findings: [], frameworks: {}, running: false };
let saveTimer = null;

// ---------------------------------------------------------------- helpers
function cfg() { return vscode.workspace.getConfiguration("devsecopsCopilot"); }
function lang() { return cfg().get("language") === "en" ? "en" : "ar"; }
function t(obj) { return obj ? obj[lang()] || obj.en : ""; }
function tr(ar, en) { return lang() === "ar" ? ar : en; }

function resolveEngine(extPath) {
  const custom = cfg().get("enginePath");
  const candidates = [custom, path.join(extPath, "python"), path.join(extPath, "..")].filter(Boolean);
  return candidates.find((d) => fs.existsSync(path.join(d, "copilot", "__init__.py"))) || null;
}

function outDirFor(root) {
  const h = crypto.createHash("sha256").update(root).digest("hex").slice(0, 10);
  return path.join(os.tmpdir(), "devsecops-copilot", h);
}

function severityToVs(sev) {
  if (sev === "critical" || sev === "high") return vscode.DiagnosticSeverity.Error;
  if (sev === "medium") return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

/** Pure: group findings into { absPath: [Diagnostic] }. Exported for tests. */
function buildDiagnostics(findings, root, minSeverity) {
  const min = SEV_RANK[minSeverity] || 1;
  const byFile = new Map();
  for (const f of findings) {
    if ((SEV_RANK[f.severity] || 0) < min) continue;
    const abs = path.join(root, ...f.file.split("/"));
    const line = Math.max(0, (f.line || 1) - 1);
    const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
    const d = new vscode.Diagnostic(range, `${t(f.title)} — ${t(f.fix)}`, severityToVs(f.severity));
    d.source = SOURCE;
    d.code = f.rule_id;
    d.finding = f;
    if (!byFile.has(abs)) byFile.set(abs, []);
    byFile.get(abs).push(d);
  }
  return byFile;
}

function controlsMarkdown(f) {
  const parts = [];
  for (const [fw, ids] of Object.entries(f.controls || {})) {
    const fwInfo = state.frameworks[fw];
    const labels = ids.map((id) => {
      const c = fwInfo && fwInfo.controls.find((x) => x.id === id);
      return c ? `\`${id}\` ${t(c.label)}` : `\`${id}\``;
    });
    parts.push(`- **${fw}**: ${labels.join(" · ")}`);
  }
  return parts.join("\n");
}

/** Pure: markdown hover text for one finding. Exported for tests. */
function hoverText(f) {
  return [
    `### 🛡️ ${t(f.title)}`,
    `**${tr("الخطورة", "Severity")}:** ${t(SEV_LABEL[f.severity])} · \`${f.rule_id}\``,
    "",
    t(f.desc),
    "",
    `**${tr("طريقة الإصلاح", "How to fix")}:** ${t(f.fix)}`,
    "",
    `**${tr("الضوابط التنظيمية المرتبطة", "Mapped compliance controls")}:**`,
    controlsMarkdown(f),
  ].join("\n");
}

function commentFor(languageId) {
  if (HASH_COMMENT.has(languageId)) return "# copilot:ignore";
  if (languageId === "html" || languageId === "xml") return "<!-- copilot:ignore -->";
  return "// copilot:ignore";
}

// ---------------------------------------------------------------- scanning
function updateStatus() {
  if (!statusItem) return;
  if (state.running) {
    statusItem.text = `$(sync~spin) ${tr("جارٍ الفحص…", "Scanning…")}`;
    return;
  }
  const min = SEV_RANK[cfg().get("minimumSeverity")] || 1;
  const visible = state.findings.filter((f) => SEV_RANK[f.severity] >= min);
  const crit = visible.filter((f) => f.severity === "critical" || f.severity === "high").length;
  const scores = Object.entries(state.frameworks).map(([k, v]) => `${k.replace("_ECC", "")} ${v.score}%`);
  statusItem.text = `$(shield) ${visible.length}` + (crit ? ` ($(error) ${crit})` : "") +
    (scores.length ? ` · ${scores.slice(0, 2).join(" · ")}` : "");
  statusItem.tooltip = tr("جاهزية الامتثال — اضغط لفتح التقرير", "Compliance readiness — click to open report") +
    "\n" + Object.entries(state.frameworks).map(([k, v]) => `${k}: ${v.score}%`).join("\n");
  statusItem.backgroundColor = crit ? new vscode.ThemeColor("statusBarItem.errorBackground") : undefined;
}

function publish() {
  diagnostics.clear();
  if (!state.root) return;
  const byFile = buildDiagnostics(state.findings, state.root, cfg().get("minimumSeverity"));
  for (const [abs, list] of byFile) diagnostics.set(vscode.Uri.file(abs), list);
  updateStatus();
}

function runEngine(root, context) {
  return new Promise((resolve, reject) => {
    const engine = resolveEngine(context.extensionPath);
    if (!engine) return reject(new Error(tr(
      "لم يتم العثور على محرك الفحص. حدّد devsecopsCopilot.enginePath.",
      "Scan engine not found. Set devsecopsCopilot.enginePath.")));
    const outDir = outDirFor(root);
    fs.mkdirSync(outDir, { recursive: true });
    const args = ["-m", "copilot", "scan", root, "--out", outDir, "--fail-on", "none",
      "--frameworks", (cfg().get("frameworks") || []).join(",") || "NCA_ECC,CRA,NIS2,DORA,GDPR"];
    const env = Object.assign({}, process.env, {
      PYTHONPATH: engine + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : ""),
      PYTHONIOENCODING: "utf-8",
    });
    output.appendLine(`> ${cfg().get("pythonPath")} ${args.join(" ")}`);
    cp.execFile(cfg().get("pythonPath") || "python", args, { env, cwd: engine, maxBuffer: 20 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (stdout) output.appendLine(stdout);
        if (stderr) output.appendLine(stderr);
        if (err) return reject(new Error(stderr || err.message));
        try {
          const data = JSON.parse(fs.readFileSync(path.join(outDir, "findings.json"), "utf-8"));
          resolve({ data, outDir });
        } catch (e) { reject(e); }
      });
  });
}

async function scan(context, { silent = false } = {}) {
  const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (!folder) {
    if (!silent) vscode.window.showWarningMessage(tr("افتح مجلد مشروع أولاً.", "Open a project folder first."));
    return;
  }
  if (state.running) return;
  state.running = true;
  updateStatus();
  try {
    const root = folder.uri.fsPath;
    const { data, outDir } = await runEngine(root, context);
    state = { root, outDir, findings: data.findings || [], frameworks: data.frameworks || {}, running: false };
    publish();
    if (!silent) {
      const n = state.findings.length;
      const pick = await vscode.window.showInformationMessage(
        tr(`اكتمل الفحص: ${n} ملاحظة.`, `Scan complete: ${n} finding(s).`),
        tr("فتح التقرير", "Open report"));
      if (pick) openReport();
    }
  } catch (e) {
    state.running = false;
    updateStatus();
    output.appendLine(String(e.stack || e));
    vscode.window.showErrorMessage(`${SOURCE}: ${e.message.split("\n")[0]}`, tr("عرض السجل", "Show log"))
      .then((p) => p && output.show());
  }
}

// ---------------------------------------------------------------- report view
let panel = null;
function openReport() {
  const file = state.outDir && path.join(state.outDir, "report.html");
  if (!file || !fs.existsSync(file)) {
    vscode.window.showInformationMessage(tr("شغّل الفحص أولاً.", "Run a scan first."));
    return;
  }
  let html = fs.readFileSync(file, "utf-8");
  if (lang() === "en") html = html.replace('<html lang="ar" dir="rtl">', '<html lang="en" dir="ltr">');
  if (!panel) {
    panel = vscode.window.createWebviewPanel("devsecopsCopilotReport", tr("تقرير الامتثال", "Compliance report"),
      vscode.ViewColumn.Beside, { enableScripts: true, localResourceRoots: [] });
    panel.onDidDispose(() => { panel = null; });
  }
  panel.webview.html = html;
  panel.reveal();
}

// ---------------------------------------------------------------- providers
const hoverProvider = {
  provideHover(doc, pos) {
    const items = diagnostics.get(doc.uri) || [];
    const hits = items.filter((d) => d.range.start.line === pos.line && d.finding);
    if (!hits.length) return null;
    const md = new vscode.MarkdownString(hits.map((d) => hoverText(d.finding)).join("\n\n---\n\n"));
    md.supportHtml = false;
    return new vscode.Hover(md);
  },
};

const codeActionProvider = {
  provideCodeActions(doc, range, ctx) {
    const actions = [];
    for (const d of ctx.diagnostics.filter((x) => x.source === SOURCE)) {
      const line = doc.lineAt(d.range.start.line);
      const ignore = new vscode.CodeAction(
        tr(`تجاهل هذه الملاحظة (${d.code})`, `Ignore this finding (${d.code})`), vscode.CodeActionKind.QuickFix);
      ignore.edit = new vscode.WorkspaceEdit();
      ignore.edit.insert(doc.uri, line.range.end, "  " + commentFor(doc.languageId));
      ignore.diagnostics = [d];
      actions.push(ignore);

      const info = new vscode.CodeAction(tr("فتح تقرير الامتثال", "Open compliance report"), vscode.CodeActionKind.Empty);
      info.command = { command: "devsecopsCopilot.openReport", title: "" };
      actions.push(info);
    }
    return actions;
  },
};

// ---------------------------------------------------------------- lifecycle
function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("devsecops-copilot");
  output = vscode.window.createOutputChannel(SOURCE);
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusItem.command = "devsecopsCopilot.openReport";
  statusItem.text = "$(shield) DevSecOps";
  statusItem.show();

  context.subscriptions.push(
    diagnostics, output, statusItem,
    vscode.commands.registerCommand("devsecopsCopilot.scan", () => scan(context)),
    vscode.commands.registerCommand("devsecopsCopilot.openReport", openReport),
    vscode.commands.registerCommand("devsecopsCopilot.clear", () => {
      state.findings = []; state.frameworks = {}; publish();
    }),
    vscode.commands.registerCommand("devsecopsCopilot.toggleLanguage", async () => {
      await cfg().update("language", lang() === "ar" ? "en" : "ar", vscode.ConfigurationTarget.Global);
    }),
    vscode.languages.registerHoverProvider({ scheme: "file" }, hoverProvider),
    vscode.languages.registerCodeActionsProvider({ scheme: "file" }, codeActionProvider,
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidSaveTextDocument(() => {
      if (!cfg().get("scanOnSave")) return;
      clearTimeout(saveTimer);
      saveTimer = setTimeout(() => scan(context, { silent: true }), 800);
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("devsecopsCopilot.language") ||
          e.affectsConfiguration("devsecopsCopilot.minimumSeverity")) {
        publish();
        if (panel) openReport();
      }
      if (e.affectsConfiguration("devsecopsCopilot.frameworks")) scan(context, { silent: true });
    }),
  );

  scan(context, { silent: true });
}

function deactivate() { clearTimeout(saveTimer); }

module.exports = { activate, deactivate, buildDiagnostics, hoverText, commentFor, resolveEngine };
