// Runs the extension against a minimal stub of the VS Code API and the real Python engine.
"use strict";
const Module = require("module");
const path = require("path");
const assert = require("assert");

const settings = { language: "ar", pythonPath: "python", enginePath: "", scanOnSave: true,
  minimumSeverity: "low", frameworks: ["NCA_ECC", "CRA", "NIS2", "DORA", "GDPR"] };
const diag = new Map();
const commands = {};
let hover, codeActions, status;

class Range { constructor(l1, c1, l2, c2) { this.start = { line: l1, character: c1 }; this.end = { line: l2, character: c2 }; } }
const vscode = {
  Range,
  Diagnostic: class { constructor(range, message, severity) { Object.assign(this, { range, message, severity }); } },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 },
  StatusBarAlignment: { Left: 1 }, ViewColumn: { Beside: -2 }, ConfigurationTarget: { Global: 1 },
  CodeActionKind: { QuickFix: "quickfix", Empty: "" },
  ThemeColor: class { constructor(id) { this.id = id; } },
  MarkdownString: class { constructor(v) { this.value = v; } },
  Hover: class { constructor(c) { this.contents = c; } },
  CodeAction: class { constructor(title, kind) { this.title = title; this.kind = kind; } },
  WorkspaceEdit: class { constructor() { this.inserts = []; } insert(uri, pos, text) { this.inserts.push({ pos, text }); } },
  Uri: { file: (p) => ({ fsPath: path.normalize(p), toString() { return path.normalize(p); } }) },
  languages: {
    createDiagnosticCollection: () => ({
      clear: () => diag.clear(), set: (uri, list) => diag.set(uri.fsPath, list),
      get: (uri) => diag.get(uri.fsPath), dispose() {},
    }),
    registerHoverProvider: (_s, p) => { hover = p; return { dispose() {} }; },
    registerCodeActionsProvider: (_s, p) => { codeActions = p; return { dispose() {} }; },
  },
  window: {
    createOutputChannel: () => ({ appendLine() {}, show() {}, dispose() {} }),
    createStatusBarItem: () => (status = { show() {}, dispose() {} }),
    showInformationMessage: async () => undefined, showWarningMessage: async () => undefined,
    showErrorMessage: async (m) => { throw new Error("extension error: " + m); },
  },
  workspace: {
    workspaceFolders: [{ uri: { fsPath: path.resolve(__dirname, "fixtures", "vulnerable-app") } }],
    getConfiguration: () => ({ get: (k) => settings[k], update: async (k, v) => { settings[k] = v; } }),
    onDidSaveTextDocument: () => ({ dispose() {} }), onDidChangeConfiguration: () => ({ dispose() {} }),
    createFileSystemWatcher: () => ({
      onDidChange: () => ({ dispose() {} }), onDidCreate: () => ({ dispose() {} }),
      onDidDelete: () => ({ dispose() {} }), dispose() {},
    }),
  },
  commands: { registerCommand: (id, fn) => { commands[id] = fn; return { dispose() {} }; } },
};

const origResolve = Module._resolveFilename;
Module._resolveFilename = function (req, ...rest) { return req === "vscode" ? "vscode" : origResolve.call(this, req, ...rest); };
require.cache.vscode = { id: "vscode", filename: "vscode", loaded: true, exports: vscode };

const ext = require("../extension.js");

(async () => {
  const context = { extensionPath: path.resolve(__dirname, ".."), subscriptions: [] };
  ext.activate(context);
  for (let i = 0; i < 100 && diag.size === 0; i++) await new Promise((r) => setTimeout(r, 100));

  const all = [...diag.values()].flat();
  console.log(`files with findings: ${diag.size}, diagnostics: ${all.length}`);
  assert.strictEqual(all.length, 16, "expected 16 findings on the sample app");

  const appPy = [...diag.keys()].find((k) => k.endsWith("app.py"));
  const sqli = diag.get(appPy).find((d) => d.code === "INJ001");
  assert.strictEqual(sqli.range.start.line, 19, "SQL injection on line 20");
  assert.strictEqual(sqli.severity, vscode.DiagnosticSeverity.Error);
  assert.ok(/SQL/.test(sqli.message) && /[؀-ۿ]/.test(sqli.message), "Arabic message");
  console.log("diagnostic:", sqli.message);

  const doc = { uri: vscode.Uri.file(appPy), languageId: "python",
    lineAt: (l) => ({ range: { end: { line: l, character: 80 } } }) };
  const h = hover.provideHover(doc, { line: 19 });
  assert.ok(h && h.contents.value.includes("NCA_ECC") && h.contents.value.includes("2-15"), "hover lists NCA controls");
  assert.ok(h.contents.value.includes("CRA"), "hover lists CRA controls");
  console.log("hover OK (first lines):\n" + h.contents.value.split("\n").slice(0, 2).join("\n"));

  const acts = codeActions.provideCodeActions(doc, sqli.range, { diagnostics: [sqli] });
  assert.strictEqual(acts[0].edit.inserts[0].text, "  # copilot:ignore");
  assert.strictEqual(ext.commentFor("javascript"), "// copilot:ignore");
  console.log("quick fix:", acts[0].title);

  assert.ok(status.text.includes("16") && status.text.includes("%"), "status bar shows totals");
  console.log("status bar:", status.text);

  settings.minimumSeverity = "high";
  assert.strictEqual([...ext.buildDiagnostics(JSON.parse(JSON.stringify(all.map((d) => d.finding))),
    vscode.workspace.workspaceFolders[0].uri.fsPath, "high").values()].flat().length, 7, "high+critical filter");

  settings.language = "en";
  assert.ok(/^### 🛡️ SQL query/.test(ext.hoverText(sqli.finding)), "English hover");

  console.log("\nALL TESTS PASSED");
})().catch((e) => { console.error(e); process.exit(1); });
