// Copies the Python engine (../copilot) into ./python/copilot so the packaged .vsix is self-contained.
const fs = require("fs");
const path = require("path");
const src = path.join(__dirname, "..", "..", "copilot");
const dst = path.join(__dirname, "..", "python", "copilot");
fs.rmSync(dst, { recursive: true, force: true });
fs.mkdirSync(dst, { recursive: true });
for (const f of fs.readdirSync(src)) {
  if (f.endsWith(".py") || f.endsWith(".json")) fs.copyFileSync(path.join(src, f), path.join(dst, f));
}
console.log("engine bundled ->", dst);
