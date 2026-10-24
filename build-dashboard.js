"use strict";
const fs = require("node:fs");
const path = require("node:path");
const ROOT = __dirname;
function read(name) {
  const file = path.join(ROOT, name);
  if (!fs.existsSync(file)) return {};
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch (e) { throw new Error(`Invalid ${name}: ${e.message}`); }
}
const risk = read("risk-findings.json");
const extra = read("extra-report.json");
const normalize = (f) => ({
  category: f.category || f.type || "code",
  algorithm: f.algorithm || f.name || "Unknown",
  risk: String(f.risk || f.severity || "unknown").toLowerCase(),
  quantum: f.quantum || "unknown",
  keySize: f.keySize || null,
  mode: f.mode || null,
  reasons: Array.isArray(f.reasons) ? f.reasons : (f.reason ? [f.reason] : []),
  recommendation: f.recommendation || f.fix || "",
  occurrences: Array.isArray(f.occurrences) && f.occurrences.length ? f.occurrences : [{ file: f.file || "", line: f.line || null, language: f.language || "" }],
});
const seen = new Set();
const items = [...(risk.findings || []), ...(extra.items || [])].map(normalize).filter((f) => {
  const k = [f.algorithm, f.category, f.occurrences[0]?.file, f.occurrences[0]?.line].join("|").toLowerCase();
  if (seen.has(k)) return false;
  seen.add(k); return true;
});
const template = fs.readFileSync(path.join(ROOT, "dashboard-template.html"), "utf8");
const data = JSON.stringify({ generatedAt: new Date().toISOString(), items }).replace(/</g, "\\u003c");
fs.writeFileSync(path.join(ROOT, "cbom-dashboard.html"), template.replace("__DATA__", () => data), "utf8");
console.log(`Dashboard written: ${path.join(ROOT, "cbom-dashboard.html")} (${items.length} findings)`);
