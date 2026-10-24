"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { analyzeFindings } = require("./risk-engine");
const ROOT = __dirname;
const INPUT_FILES = ["findings.json", "python-findings.json", "java-findings.json", "extra-report.json"];
const OUTPUT_FILE = path.join(ROOT, "risk-findings.json");

function readFindings(filename) {
  const full = path.join(ROOT, filename);
  if (!fs.existsSync(full)) return [];
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(full, "utf8")); }
  catch (e) { throw new Error(`Invalid JSON in ${filename}: ${e.message}`); }
  if (Array.isArray(parsed)) return parsed;
  for (const key of ["findings", "items", "assets"]) if (parsed && Array.isArray(parsed[key])) return parsed[key];
  throw new Error(`${filename} must be an array or contain findings/items/assets array`);
}
function main() {
  const merged = [];
  for (const file of INPUT_FILES) {
    const rows = readFindings(file);
    console.log(`${file}: ${rows.length} findings`);
    merged.push(...rows);
  }
  const unique = new Map();
  for (const f of merged) {
    if (!f || typeof f.algorithm !== "string") continue;
    const occurrence = Array.isArray(f.occurrences) ? f.occurrences[0] || {} : {};
    const key = [f.algorithm, f.file || occurrence.file, f.line || occurrence.line, f.api, f.operation].join("|").toLowerCase();
    if (!unique.has(key)) unique.set(key, f);
  }
  const report = analyzeFindings([...unique.values()]);
  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log("\nCRYPTOGRAPHIC RISK ASSESSMENT");
  console.log(JSON.stringify(report.summary, null, 2));
  console.log(`Report: ${OUTPUT_FILE}`);
}
try { main(); } catch (e) { console.error(`Risk assessment failed: ${e.message}`); process.exitCode = 1; }
