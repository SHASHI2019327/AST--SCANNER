"use strict";
// Main entry point: JavaScript/TypeScript AST + Python AST + optional Java AST,
// CycloneDX 1.6 generation/validation, risk report, and CI policy.
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const script = path.join(__dirname, "unified-scanner.js");
const result = spawnSync(process.execPath, [script, ...process.argv.slice(2)], { stdio: "inherit", windowsHide: true });
if (result.error) { console.error(`Could not start scanner: ${result.error.message}`); process.exit(2); }
process.exit(result.status === null ? 2 : result.status);
