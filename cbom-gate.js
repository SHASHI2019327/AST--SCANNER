"use strict";

/**
 * CI gate. Usage:
 *   node cbom-gate.js [--fail-on critical|high|medium|low|unknown] [--fail-quantum] [--report file]
 * Exit codes: 0 = pass, 1 = policy violation, 2 = error.
 */

const fs = require("fs");
const path = require("path");
const { rank, LEVELS } = require("./risk-classifier");

function parseArgs(argv) {
    const opts = { failOn: "high", failQuantum: false, report: path.join(__dirname, "risk-report.json") };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg === "--fail-quantum") opts.failQuantum = true;
        else if (arg === "--fail-on") opts.failOn = argv[++i];
        else if (arg.startsWith("--fail-on=")) opts.failOn = arg.split("=")[1];
        else if (arg === "--report") opts.report = path.resolve(argv[++i]);
    }
    return opts;
}

const opts = parseArgs(process.argv.slice(2));

if (!LEVELS.includes(opts.failOn) || opts.failOn === "safe") {
    console.error(`Invalid --fail-on value "${opts.failOn}". Use: ${LEVELS.slice(1).join(", ")}`);
    process.exit(2);
}
if (!fs.existsSync(opts.report)) {
    console.error(`Risk report not found: ${opts.report}`);
    process.exit(2);
}

const report = JSON.parse(fs.readFileSync(opts.report, "utf8"));
const threshold = rank(opts.failOn);

const violations = report.items.filter(
    (item) =>
        rank(item.risk) >= threshold ||
        (opts.failQuantum && item.quantum === "vulnerable")
);

console.log("\n======================================");
console.log(" CBOM POLICY GATE");
console.log("======================================");
console.log(`Fail on: ${opts.failOn}+${opts.failQuantum ? " and quantum-vulnerable" : ""}`);

if (violations.length === 0) {
    console.log("RESULT: PASS\n");
    process.exit(0);
}

console.log(`RESULT: FAIL (${violations.length} violation(s))\n`);
for (const v of violations) {
    const where = v.occurrences.slice(0, 3).map((o) => `${o.file}:${o.line}`).join(", ");
    console.log(`  [${v.risk.toUpperCase()}] ${v.algorithm} (quantum: ${v.quantum})`);
    if (v.reasons.length) console.log(`      why: ${v.reasons.join(" ")}`);
    if (v.recommendation) console.log(`      fix: ${v.recommendation}`);
    console.log(`      at : ${where}${v.occurrences.length > 3 ? ", ..." : ""}`);
}
console.log("");
process.exit(1);
