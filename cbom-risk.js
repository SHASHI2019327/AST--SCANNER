"use strict";

/**
 * Annotates cbom.json with weakness / quantum-risk data and writes risk-report.json.
 * Run after cbom-generator.js and before validate-cbom.js.
 */

const fs = require("fs");
const path = require("path");
const { analyse, rank, LEVELS } = require("./risk-classifier");

const DIR = __dirname;
const CBOM_FILE = path.join(DIR, "cbom.json");
const REPORT_FILE = path.join(DIR, "risk-report.json");
const FINDING_FILES = ["findings.json", "python-findings.json", "java-findings.json"]
    .map((name) => path.join(DIR, name));

const ALLOWED_MODES = new Set(["cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"]);

// scanner "operation" values -> CycloneDX cryptoFunctions
const OPERATION_TO_FUNCTIONS = {
    encrypt: ["encrypt"],
    decrypt: ["decrypt"],
    hash: ["digest"],
    digest: ["digest"],
    mac: ["tag"],
    authentication: ["tag"],
    sign: ["sign"],
    verify: ["verify"],
    signature: ["sign", "verify"],
    "key-generation": ["keygen"],
    "key-pair-generation": ["keygen"],
    "encryption-decryption": ["encrypt", "decrypt"],
    "key-agreement": ["keyderive"],
};

const normName = (value) => String(value || "Unknown").trim().replace(/\s+/g, " ");

function loadFindings() {
    const seen = new Set();
    const all = [];
    for (const file of FINDING_FILES) {
        if (!fs.existsSync(file)) continue;
        const data = JSON.parse(fs.readFileSync(file, "utf8"));
        if (!Array.isArray(data)) continue;
        for (const f of data) {
            if (!f || typeof f.algorithm !== "string" || !f.algorithm.trim()) continue;
            const key = [f.algorithm, f.file, f.line, f.api, f.operation].join("|").toLowerCase();
            if (seen.has(key)) continue;
            seen.add(key);
            all.push(f);
        }
    }
    return all;
}

function setProperty(component, name, value) {
    component.properties = (component.properties || []).filter((p) => p.name !== name);
    if (value !== undefined && value !== null && String(value) !== "") {
        component.properties.push({ name, value: String(value) });
    }
}

function main() {
    if (!fs.existsSync(CBOM_FILE)) {
        console.error(`cbom.json not found: ${CBOM_FILE}`);
        process.exit(2);
    }

    const cbom = JSON.parse(fs.readFileSync(CBOM_FILE, "utf8"));
    const findings = loadFindings();

    const groups = new Map();
    for (const f of findings) {
        const key = normName(f.algorithm);
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(f);
    }

    const items = [];

    for (const component of cbom.components || []) {
        const group = groups.get(component.name);
        if (!group) continue;

        const analyses = group.map((f) => ({ f, a: analyse(f) }));
        let best = analyses[0];
        for (const entry of analyses) {
            if (rank(entry.a.risk) > rank(best.a.risk)) best = entry;
        }

        const reasons = [...new Set(analyses.flatMap((e) => e.a.reasons))];
        const fixes = [...new Set(analyses.flatMap((e) => e.a.fixes))];
        const languages = [...new Set(group.map((f) => f.language || guessLanguage(f)))];
        const mode = analyses.map((e) => e.a.mode).find(Boolean) || null;
        const keySize = analyses.map((e) => e.a.keySize).find(Boolean) || null;

        // Merge functions across ALL findings (fixes "first finding only" behaviour)
        const functions = new Set();
        for (const f of group) {
            const op = String(f.operation || "").toLowerCase().replace(/_/g, "-");
            (OPERATION_TO_FUNCTIONS[op] || []).forEach((fn) => functions.add(fn));
        }

        const props = (component.cryptoProperties ||= { assetType: "algorithm" });
        const algo = (props.algorithmProperties ||= {});
        if (functions.size) algo.cryptoFunctions = [...functions];
        if (mode) {
            const lower = mode.toLowerCase();
            algo.mode = ALLOWED_MODES.has(lower) ? lower : "other";
        }
        if (keySize) algo.parameterSetIdentifier = String(keySize);
        if (best.a.quantumSecurityLevel !== null) {
            algo.nistQuantumSecurityLevel = best.a.quantumSecurityLevel;
        }

        setProperty(component, "cbom:risk-level", best.a.risk);
        setProperty(component, "cbom:quantum-status", best.a.quantum);
        setProperty(component, "cbom:weaknesses", reasons.join(" | "));
        setProperty(component, "cbom:recommendation", fixes.join(" "));
        setProperty(component, "cbom:languages", languages.join(","));

        items.push({
            algorithm: component.name,
            risk: best.a.risk,
            quantum: best.a.quantum,
            keySize,
            mode,
            languages,
            reasons,
            recommendation: fixes.join(" "),
            occurrences: group.map((f) => ({
                file: f.file,
                line: f.line,
                api: f.api,
                language: f.language || guessLanguage(f),
                library: f.library,
            })),
        });
    }

    items.sort((a, b) => rank(b.risk) - rank(a.risk) || a.algorithm.localeCompare(b.algorithm));

    const summary = { total: items.length, byRisk: {}, quantumVulnerable: 0, quantumWeakened: 0 };
    LEVELS.forEach((l) => (summary.byRisk[l] = 0));
    for (const item of items) {
        summary.byRisk[item.risk]++;
        if (item.quantum === "vulnerable") summary.quantumVulnerable++;
        if (item.quantum === "weakened") summary.quantumWeakened++;
    }

    fs.writeFileSync(CBOM_FILE, JSON.stringify(cbom, null, 2), "utf8");
    fs.writeFileSync(
        REPORT_FILE,
        JSON.stringify({ generatedAt: new Date().toISOString(), summary, items }, null, 2),
        "utf8"
    );

    console.log("\n======================================");
    console.log(" CBOM RISK ANALYSIS");
    console.log("======================================");
    for (const item of items) {
        console.log(
            `${item.risk.toUpperCase().padEnd(9)} ${item.algorithm.padEnd(28)} quantum: ${item.quantum}`
        );
    }
    console.log("--------------------------------------");
    console.log("By risk:", JSON.stringify(summary.byRisk));
    console.log(`Quantum-vulnerable: ${summary.quantumVulnerable}`);
    console.log(`Report: ${REPORT_FILE}\n`);
}

function guessLanguage(f) {
    const lib = String(f.library || "").toLowerCase();
    if (lib.includes("node")) return "JavaScript";
    if (lib.includes("python") || lib.includes("pycrypto")) return "Python";
    if (lib.includes("java")) return "Java";
    return "unknown";
}

main();
