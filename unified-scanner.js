
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { enforceRiskThreshold } = require("./ci-policy");

const SCANNER_DIR = __dirname;

const FILES = {
    jsScanner: path.join(SCANNER_DIR, "scanner.js"),
    pythonScanner: path.join(SCANNER_DIR, "python-scanner.py"),
    extraScanner: path.join(SCANNER_DIR, "extra-scanner.js"),
    dashboardBuilder: path.join(SCANNER_DIR, "build-dashboard.js"),
    javaPom: path.join(SCANNER_DIR, "java-scanner", "pom.xml"),
    generator: path.join(SCANNER_DIR, "cbom-generator.js"),
    validator: path.join(SCANNER_DIR, "validate-cbom.js"),
    riskReport: path.join(SCANNER_DIR, "risk-report.js"),
    ciPolicy: path.join(SCANNER_DIR, "ci-policy.js"),
    findings: path.join(SCANNER_DIR, "risk-findings.json"),
};

const VALID_THRESHOLDS = ["none", "high", "critical"];

const USAGE = `
AST-Based Unified Cryptographic Scanner

Usage:
  node unified-scanner.js <project-dir> [options]

Options:
  --fail-on <level>   Risk threshold: none, high, critical
                      Default: none
  --skip-java         Skip Java scanning
  --skip-python       Skip Python scanning
  -h, --help          Display help

Exit codes:
  0 = Scan completed and policy passed
  1 = Risk policy failed or CBOM validation failed
  2 = Scanner/setup error
`;

function fail(message, code = 2) {
    console.error(`\nERROR: ${message}`);
    process.exit(code);
}

function banner(message) {
    console.log("\n" + "=".repeat(64));
    console.log(message);
    console.log("=".repeat(64));
}

function parseArguments(argv) {
    const options = {
        target: null,
        failOn: "none",
        skipJava: false,
        skipPython: false,
    };

    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];

        if (arg === "-h" || arg === "--help") {
            console.log(USAGE);
            process.exit(0);
        }

        if (arg === "--fail-on") {
            const value = argv[++i];

            if (!value || value.startsWith("--")) {
                fail(
                    'Missing threshold. Use "none", "high", or "critical".'
                );
            }

            options.failOn = value.toLowerCase();
            continue;
        }

        if (arg.startsWith("--fail-on=")) {
            options.failOn = arg
                .slice("--fail-on=".length)
                .toLowerCase();
            continue;
        }

        if (arg === "--skip-java") {
            options.skipJava = true;
            continue;
        }

        if (arg === "--skip-python") {
            options.skipPython = true;
            continue;
        }

        if (arg.startsWith("--")) {
            fail(`Unknown option: ${arg}\n${USAGE}`);
        }

        if (options.target !== null) {
            fail(`Unexpected extra argument: ${arg}\n${USAGE}`);
        }

        options.target = arg;
    }

    if (!options.target) {
        fail(`Missing target project directory.\n${USAGE}`);
    }

    if (!VALID_THRESHOLDS.includes(options.failOn)) {
        fail(
            `Invalid risk threshold "${options.failOn}". ` +
            'Allowed values: "none", "high", "critical".'
        );
    }

    return options;
}

function checkFile(filePath, description) {
    if (!fs.existsSync(filePath)) {
        fail(`${description} not found:\n${filePath}`);
    }

    if (!fs.statSync(filePath).isFile()) {
        fail(`${description} is not a file:\n${filePath}`);
    }
}

function runCommand(command, args, description, options = {}) {
    banner(description);

    const result = spawnSync(command, args, {
        cwd: options.cwd || SCANNER_DIR,
        encoding: "utf8",
        stdio: "inherit",
        windowsHide: true,
        shell: false,
        env: {
            ...process.env,
            ...(options.env || {}),
        },
    });

    if (result.error) {
        fail(
            `Could not start ${description}: ${result.error.message}`
        );
    }

    if (result.status !== 0) {
        fail(
            `${description} failed with exit code ` +
            `${result.status ?? "unknown"}.`
        );
    }
}

// --------------------------------------------------
// Python discovery
// --------------------------------------------------

function findPython() {
    const candidates =
        process.platform === "win32"
            ? ["python", "py", "python3"]
            : ["python3", "python"];

    for (const command of candidates) {
        const result = spawnSync(command, ["--version"], {
            encoding: "utf8",
            windowsHide: true,
            shell: false,
        });

        if (!result.error && result.status === 0) {
            const version = (
                result.stdout ||
                result.stderr ||
                ""
            ).trim();

            console.log(`Python detected: ${command} ${version}`);
            return command;
        }
    }

    return null;
}

// --------------------------------------------------
// Maven discovery
// --------------------------------------------------

function findMaven() {
    const isWindows = process.platform === "win32";
    const candidates = [];

    if (process.env.MVN_CMD) {
        candidates.push(process.env.MVN_CMD);
    }

    candidates.push("mvn");

    if (process.env.MAVEN_HOME) {
        candidates.push(
            path.join(
                process.env.MAVEN_HOME,
                "bin",
                isWindows ? "mvn.cmd" : "mvn"
            )
        );
    }

    if (process.env.M2_HOME) {
        candidates.push(
            path.join(
                process.env.M2_HOME,
                "bin",
                isWindows ? "mvn.cmd" : "mvn"
            )
        );
    }

    if (isWindows && process.env.APPDATA) {
        candidates.push(
            path.join(
                process.env.APPDATA,
                "Code",
                "User",
                "globalStorage",
                "pleiades.java-extension-pack-jdk",
                "maven",
                "latest",
                "bin",
                "mvn.cmd"
            )
        );
    }

    const uniqueCandidates = [...new Set(candidates)];

    for (const candidate of uniqueCandidates) {
        const result = spawnMaven(candidate, ["--version"], {
            stdio: "ignore",
        });

        if (!result.error && result.status === 0) {
            console.log(`Maven detected: ${candidate}`);
            return candidate;
        }
    }

    return null;
}

function spawnMaven(mavenCommand, args, options = {}) {
    const isWindows = process.platform === "win32";

    const baseOptions = {
        cwd: options.cwd || SCANNER_DIR,
        stdio: options.stdio || "inherit",
        encoding: "utf8",
        windowsHide: true,
        shell: false,
        env: {
            ...process.env,
            ...(options.env || {}),
        },
    };

    if (!isWindows) {
        return spawnSync(mavenCommand, args, baseOptions);
    }

    // Windows batch files require cmd.exe.
    const quote = (value) =>
        `"${String(value).replace(/"/g, '""')}"`;

    const commandLine = [mavenCommand, ...args]
        .map(quote)
        .join(" ");

    return spawnSync(
        process.env.ComSpec || "cmd.exe",
        ["/d", "/s", "/c", `"${commandLine}"`],
        {
            ...baseOptions,
            windowsVerbatimArguments: true,
        }
    );
}

function runJavaScanner(targetDirectory, mavenCommand) {
    banner("Running Java AST scanner");

    const result = spawnMaven(
        mavenCommand,
        [
            "-f",
            FILES.javaPom,
            "compile",
            "exec:java",
        ],
        {
            cwd: SCANNER_DIR,
            env: {
                CBOM_TARGET: targetDirectory,
            },
        }
    );

    if (result.error) {
        fail(`Could not start Java scanner: ${result.error.message}`);
    }

    if (result.status !== 0) {
        fail(
            `Java scanner failed with exit code ` +
            `${result.status ?? "unknown"}.`
        );
    }
}

// --------------------------------------------------
// Risk report
// --------------------------------------------------

function loadRiskReport() {
    checkFile(FILES.findings, "Risk findings report");

    let report;

    try {
        report = JSON.parse(
            fs.readFileSync(FILES.findings, "utf8")
        );
    } catch (error) {
        fail(`Cannot parse risk findings JSON: ${error.message}`);
    }

    if (!report || !Array.isArray(report.findings)) {
        fail(
            'Invalid risk report: expected a "findings" array.'
        );
    }

    return report;
}

// --------------------------------------------------
// Main pipeline
// --------------------------------------------------

function main() {
    const options = parseArguments(process.argv.slice(2));

    const targetDirectory = path.resolve(options.target);

    if (!fs.existsSync(targetDirectory)) {
        fail(`Target directory does not exist:\n${targetDirectory}`);
    }

    if (!fs.statSync(targetDirectory).isDirectory()) {
        fail(`Target path is not a directory:\n${targetDirectory}`);
    }

    // Validate required project files before starting.
    checkFile(FILES.jsScanner, "JavaScript/TypeScript scanner");
    checkFile(FILES.generator, "CBOM generator");
    checkFile(FILES.validator, "CBOM validator");
    checkFile(FILES.riskReport, "Risk report generator");
    checkFile(FILES.ciPolicy, "CI policy module");
    checkFile(FILES.pythonScanner, "Python scanner");
    checkFile(FILES.extraScanner, "Additional scanner");
    checkFile(FILES.dashboardBuilder, "Dashboard builder");
    if (!options.skipJava) checkFile(FILES.javaPom, "Java scanner Maven configuration");

    console.log("\nAST-Based Unified Cryptographic Scanner");
    console.log(`Scanner directory: ${SCANNER_DIR}`);
    console.log(`Target directory:  ${targetDirectory}`);
    console.log(`Risk threshold:    ${options.failOn.toUpperCase()}`);

    // 1. JavaScript and TypeScript.
    runCommand(
        process.execPath,
        [FILES.jsScanner, targetDirectory],
        "Scanning JavaScript and TypeScript"
    );

    // 2. Python.
    if (!options.skipPython) {
        const pythonCommand = findPython();

        if (!pythonCommand) {
            fail(
                "Python is unavailable. Install Python and add it to PATH, " +
                "or explicitly use --skip-python."
            );
        }

        runCommand(
            pythonCommand,
            [FILES.pythonScanner, targetDirectory],
            "Scanning Python"
        );
    } else {
        console.log("\nPython scan explicitly skipped.");
    }

    // 3. Java.
    if (!options.skipJava) {
        const mavenCommand = findMaven();

        if (!mavenCommand) {
            fail(
                "Maven is unavailable. Install Maven or configure MVN_CMD, " +
                "MAVEN_HOME, or M2_HOME. Alternatively, use --skip-java."
            );
        }

        runJavaScanner(targetDirectory, mavenCommand);
    } else {
        console.log("\nJava scan explicitly skipped.");
    }

    // 4. Scan dependencies, crypto material, configuration, Go and C/C++.
    runCommand(
        process.execPath,
        [FILES.extraScanner, targetDirectory],
        "Scanning dependencies, keys/certificates, configuration and additional languages"
    );

    // 5. Generate CycloneDX 1.6 CBOM from all scanner outputs.
    runCommand(
        process.execPath,
        [FILES.generator],
        "Generating CycloneDX 1.6 CBOM"
    );

    // 6. Validate the generated CBOM.
    runCommand(
        process.execPath,
        [FILES.validator],
        "Validating CycloneDX 1.6 CBOM"
    );

    // 7. Generate cryptographic risk findings.
    runCommand(
        process.execPath,
        [FILES.riskReport],
        "Generating cryptographic risk assessment"
    );

    // 8. Build the standalone dashboard.
    runCommand(process.execPath, [FILES.dashboardBuilder], "Building scan dashboard");

    // 9. Enforce the shared CI policy.
    const report = loadRiskReport();
    const policyResult = enforceRiskThreshold(
        report,
        options.failOn
    );

    if (
        !policyResult ||
        typeof policyResult.passed !== "boolean"
    ) {
        fail(
            "CI policy returned an unexpected result. " +
            "Expected an object containing a boolean 'passed' property."
        );
    }

    banner(
        policyResult.passed
            ? "UNIFIED SCAN COMPLETED SUCCESSFULLY"
            : "SCAN COMPLETED - RISK POLICY FAILED"
    );

    console.log(`Target scanned: ${targetDirectory}`);
    console.log(`CBOM output:    ${path.join(SCANNER_DIR, "cbom.json")}`);
    console.log(`Risk report:    ${FILES.findings}`);

    if (options.skipPython || options.skipJava) {
        console.warn(
            "\nWARNING: One or more language scanners were skipped. " +
            "This result does not represent a complete multi-language scan."
        );
    }

    if (!policyResult.passed) {
        process.exitCode = 1;
    }
}

try {
    main();
} catch (error) {
    console.error(`\nUnexpected scanner error: ${error.message}`);
    process.exitCode = 2;
}
