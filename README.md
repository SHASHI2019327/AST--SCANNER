# AST-SCANNER — CycloneDX 1.6 Cryptographic Inventory

A local static scanner that produces a CycloneDX 1.6 cryptographic inventory (CBOM), risk report, and HTML dashboard.

## Requirements

- Node.js 18+ (Node.js 20+ recommended)
- Python 3.10+ for Python AST scanning
- JDK 17+ and Maven for Java AST scanning. If not installed, pass `--skip-java`.
- npm network access for the first dependency install.

## Install

From this folder:

```powershell
npm install
npm test
```

## Run a scan

Pass a **project directory**, not a single file. Quote paths that contain spaces:

```powershell
node run-all.js "C:\Users\YOUR_USERNAME\Desktop\crypto-scanner" --skip-java --fail-on none
```

Use `--skip-java` only if JDK/Maven is not ready. Remove that option when both are installed to include the JavaParser AST scanner. To skip Python explicitly, use `--skip-python`.

Risk policy examples:

```powershell
node run-all.js "C:\path\to\project" --skip-java --fail-on none
node run-all.js "C:\path\to\project" --skip-java --fail-on high
node run-all.js "C:\path\to\project" --skip-java --fail-on critical
```

`none` means scan without failing the CI gate for severity. `high` and `critical` return exit code 1 when findings meet or exceed that severity. Setup, tool, or schema errors return a nonzero exit code.

## Outputs

- `cbom.json` — generated CycloneDX 1.6 CBOM.
- `risk-findings.json` — severity and quantum-risk assessment.
- `extra-report.json` — dependency/config/key/certificate/Go/C/C++ findings.
- `cbom-dashboard.html` — self-contained dashboard; open it in a browser.
- `findings.json` — JavaScript/TypeScript AST findings plus Java AST findings when Java scanning runs.
- `python-findings.json` — Python AST findings.
- `scanner-errors.json` — used by the broad static scanner when applicable.

The pipeline validates `cbom.json` against the bundled CycloneDX 1.6 schema before it reports success. You can also validate manually with `node validate-cbom.js`.

## Scanner coverage and limits

- JavaScript/TypeScript: Babel AST scanner.
- Python: Python `ast` scanner.
- Java: JavaParser AST scanner (requires Maven/JDK).
- Additional inventory: pattern-based detection for dependency manifests, configuration, key/certificate files, Go, C, and C++.

Static analysis cannot guarantee detection of every crypto use. Dynamic algorithm names, reflection, generated code, encrypted/unsupported keystores, and indirect library calls may require manual review. A schema-valid CBOM confirms document structure, not completeness of detection. Do not commit real private keys into a test project; use synthetic fixtures.
