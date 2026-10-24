"use strict";
const fs = require("node:fs");
const path = require("node:path");
const Ajv = require("ajv");
const addFormats = require("ajv-formats");

const ROOT = __dirname;
const readJson = (file) => JSON.parse(fs.readFileSync(path.join(ROOT, file), "utf8"));

function main() {
  const schema = readJson("schema/bom-1.6.schema.json");
  const spdx = readJson("schema/spdx.schema.json");
  const jsf = readJson("schema/jsf-0.82.schema.json");
  const cbom = readJson("cbom.json");
  const ajv = new Ajv({ allErrors: true, strict: false, validateFormats: false });
  addFormats(ajv);
  ajv.addSchema(spdx, "http://cyclonedx.org/schema/spdx.schema.json");
  ajv.addSchema(jsf, "http://cyclonedx.org/schema/jsf-0.82.schema.json");
  const validate = ajv.compile(schema);
  if (!validate(cbom)) {
    console.error("\nCBOM VALIDATION FAILED\n");
    console.error(JSON.stringify(validate.errors, null, 2));
    process.exitCode = 1;
    return;
  }
  console.log("\nCBOM VALIDATION SUCCESSFUL");
  console.log(`CycloneDX version: ${cbom.specVersion}`);
  console.log(`Cryptographic assets: ${(cbom.components || []).length}`);
  console.log(`Validated file: ${path.join(ROOT, "cbom.json")}`);
}

try { main(); }
catch (error) {
  console.error(`CBOM validation could not run: ${error.message}`);
  process.exitCode = 1;
}
