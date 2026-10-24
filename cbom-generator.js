
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const ROOT = __dirname;
const OUTPUT_FILE = path.join(ROOT, "cbom.json");

const INPUT_FILES = {
  main: path.join(ROOT, "findings.json"),
  python: path.join(ROOT, "python-findings.json"),
  java: path.join(ROOT, "java-findings.json"),
  extra: path.join(ROOT, "extra-report.json"),
};

const VALID = {
  primitives: new Set([
    "ae", "block-cipher", "combiner", "drbg", "hash",
    "kdf", "kem", "key-agree", "mac", "pke",
    "signature", "stream-cipher", "xof", "other", "unknown",
  ]),
  modes: new Set([
    "cbc", "ecb", "ccm", "gcm", "cfb", "ofb",
    "ctr", "xts", "other", "unknown",
  ]),
  padding: new Set([
    "pkcs5", "pkcs7", "pkcs1v15", "oaep",
    "raw", "other", "unknown",
  ]),
  functions: new Set([
    "decapsulate", "decrypt", "digest", "encapsulate",
    "encrypt", "generate", "keyderive", "keygen",
    "sign", "tag", "verify", "other", "unknown",
  ]),
  environments: new Set([
    "software-plain-ram", "software-encrypted-ram",
    "software-tee", "hardware", "other", "unknown",
  ]),
  platforms: new Set([
    "generic", "x86_32", "x86_64", "armv7-a", "armv7-m",
    "armv8-a", "armv8-m", "armv9-a", "armv9-m",
    "s390x", "ppc64", "ppc64le", "other", "unknown",
  ]),
  certifications: new Set([
    "none",
    "fips-140-2-l1", "fips-140-2-l2", "fips-140-2-l3", "fips-140-2-l4",
    "fips-140-3-l1", "fips-140-3-l2", "fips-140-3-l3", "fips-140-3-l4",
    "cc-eal1", "cc-eal1+", "cc-eal2", "cc-eal2+",
    "cc-eal3", "cc-eal3+", "cc-eal4", "cc-eal4+",
    "cc-eal5", "cc-eal5+", "cc-eal6", "cc-eal6+",
    "cc-eal7", "cc-eal7+", "other", "unknown",
  ]),
};

function log(message) {
  console.log(message);
}

function readFindings(filePath, required = false) {
  if (!fs.existsSync(filePath)) {
    if (required) {
      throw new Error(`Required input file not found: ${filePath}`);
    }
    log(`Info: ${path.basename(filePath)} not found; skipping.`);
    return [];
  }

  let data;
  try {
    data = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(
      `Invalid JSON in ${path.basename(filePath)}: ${error.message}`
    );
  }

  // Support common scanner output shapes.
  let items;
  if (Array.isArray(data)) {
    items = data;
  } else if (data && Array.isArray(data.findings)) {
    items = data.findings;
  } else if (data && Array.isArray(data.items)) {
    items = data.items;
  } else if (data && Array.isArray(data.assets)) {
    items = data.assets;
  } else {
    throw new Error(
      `${path.basename(filePath)} must contain an array, ` +
      "or an object with findings/items/assets array."
    );
  }

  const valid = items.filter((item) =>
    item &&
    typeof item === "object" &&
    typeof (item.algorithm || item.algorithmName) === "string" &&
    String(item.algorithm || item.algorithmName).trim() !== ""
  );

  log(`${path.basename(filePath)}: ${valid.length} valid findings`);
  return valid;
}

function normalizeText(value) {
  return String(value ?? "").trim();
}

function lower(value) {
  return normalizeText(value).toLowerCase();
}

function getAlgorithm(finding) {
  return normalizeText(
    finding.algorithm || finding.algorithmName || "Unknown"
  ).replace(/\s+/g, " ");
}

function getFile(finding) {
  return normalizeText(
    finding.file || finding.filename || finding.path ||
    finding.source || finding.occurrences?.[0]?.file || ""
  );
}

function getLine(finding) {
  const value =
    finding.line ??
    finding.lineNumber ??
    finding.loc?.start?.line ??
    finding.occurrences?.[0]?.line;

  if (value === null || value === undefined || value === "") {
    return null;
  }

  const line = Number(value);
  return Number.isInteger(line) && line > 0 ? line : null;
}

function slug(value) {
  return lower(value)
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "unknown";
}

function safeNumber(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

function getApi(finding) {
  return lower(finding.api);
}

function getPrimitive(finding) {
  const algorithm = getAlgorithm(finding).toLowerCase();
  const api = getApi(finding);
  const type = lower(finding.type);
  const operation = lower(finding.operation);

  // Prefer explicit scanner classification when it is schema-valid.
  const explicit = lower(finding.primitive);
  if (VALID.primitives.has(explicit)) return explicit;

  // Check MAC before hash: HMAC-SHA256 contains "SHA".
  if (
    algorithm.includes("hmac") ||
    type === "mac" ||
    type.includes("message-authentication") ||
    api === "mac" ||
    operation === "mac"
  ) return "mac";

  if (
    /shake|blake2x|blake3-xof/.test(algorithm) ||
    type === "xof"
  ) return "xof";

  if (
    /^(sha|md2|md4|md5|blake|whirlpool)/.test(algorithm) ||
    api === "messagedigest" ||
    type === "hash"
  ) return "hash";

  if (
    /ml-kem|kyber/.test(algorithm) ||
    type === "kem"
  ) return "kem";

  if (
    /ecdh|x25519|x448|diffie.?hellman/.test(algorithm) ||
    algorithm === "dh" ||
    api === "keyagreement" ||
    type === "key-agreement" ||
    type === "key-agree"
  ) return "key-agree";

  if (
    /pbkdf|scrypt|argon2|hkdf/.test(algorithm) ||
    type === "kdf" ||
    type === "key-derivation"
  ) return "kdf";

  if (
    /ml-dsa|dilithium|falcon|sphincs|slh-dsa|ecdsa|ed25519|ed448|rsa.*signature|signature.*rsa/.test(algorithm) ||
    type === "signature" ||
    api === "signature"
  ) return "signature";

  // RSA alone does not establish whether it is being used for
  // signing, verification, encryption, or key transport.
  if (
    /rsa|rsa-oaep/.test(algorithm) ||
    type === "public-key"
  ) return "pke";

  if (
    /aes.*(gcm|ccm)|chacha20-poly1305/.test(algorithm) ||
    type === "aead" ||
    type === "authenticated-encryption"
  ) return "ae";

  if (
    /aes|des|camellia|serpent|twofish|aria|rc2/.test(algorithm)
  ) return "block-cipher";

  if (/chacha20|salsa20|rc4|arcfour/.test(algorithm)) {
    return "stream-cipher";
  }

  return "unknown";
}

function getCryptoFunctions(finding) {
  const algorithm = getAlgorithm(finding).toLowerCase();
  const description = [
    finding.cryptoFunction,
    finding.cryptoFunctions,
    finding.operation,
    finding.function,
    finding.method,
    finding.api,
    finding.type,
  ].flat().filter(Boolean).join(" ").toLowerCase();

  const result = new Set();

  // Use the operation where the scanner explicitly provides one.
  const operation = lower(finding.operation);
  const operationMap = {
    digest: "digest",
    hash: "digest",
    encrypt: "encrypt",
    encryption: "encrypt",
    decrypt: "decrypt",
    decryption: "decrypt",
    sign: "sign",
    signing: "sign",
    verify: "verify",
    verification: "verify",
    keygen: "keygen",
    "key-generation": "keygen",
    generate: "generate",
    derive: "keyderive",
    keyderive: "keyderive",
    "key-agreement": "keyderive",
    encapsulate: "encapsulate",
    decapsulate: "decapsulate",
    tag: "tag",
  };

  if (operationMap[operation]) result.add(operationMap[operation]);

  if (
    description.includes("createhash") ||
    description.includes("digest") ||
    getPrimitive(finding) === "hash" ||
    getPrimitive(finding) === "xof"
  ) result.add("digest");

  if (
    description.includes("hmac") ||
    description.includes("message-authentication") ||
    getPrimitive(finding) === "mac"
  ) result.add("tag");

  if (/encrypt|createcipher|encryption/.test(description)) {
    result.add("encrypt");
  }
  if (/decrypt|createdecipher|decryption/.test(description)) {
    result.add("decrypt");
  }

  if (
    /generatekey|keypairgenerator|keygenerator|keygen|key-generation|generate_key/.test(description)
  ) result.add("keygen");

  if (
    /keyagreement|keyderive|derive|exchange/.test(description) ||
    getPrimitive(finding) === "key-agree"
  ) result.add("keyderive");

  if (
    /\bsign\b|createsign|\.sign|signing/.test(description)
  ) result.add("sign");

  if (
    /\bverify\b|createverify|verification/.test(description)
  ) result.add("verify");

  if (/encapsulate/.test(description)) result.add("encapsulate");
  if (/decapsulate/.test(description)) result.add("decapsulate");

  return [...result].filter((value) => VALID.functions.has(value));
}

function getKeySize(finding) {
  // Only use fields explicitly named as key-size/length/bits.
  // Do not infer key size from names such as SHA-256 or AES-256.
  for (const value of [
    finding.keySize,
    finding.key_size,
    finding.keyLength,
    finding.key_length,
    finding.keySizeBits,
    finding.bits,
  ]) {
    const number = safeNumber(value);
    if (number !== null && Number.isInteger(number) && number > 0) {
      return number;
    }
  }

  return null;
}

function getMode(finding) {
  const raw = lower(finding.mode);
  if (VALID.modes.has(raw)) return raw;

  const algorithm = getAlgorithm(finding).toLowerCase();
  for (const mode of ["gcm", "ccm", "cbc", "ctr", "ofb", "cfb", "xts", "ecb"]) {
    if (new RegExp(`(?:^|[-_/ ])${mode}(?:$|[-_/ ])`, "i").test(algorithm)) {
      return mode;
    }
  }
  return null;
}

function getPadding(finding) {
  const raw = lower(finding.padding);
  if (VALID.padding.has(raw)) return raw;

  const text = `${getAlgorithm(finding)} ${normalizeText(finding.padding)}`.toLowerCase();
  if (/oaep/.test(text)) return "oaep";
  if (/pkcs5padding|pkcs5/.test(text)) return "pkcs5";
  if (/pkcs7padding|pkcs7/.test(text)) return "pkcs7";
  if (/pkcs1padding|pkcs1v1\.5|pkcs1v15/.test(text)) return "pkcs1v15";

  return null;
}

function createAlgorithmProperties(finding) {
  const properties = {
    primitive: getPrimitive(finding),
  };

  const keySize = getKeySize(finding);
  const mode = getMode(finding);
  const padding = getPadding(finding);
  const functions = getCryptoFunctions(finding);

  if (keySize !== null) {
    properties.parameterSetIdentifier = String(keySize);
  }
  if (mode) properties.mode = mode;
  if (padding) properties.padding = padding;
  if (functions.length) properties.cryptoFunctions = functions;

  const environment = lower(finding.executionEnvironment);
  if (VALID.environments.has(environment)) {
    properties.executionEnvironment = environment;
  }

  const platform = lower(finding.implementationPlatform);
  if (VALID.platforms.has(platform)) {
    properties.implementationPlatform = platform;
  }

  if (finding.certificationLevel !== undefined) {
    const values = Array.isArray(finding.certificationLevel)
      ? finding.certificationLevel
      : [finding.certificationLevel];

    const certifications = [...new Set(
      values.map((item) => lower(item)).filter((item) =>
        VALID.certifications.has(item)
      )
    )];

    if (certifications.length) {
      properties.certificationLevel = certifications;
    }
  }

  for (const [source, destination, max] of [
    ["classicalSecurityLevel", "classicalSecurityLevel", Infinity],
    ["nistQuantumSecurityLevel", "nistQuantumSecurityLevel", 6],
  ]) {
    const value = safeNumber(finding[source]);
    if (
      value !== null &&
      Number.isInteger(value) &&
      value <= max
    ) {
      properties[destination] = value;
    }
  }

  return properties;
}

function collectOccurrences(finding) {
  const sourceOccurrences = Array.isArray(finding.occurrences)
    ? finding.occurrences
    : [finding];

  const occurrences = [];
  const seen = new Set();

  for (const source of sourceOccurrences) {
    const file = normalizeText(
      source.file || source.location || source.filename ||
      source.path || finding.file || finding.filename || finding.path
    );
    const rawLine = source.line ?? source.lineNumber ?? getLine(finding);
    const line = rawLine == null ? null : Number(rawLine);

    if (!file) continue;

    const key = `${file}:${Number.isInteger(line) && line > 0 ? line : ""}`;
    if (seen.has(key)) continue;
    seen.add(key);

    occurrences.push({
      location: file,
      ...(Number.isInteger(line) && line > 0 ? { line } : {}),
    });
  }

  return occurrences;
}

function getCategory(finding) {
  return normalizeText(finding.category || finding.type || "code");
}

function getRisk(finding) {
  return normalizeText(finding.risk || finding.riskLevel || "unknown");
}

function createComponent(finding, index) {
  const algorithm = getAlgorithm(finding);
  const category = getCategory(finding);
  const occurrences = collectOccurrences(finding);

  const component = {
    type: "cryptographic-asset",
    "bom-ref": `crypto-${index}-${slug(algorithm)}-${crypto.randomUUID()}`,
    name: algorithm,
    cryptoProperties: {
      assetType:
        category.toLowerCase() === "certificate" ? "certificate" :
        ["key-material", "key"].includes(category.toLowerCase()) ? "related-crypto-material" :
        ["configuration", "protocol"].includes(category.toLowerCase()) ? "protocol" :
        "algorithm",
    },
  };

  if (component.cryptoProperties.assetType === "algorithm") {
    component.cryptoProperties.algorithmProperties =
      createAlgorithmProperties(finding);
  }

  const properties = [
    { name: "cbom:language", value: normalizeText(finding.language || "unknown") },
    { name: "cbom:category", value: category },
    { name: "cbom:risk-level", value: getRisk(finding) },
    { name: "cbom:quantum-status", value: normalizeText(finding.quantum || finding.quantumStatus || "unknown") },
  ];

  const recommendation = normalizeText(finding.recommendation);
  if (recommendation) {
    properties.push({ name: "cbom:recommendation", value: recommendation });
  }

  const reasons = Array.isArray(finding.reasons)
    ? finding.reasons.map(normalizeText).filter(Boolean)
    : finding.reason ? [normalizeText(finding.reason)] : [];

  if (reasons.length) {
    properties.push({
      name: "cbom:risk-reasons",
      value: reasons.join("; "),
    });
  }

  const keySize = getKeySize(finding);
  if (keySize !== null) {
    properties.push({
      name: "cbom:key-size-bits",
      value: String(keySize),
    });
  }

  if (finding.mode) {
    properties.push({
      name: "cbom:detected-mode",
      value: normalizeText(finding.mode),
    });
  }

  component.properties = properties;

  const descriptionParts = [
    ...reasons,
    recommendation,
  ].filter(Boolean);

  if (descriptionParts.length) {
    component.description = descriptionParts.join(" ");
  }

  if (occurrences.length) {
    component.evidence = { occurrences };
  }

  return component;
}

// Read the three inputs. Java findings may already be included in
// findings.json, so deduplicate only the Java input records.
function findingIdentity(finding) {
  return [
    getAlgorithm(finding).toLowerCase(),
    getFile(finding).toLowerCase(),
    getLine(finding) ?? "",
    lower(finding.api),
    lower(finding.operation),
    lower(finding.language),
  ].join("|");
}

function main() {
  const mainFindings = readFindings(INPUT_FILES.main);
  const pythonFindings = readFindings(INPUT_FILES.python);
  const separateJavaFindings = readFindings(INPUT_FILES.java);
  const extraFindings = readFindings(INPUT_FILES.extra);

  const jsFindings = mainFindings.filter(
    (finding) => lower(finding.language) !== "java"
  );

  const embeddedJava = mainFindings.filter(
    (finding) => lower(finding.language) === "java"
  );

  const javaMap = new Map();
  for (const finding of [...embeddedJava, ...separateJavaFindings]) {
    const key = findingIdentity(finding);
    if (!javaMap.has(key)) javaMap.set(key, finding);
  }

  const javaFindings = [...javaMap.values()];
  const allFindings = [...jsFindings, ...pythonFindings, ...javaFindings, ...extraFindings];

  // Stable deduplication of exact same scanner observations across inputs.
  const unique = new Map();
  for (const finding of allFindings) {
    const key = [
      findingIdentity(finding),
      getCategory(finding).toLowerCase(),
    ].join("|");
    if (!unique.has(key)) unique.set(key, finding);
  }

  const findings = [...unique.values()];

  const components = findings.map((finding, index) =>
    createComponent(finding, index + 1)
  );

  const bom = {
    $schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: {
        components: [{
          type: "application",
          name: "AST-Based CBOM Scanner",
          version: "2.2.0",
        }],
      },
      properties: [
        { name: "cbom:source-findings", value: "findings.json, python-findings.json, java-findings.json" },
        { name: "cbom:generator", value: "cbom-generator.js" },
      ],
    },
    components,
  };

  // Write atomically to avoid leaving a partially written CBOM.
  const temporaryFile = `${OUTPUT_FILE}.tmp`;
  fs.writeFileSync(temporaryFile, JSON.stringify(bom, null, 2) + "\n", "utf8");
  fs.renameSync(temporaryFile, OUTPUT_FILE);

  log("\n======================================");
  log(" AST-BASED CBOM GENERATOR");
  log("======================================");
  log(`JavaScript/TypeScript findings: ${jsFindings.length}`);
  log(`Python findings:                ${pythonFindings.length}`);
  log(`Java findings:                  ${javaFindings.length}`);
  log(`Additional findings:            ${extraFindings.length}`);
  log(`Unique findings:                ${findings.length}`);
  log(`CBOM components:                ${components.length}`);
  log(`CycloneDX version:              ${bom.specVersion}`);
  log(`Output: ${OUTPUT_FILE}`);
  log("======================================");
}

try {
  main();
} catch (error) {
  console.error(`CBOM generation failed: ${error.message}`);
  process.exitCode = 1;
}
