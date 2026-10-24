"use strict";

const fs = require("node:fs");
const path = require("node:path");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const SUPPORTED_EXTENSIONS = new Set([
  ".js", ".mjs", ".cjs", ".jsx",
  ".ts", ".tsx", ".mts", ".cts",
]);

const IGNORED_DIRECTORIES = new Set([
  "node_modules", ".git", ".svn", ".hg", "dist", "build", 
  "coverage", ".next", ".nuxt", ".output", ".turbo", ".cache", "vendor",
]);

const CRYPTO_MODULES = new Set(["crypto", "node:crypto"]);

function createFinding(data) {
  return {
    algorithm: data.algorithm ?? "unknown",
    family: data.family ?? "unknown",
    type: data.type ?? "unknown",
    keySize: data.keySize ?? null,
    operation: data.operation ?? "unknown",
    api: data.api ?? "unknown",
    file: data.file,
    line: data.line ?? null,
    language: data.language,
    risk: data.risk ?? "unknown",
    reason: data.reason ?? "",
    cwe: data.cwe ?? "N/A",
  };
}

function getStringValue(node) {
  if (!node) return null;
  if (node.type === "StringLiteral" || node.type === "Literal") {
    return typeof node.value === "string" ? node.value : null;
  }
  if (node.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis[0]?.value?.cooked ?? null;
  }
  return null;
}

function getNumericValue(node) {
  if (!node) return null;
  if (node.type === "NumericLiteral" || (node.type === "Literal" && typeof node.value === "number")) {
    return node.value;
  }
  if (node.type === "UnaryExpression" && node.operator === "-") {
    const value = getNumericValue(node.argument);
    return value === null ? null : -value;
  }
  return null;
}

function getPropertyName(property) {
  if (!property || property.type !== "ObjectProperty") return null;
  if (!property.computed && property.key.type === "Identifier") return property.key.name;
  if (property.key.type === "StringLiteral" || property.key.type === "Literal") return String(property.key.value);
  return null;
}

function getObjectOption(objectNode, optionName) {
  if (objectNode?.type !== "ObjectExpression") return null;
  for (const property of objectNode.properties) {
    if (property.type === "SpreadElement") continue;
    if (getPropertyName(property) === optionName) {
      return getNumericValue(property.value);
    }
  }
  return null;
}

function getStringOption(objectNode, optionName) {
  if (objectNode?.type !== "ObjectExpression") return null;
  for (const property of objectNode.properties) {
    if (property.type === "SpreadElement") continue;
    if (getPropertyName(property) === optionName) {
      return getStringValue(property.value);
    }
  }
  return null;
}

function normalizeAlgorithm(value) {
  return String(value ?? "unknown").trim().toUpperCase().replace(/\s+/g, "-");
}

// ---------------------------------------------------------
// RULE SET 1: HASH ALGORITHMS (CWE-328)
// ---------------------------------------------------------
function getHashInformation(algorithm) {
  const normalized = normalizeAlgorithm(algorithm);
  let family = "HASH";
  let risk = "safe";
  let reason = "Safe hash algorithm.";
  let cwe = "N/A";

  if (/^SHA-?1$/.test(normalized) || normalized === "MD5" || normalized === "MD4" || normalized === "MD2" || normalized === "SHA-0" || normalized === "RIPEMD-160") {
    family = normalized.replace("-", "");
    risk = "high";
    reason = `${family} is cryptographically broken or deprecated.`;
    cwe = "CWE-328";
  } else if (/^SHA-?224$/.test(normalized) || /^SHA-?256$/.test(normalized) || /^SHA-?384$/.test(normalized) || /^SHA-?512(?:\/256|\/224)?$/.test(normalized)) {
    family = "SHA-2";
  } else if (/^SHA3-/.test(normalized)) {
    family = "SHA-3";
  } else if (/^BLAKE2/.test(normalized)) {
    family = "BLAKE";
  }

  return { algorithm: normalized, family, keySize: null, risk, reason, cwe };
}

// ---------------------------------------------------------
// RULE SET 2: CIPHERS & MODES (CWE-327)
// ---------------------------------------------------------
function getCipherInformation(algorithm) {
  const normalized = normalizeAlgorithm(algorithm);
  const aesMatch = normalized.match(/\bAES-(128|192|256)\b/);
  const isLegacy = /3DES|TRIPLEDES|DES-EDE|^DES|RC2|RC4|ARCFOUR|BLOWFISH|CAST5|IDEA|SKIPJACK|NULLCIPHER|PAKE/i.test(normalized);
  const isEcb = normalized.includes("/ECB/") || normalized === "AES" || normalized === "DES";
  const isCbcPkcs5 = normalized.includes("/CBC/") && (normalized.includes("PKCS5") || normalized.includes("PKCS7"));

  let risk = "safe";
  let reason = "Safe cipher.";
  let cwe = "N/A";

  if (isLegacy) {
    risk = "critical";
    reason = `${normalized} is a legacy cipher and should be retired immediately.`;
    cwe = "CWE-327";
  } else if (isEcb) {
    risk = "high";
    reason = "ECB mode reveals patterns and lacks semantic security (Penguin attack).";
    cwe = "CWE-327";
  } else if (isCbcPkcs5) {
    risk = "medium";
    reason = "CBC mode with PKCS5/7 padding is vulnerable to Padding Oracle attacks.";
    cwe = "CWE-327";
  }

  if (aesMatch) return { algorithm: normalized, family: "AES", keySize: Number(aesMatch[1]), risk, reason, cwe };
  if (isLegacy) return { algorithm: normalized, family: "LEGACY_SYMMETRIC", keySize: null, risk, reason, cwe };
  if (/^CHACHA20(?:-POLY1305)?$/.test(normalized)) return { algorithm: normalized, family: "CHACHA20", keySize: 256, risk: "safe", reason, cwe };
  
  return { algorithm: normalized, family: "SYMMETRIC", keySize: null, risk, reason, cwe };
}

// ---------------------------------------------------------
// RULE SET 3: PUBLIC KEY & PQC (CWE-326 / Migration)
// ---------------------------------------------------------
function getPublicKeyInformation(algorithm, optionsNode) {
  const normalized = String(algorithm ?? "").trim().toLowerCase();
  let risk = "medium";
  let reason = "Quantum-vulnerable algorithm (migration planning needed).";
  let cwe = "CWE-327";

  if (["ml-kem", "kyber", "ml-dsa", "dilithium", "slh-dsa", "falcon", "hqc", "x25519mlkem768"].some(pqc => normalized.includes(pqc))) {
    return { algorithm: normalized.toUpperCase(), family: "PQC", keySize: null, risk: "safe", reason: "Post-Quantum Cryptography (PQC) algorithm.", cwe: "N/A" };
  }

  const keySize = normalized.includes("rsa") 
    ? getObjectOption(optionsNode, "modulusLength") 
    : getObjectOption(optionsNode, "primeLength");

  if (normalized.includes("rsa") && keySize && keySize < 2048) {
    risk = "high";
    reason = "RSA key size too small (less than 2048 bits).";
  } else if (normalized.includes("rsa")) {
    return { algorithm: "RSA", family: "RSA", keySize: keySize, risk: "medium", reason, cwe };
  } else if (["ec", "ecdsa", "ecdh"].includes(normalized)) {
    const curve = getStringOption(optionsNode, "namedCurve");
    const curveSize = getCurveSize(curve);
    if (curve && ["secp192r1", "prime192v1", "p-192", "x9_62_prime256v1"].includes(curve.toLowerCase())) {
       risk = "high";
       reason = `Weak Elliptic Curve detected: ${curve}.`;
    }
    return { algorithm: normalized.toUpperCase(), family: "ECDSA/ECDH", keySize: curveSize, risk: risk, reason, cwe };
  } else if (normalized === "ed25519" || normalized === "ed448" || normalized === "x25519" || normalized === "x448") {
    return { algorithm: normalized.toUpperCase(), family: "EdDSA/ECDH", keySize: null, risk: "medium", reason: "Quantum-vulnerable ECC variant.", cwe };
  }

  return { algorithm: algorithm ?? "unknown", family: "unknown", keySize: null, risk: "unknown", reason: "Unknown algorithm.", cwe: "N/A" };
}

function getCurveSize(curve) {
  if (!curve) return null;
  const normalized = curve.toLowerCase();
  const curves = {
    "prime256v1": 256, "secp256r1": 256, "p-256": 256,
    "secp384r1": 384, "p-384": 384, "secp521r1": 521,
    "p-521": 521, "secp256k1": 256, "secp192r1": 192, "prime192v1": 192,
  };
  return curves[normalized] ?? null;
}

// ---------------------------------------------------------
// RULE SET 4: RANDOM NUMBER GENERATION (CWE-330)
// ---------------------------------------------------------
function checkRandomNumberGeneration(callee, node, relativeFile, findings, language) {
  const base = { file: relativeFile, line: node.loc?.start.line ?? null, language };
  const methodName = callee.type === "MemberExpression" ? callee.property.name : (callee.type === "Identifier" ? callee.name : null);

  if (!methodName) return;

  if (["random", "randomInt", "randomUUID"].includes(methodName)) {
    let isInsecure = false;
    if (callee.type === "MemberExpression" && callee.object.name === "Math" && callee.property.name === "random") {
        isInsecure = true;
    }
    if (isInsecure) {
        findings.push(createFinding({
            ...base,
            algorithm: "Math.random()",
            family: "PRNG",
            type: "random-generation",
            keySize: null,
            risk: "high",
            reason: "Math.random() is not cryptographically secure and predictable.",
            cwe: "CWE-330",
            operation: "random-generation",
            api: "Math.random",
        }));
    }
  }
}

// ---------------------------------------------------------
// CORE SCANNER LOGIC
// ---------------------------------------------------------
function getCryptoMethodName(member) {
  if (!member || member.type !== "MemberExpression") return null;
  if (!member.computed && member.property.type === "Identifier") return member.property.name;
  if (member.computed) return getStringValue(member.property);
  return null;
}

function isCryptoRequire(node) {
  return (
    node?.type === "CallExpression" &&
    node.callee?.type === "Identifier" &&
    node.callee.name === "require" &&
    CRYPTO_MODULES.has(getStringValue(node.arguments?.[0]))
  );
}

function isCryptoModuleBinding(binding) {
  if (!binding) return false;
  const bindingPath = binding.path;
  if (bindingPath.isVariableDeclarator()) {
    return bindingPath.node.id.type === "Identifier" && isCryptoRequire(bindingPath.node.init);
  }
  if (bindingPath.isImportDefaultSpecifier() || bindingPath.isImportNamespaceSpecifier()) {
    const declaration = bindingPath.parentPath;
    return declaration?.isImportDeclaration() && CRYPTO_MODULES.has(declaration.node.source.value);
  }
  return false;
}

function isImportedCryptoFunctionBinding(binding, methodName) {
  if (!binding) return false;
  const bindingPath = binding.path;
  if (bindingPath.isImportSpecifier()) {
    const declaration = bindingPath.parentPath;
    if (!declaration?.isImportDeclaration() || !CRYPTO_MODULES.has(declaration.node.source.value)) return false;
    const imported = bindingPath.node.imported;
    const importedName = imported.type === "Identifier" ? imported.name : imported.value;
    return importedName === methodName;
  }
  if (bindingPath.isVariableDeclarator()) {
    const { id, init } = bindingPath.node;
    if (id.type !== "ObjectPattern" || !isCryptoRequire(init)) return false;
    return id.properties.some((property) => {
      if (property.type !== "ObjectProperty" || property.value.type !== "Identifier") return false;
      return property.value.name === binding.identifier.name && getPropertyName(property) === methodName;
    });
  }
  return false;
}

function getSourceFiles(target) {
  if (!fs.existsSync(target)) throw new Error(`Target path does not exist: ${target}`);
  const stats = fs.statSync(target);
  if (stats.isFile()) {
    const extension = path.extname(target).toLowerCase();
    if (!SUPPORTED_EXTENSIONS.has(extension)) throw new Error(`Unsupported file extension: ${target}`);
    return [target];
  }
  if (!stats.isDirectory()) throw new Error(`Target must be a file or directory: ${target}`);

  const files = [];
  function walk(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) walk(fullPath);
      } else if (entry.isFile() && SUPPORTED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        files.push(fullPath);
      }
    }
  }
  walk(target);
  return files.sort();
}

// ---------------------------------------------------------
// PROCESSING NODE.JS CRYPTO METHODS
// ---------------------------------------------------------
function processCryptoMethod(methodName, node, relativeFile, findings, language) {
  const line = node.loc?.start.line ?? null;
  const args = node.arguments ?? [];
  const base = { file: relativeFile, line, language };

  switch (methodName) {
    case "randomBytes":
    case "randomFillSync":
    case "randomFill": {
      findings.push(createFinding({ 
        ...base, algorithm: "SecureRandom", family: "PRNG", type: "random-generation", 
        keySize: null, risk: "safe", reason: "Secure random bytes generated.", cwe: "N/A", 
        operation: "random-generation", api: `crypto.${methodName}` 
      }));
      return;
    }
    case "pbkdf2":
    case "pbkdf2Sync": {
      const digest = getStringValue(args[4]) || "sha1";
      const info = getHashInformation(digest);
      findings.push(createFinding({ 
        ...base, algorithm: `PBKDF2-${info.algorithm}`, family: "KDF", type: "key-derivation", 
        keySize: null, risk: info.risk, reason: "PBKDF2 key derivation detected.", cwe: "N/A", 
        operation: "key-derivation", api: `crypto.${methodName}` 
      }));
      return;
    }
    case "scrypt":
    case "scryptSync": {
      findings.push(createFinding({ 
        ...base, algorithm: "scrypt", family: "KDF", type: "key-derivation", 
        keySize: null, risk: "safe", reason: "scrypt key derivation detected.", cwe: "N/A", 
        operation: "key-derivation", api: `crypto.${methodName}` 
      }));
      return;
    }
    case "hkdf":
    case "hkdfSync": {
      const digest = getStringValue(args[0]) || "sha256";
      const info = getHashInformation(digest);
      findings.push(createFinding({ 
        ...base, algorithm: `HKDF-${info.algorithm}`, family: "KDF", type: "key-derivation", 
        keySize: null, risk: info.risk, reason: "HKDF key derivation detected.", cwe: "N/A", 
        operation: "key-derivation", api: `crypto.${methodName}` 
      }));
      return;
    }
    case "createSecretKey":
    case "createPublicKey":
    case "createPrivateKey": {
      findings.push(createFinding({ 
        ...base, algorithm: "KeyObject", family: "KEY_MANAGEMENT", type: "key-import", 
        keySize: null, risk: "safe", reason: "Cryptographic key imported/created.", cwe: "N/A", 
        operation: "key-management", api: `crypto.${methodName}` 
      }));
      return;
    }
    case "createHash":
    case "createHmac": {
      const algorithm = getStringValue(args[0]) ?? "unknown";
      const info = getHashInformation(algorithm);
      findings.push(createFinding({ ...base, ...info, type: "hash", operation: methodName === "createHash" ? "hash" : "hmac", api: `crypto.${methodName}` }));
      return;
    }
    case "createCipher":
    case "createCipheriv":
    case "createDecipher":
    case "createDecipheriv": {
      const algorithm = getStringValue(args[0]) ?? "unknown";
      const info = getCipherInformation(algorithm);
      const decrypt = methodName.startsWith("createDecipher");
      findings.push(createFinding({ ...base, ...info, type: "cipher", operation: decrypt ? "decryption" : "encryption", api: `crypto.${methodName}` }));
      return;
    }
    case "generateKey":
    case "generateKeySync":
    case "generateKeyPair":
    case "generateKeyPairSync": {
      const algorithm = getStringValue(args[0]) ?? "unknown";
      const info = getPublicKeyInformation(algorithm, args[1]);
      findings.push(createFinding({ ...base, ...info, type: "public-key", operation: "key-generation", api: `crypto.${methodName}` }));
      return;
    }
    case "publicEncrypt":
    case "privateDecrypt":
    case "privateEncrypt":
    case "publicDecrypt":
    case "sign":
    case "verify": {
      let algorithmName = "RSA";
      if (args[0] && args[0].type === "ObjectExpression") {
        for (const prop of args[0].properties) {
          if (prop.type === "ObjectProperty" && getPropertyName(prop) === "padding") {
             const val = prop.value.toString();
             if (val.includes("OAEP")) algorithmName = "RSA-OAEP";
             if (val.includes("PSS")) algorithmName = "RSA-PSS";
          }
        }
      } else if (methodName === "sign" || methodName === "verify") {
        const alg = getStringValue(args[0]);
        if (alg) algorithmName = `RSA-${alg.toUpperCase()}`;
      }

      findings.push(createFinding({ 
        ...base, algorithm: algorithmName, family: "RSA", type: "public-key", 
        keySize: null, risk: "medium", reason: "Quantum-vulnerable RSA operation.", 
        cwe: "CWE-327", operation: methodName, api: `crypto.${methodName}` 
      }));
      return;
    }
    case "createSign":
    case "createVerify": {
      const algorithm = getStringValue(args[0]) ?? "unknown";
      findings.push(createFinding({ ...base, algorithm: normalizeAlgorithm(algorithm), family: "SIGNATURE", type: "signature", keySize: null, risk: "medium", reason: "Quantum-vulnerable signature.", cwe: "CWE-327", operation: methodName === "createSign" ? "signing" : "verification", api: `crypto.${methodName}` }));
      return;
    }
    case "createDiffieHellman":
    case "createDiffieHellmanGroup":
    case "getDiffieHellman":
    case "diffieHellman": {
      const bits = getNumericValue(args[0]);
      findings.push(createFinding({ ...base, algorithm: "DH", family: "DH", type: "key-agreement", keySize: Number.isInteger(bits) && bits > 0 ? bits : null, risk: "medium", reason: "Quantum-vulnerable key agreement.", cwe: "CWE-327", operation: "key-agreement", api: `crypto.${methodName}` }));
      return;
    }
    case "generateKeys":
    case "computeSecret": {
       findings.push(createFinding({ ...base, algorithm: "ECDH", family: "ECDH", type: "key-agreement", keySize: null, risk: "medium", reason: "Quantum-vulnerable ECDH operation.", cwe: "CWE-327", operation: "key-agreement", api: `crypto.ECDH.${methodName}` }));
       return;
    }
    default:
      return;
  }
}

function scanFile(filePath, targetRoot) {
  let source;
  try {
    source = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    console.warn(`Could not read ${filePath}: ${error.message}`);
    return [];
  }

  const relativeFile = path.relative(targetRoot, filePath).split(path.sep).join("/");
  const extension = path.extname(filePath).toLowerCase();
  const language = [".ts", ".tsx", ".mts", ".cts"].includes(extension) ? "typescript" : "javascript";

  const findings = [];
  let ast;

  try {
    ast = parser.parse(source, {
      sourceType: "unambiguous",
      allowReturnOutsideFunction: true,
      plugins: ["typescript", "jsx", "decorators-legacy", "classProperties", "dynamicImport", "optionalChaining"],
    });
  } catch (error) {
    console.warn(`Skipping unparsable file ${relativeFile}: ${error.message}`);
    return findings;
  }

  traverse(ast, {
    NewExpression(pathRef) {
      const { node } = pathRef;
      if (node.callee.type === "MemberExpression" && node.callee.object.type === "Identifier") {
        const binding = pathRef.scope.getBinding(node.callee.object.name);
        if (isCryptoModuleBinding(binding)) {
          const methodName = getCryptoMethodName(node.callee);
          if (methodName === "X509Certificate" || methodName === "DiffieHellman") {
            findings.push(createFinding({
              file: relativeFile, line: node.loc?.start.line ?? null, language,
              algorithm: methodName, family: "CERTIFICATE", type: "certificate", keySize: null,
              risk: "unknown", reason: "X509 certificate object instantiation.", cwe: "N/A",
              operation: "certificate-handling", api: `crypto.${methodName}`,
            }));
          }
          if (methodName === "ECDH") {
            findings.push(createFinding({
              file: relativeFile, line: node.loc?.start.line ?? null, language,
              algorithm: "ECDH", family: "ECDH", type: "key-agreement", keySize: null,
              risk: "medium", reason: "Quantum-vulnerable ECDH instantiation.", cwe: "CWE-327",
              operation: "key-agreement", api: `crypto.ECDH`,
            }));
          }
        }
      }
    },
    CallExpression(pathRef) {
      const { node } = pathRef;
      const callee = node.callee;

      checkRandomNumberGeneration(callee, node, relativeFile, findings, language);

      // Web Crypto API Support
      if (
        callee.type === "MemberExpression" &&
        callee.object.type === "MemberExpression" &&
        getCryptoMethodName(callee.object) === "subtle"
      ) {
        const methodName = getCryptoMethodName(callee);
        const algorithmArg = node.arguments?.[0];
        
        let algorithm = "unknown";
        let keySize = null;

        if (algorithmArg && algorithmArg.type === "StringLiteral") {
          algorithm = algorithmArg.value;
        } else if (algorithmArg && algorithmArg.type === "ObjectExpression") {
          const nameOption = getStringOption(algorithmArg, "name");
          const lengthOption = getObjectOption(algorithmArg, "length");
          if (nameOption) algorithm = nameOption;
          if (lengthOption) keySize = lengthOption;
        }

        if (algorithm !== "unknown") {
          let info;
          let type = "cipher";
          if (methodName === "digest") {
             info = getHashInformation(algorithm);
             type = "hash";
          } else if (methodName === "deriveBits" || methodName === "deriveKey") {
             info = getPublicKeyInformation(algorithm); 
             type = "key-derivation";
          } else {
             info = getCipherInformation(algorithm);
          }
          
          findings.push(createFinding({
            ...info, file: relativeFile, line: node.loc?.start.line ?? null, language,
            type: type,
            operation: methodName,
            api: `crypto.subtle.${methodName}`,
            keySize: keySize || info.keySize
          }));
        }
        return; 
      }

      // Node.js Crypto Checks
      if (callee.type === "MemberExpression") {
        const methodName = getCryptoMethodName(callee);
        if (!methodName) return;

        if (callee.object.type === "Identifier") {
          const binding = pathRef.scope.getBinding(callee.object.name);
          if (isCryptoModuleBinding(binding)) {
            processCryptoMethod(methodName, node, relativeFile, findings, language);
          }
          return;
        }

        if (isCryptoRequire(callee.object)) {
          processCryptoMethod(methodName, node, relativeFile, findings, language);
        }
        return;
      }

      if (callee.type === "Identifier") {
        const binding = pathRef.scope.getBinding(callee.name);
        const supportedMethods = [
          "createHash", "createHmac", "createCipher", "createCipheriv", "createDecipher", "createDecipheriv",
          "generateKey", "generateKeySync", "generateKeyPair", "generateKeyPairSync", "createSign", "createVerify",
          "createDiffieHellman", "createDiffieHellmanGroup", "getDiffieHellman", "diffieHellman",
          "publicEncrypt", "privateDecrypt", "privateEncrypt", "publicDecrypt", "sign", "verify",
          "pbkdf2", "pbkdf2Sync", "scrypt", "scryptSync", "hkdf", "hkdfSync",
          "randomBytes", "randomFillSync", "randomFill", "createSecretKey", "createPublicKey", "createPrivateKey"
        ];

        if (supportedMethods.includes(callee.name) && isImportedCryptoFunctionBinding(binding, callee.name)) {
          processCryptoMethod(callee.name, node, relativeFile, findings, language);
          return;
        }

        if (binding?.path.isImportSpecifier()) {
          const imported = binding.path.node.imported;
          const importedName = imported.type === "Identifier" ? imported.name : imported.value;
          if (supportedMethods.includes(importedName) && isImportedCryptoFunctionBinding(binding, importedName)) {
            processCryptoMethod(importedName, node, relativeFile, findings, language);
          }
        } else if (binding?.path.isVariableDeclarator()) {
          const id = binding.path.node.id;
          if (id.type === "ObjectPattern") {
            const property = id.properties.find((item) => item.type === "ObjectProperty" && item.value.type === "Identifier" && item.value.name === callee.name);
            const originalName = property ? getPropertyName(property) : null;
            if (originalName && supportedMethods.includes(originalName) && isImportedCryptoFunctionBinding(binding, originalName)) {
              processCryptoMethod(originalName, node, relativeFile, findings, language);
            }
          }
        }
      }
    },
  });

  return findings;
}

function main() {
  const targetArgument = process.argv[2];
  if (!targetArgument) {
    console.error('Usage: node scanner.js "<project-directory-or-source-file>"');
    process.exitCode = 2;
    return;
  }

  const target = path.resolve(targetArgument);
  console.log("\nAST Crypto Scanner");
  console.log(`Target: ${target}`);

  const files = getSourceFiles(target);
  const targetRoot = fs.statSync(target).isDirectory() ? target : path.dirname(target);
  const allFindings = [];

  for (const file of files) {
    allFindings.push(...scanFile(file, targetRoot));
  }

  // FIX: Delete old findings before writing new ones to avoid appending
  const outputPath = path.join(__dirname, "findings.json");
  if (fs.existsSync(outputPath)) {
    fs.unlinkSync(outputPath);
  }

  fs.writeFileSync(outputPath, JSON.stringify(allFindings, null, 2), "utf8");

  console.log(`Files scanned: ${files.length}`);
  console.log(`Crypto findings: ${allFindings.length}`);
  console.log(`Output: ${outputPath}`);

  if (files.length === 0) {
    console.warn("No supported JavaScript/TypeScript source files were found.");
  }
}

try {
  main();
} catch (error) {
  console.error(`Scanner failed: ${error.message}`);
  process.exitCode = 1;
}