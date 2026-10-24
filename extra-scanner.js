"use strict";
/** Scans certs/keys, dependency manifests, config files (TLS/SSH), Go and C/C++ (regex-based).
 *  Usage: node extra-scanner.js <project-dir>   ->  extra-report.json */
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const { analyse } = require("./risk-classifier");
const root = path.resolve(process.argv[2] || ".");
if (!fs.existsSync(root)) { console.error("Target not found: " + root); process.exit(2); }
const SKIP = new Set(["node_modules", ".git", "target", "build", "dist", "venv", ".venv", "__pycache__", "vendor"]);
const items = [];
const lineOf = (t, i) => t.slice(0, i).split("\n").length;
const add = (category, algorithm, risk, reason, file, line, o = {}) => items.push({
  category, algorithm, risk, quantum: o.quantum || "not-applicable", keySize: o.keySize || null, mode: o.mode || null,
  languages: o.language ? [o.language] : [], reasons: reason ? [reason] : [], recommendation: o.fix || "",
  occurrences: [{ file, line, language: o.language || null }],
});
function addCode(f, file, line, language, category = "code") {
  const a = analyse({ ...f, language, api: "", type: "" });
  items.push({ category, algorithm: f.algorithm, risk: a.risk, quantum: a.quantum, keySize: a.keySize || f.keySize || null,
    mode: a.mode || f.mode || null, languages: [language], reasons: a.reasons, recommendation: a.fixes.join(" "),
    occurrences: [{ file, line, language }] });
}
function* walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = path.join(d, e.name);
    if (e.isDirectory()) yield* walk(p); else yield p;
  }
}
const LIBS = { pycrypto: ["high", "PyCrypto is unmaintained and has known CVEs", "Use pycryptodome or cryptography."],
  "crypto-js": ["low", "crypto-js is no longer maintained", "Use Node crypto or WebCrypto."],
  md5: ["medium", "md5 package implements a broken hash", "Use SHA-256."], sha1: ["medium", "sha1 package implements a deprecated hash", "Use SHA-256."],
  jasypt: ["low", "Jasypt defaults to weak legacy algorithms unless configured", "Configure AES-256-GCM / PBKDF2."],
  "node-forge": ["safe"], bcrypt: ["safe"], jsonwebtoken: ["safe"], pycryptodome: ["safe"], cryptography: ["safe"],
  pyopenssl: ["safe"], passlib: ["safe"], "commons-codec": ["safe"], bcprov: ["safe"] };
const lib = (n) => LIBS[n] || (n.includes("bcprov") ? LIBS.bcprov : null);
const RULES = [
  [/crypto\/md5|EVP_md5|MD5_Init|\bMD5\s*\(/, "MD5"], [/crypto\/sha1|EVP_sha1|SHA1_Init|\bSHA1\s*\(/, "SHA-1"],
  [/crypto\/des|EVP_des_|DES_set_key|DES_ecb/, "DES"], [/crypto\/rc4|EVP_rc4|RC4_set_key/, "RC4"],
  [/rsa\.GenerateKey\(\s*[^,]+,\s*(\d+)|RSA_generate_key(?:_ex)?\(\s*[^,]*,\s*(\d+)/, "RSA", (m) => ({ keySize: +(m[1] || m[2]) })],
  [/EVP_aes_(128|192|256)_(ecb|cbc|ctr|gcm|ccm)/, "AES", (m) => ({ keySize: +m[1], mode: m[2].toUpperCase() })],
  [/aes\.NewCipher/, "AES"], [/ecdsa\.GenerateKey|EC_KEY_new_by_curve_name/, "ECDSA"], [/ed25519\.GenerateKey/, "Ed25519"],
  [/crypto\/sha256|sha256\.(?:New|Sum256)|EVP_sha256/, "SHA-256"],
];
const CONF_EXT = new Set([".conf", ".cnf", ".cfg", ".ini", ".properties", ".yml", ".yaml"]);
let scanned = 0;

for (const abs of walk(root)) {
  const file = path.relative(root, abs).replace(/\\/g, "/"), name = path.basename(abs).toLowerCase(), ext = path.extname(name);
  const readable = fs.statSync(abs).size < 2e6;
  const text = () => fs.readFileSync(abs, "utf8");
  try {
    if ([".jks", ".p12", ".pfx", ".keystore"].includes(ext)) {
      add("key-material", "Keystore file", "high", "Keystore committed to the repository", file, 1, { fix: "Remove from source control; load from a secret store." });
      scanned++;
    } else if ([".pem", ".crt", ".cer", ".key"].includes(ext) && readable) {
      const t = text(); scanned++;
      for (const m of t.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g)) {
        const line = lineOf(t, m.index);
        if (m[1].includes("PRIVATE KEY")) add("key-material", "Private key", "critical", "Private key committed to the repository", file, line, { fix: "Remove, rotate the key, and use a secret store." });
        else if (m[1] === "CERTIFICATE") {
          const c = new crypto.X509Certificate(m[0]), k = c.publicKey, ty = k.asymmetricKeyType;
          const algorithm = ty === "rsa" ? "RSA" : ty === "ec" ? "ECDSA" : String(ty).replace(/^./, (x) => x.toUpperCase());
          const size = k.asymmetricKeyDetails && k.asymmetricKeyDetails.modulusLength;
          addCode({ algorithm, keySize: size }, file, line, "Certificate", "certificate");
          const it = items[items.length - 1];
          it.reasons.unshift(`Certificate for ${c.subject.replace(/\n/g, ", ")}, valid until ${c.validTo}.`);
          if (new Date(c.validTo) < new Date()) { it.reasons.push("Certificate has expired."); if (it.risk === "safe" || it.risk === "low") it.risk = "medium"; }
        }
      }
    } else if (name === "package.json" && readable) {
      const t = text(), j = JSON.parse(t); scanned++;
      for (const n of Object.keys({ ...j.dependencies, ...j.devDependencies })) {
        const L = lib(n.toLowerCase()); if (L) add("dependency", n, L[0], L[1], file, lineOf(t, t.indexOf(`"${n}"`)), { fix: L[2], language: "JavaScript" });
      }
    } else if (/^requirements.*\.txt$/.test(name) && readable) {
      const t = text(); scanned++;
      t.split(/\r?\n/).forEach((ln, i) => { const m = ln.match(/^\s*([A-Za-z0-9_.-]+)/), L = m && lib(m[1].toLowerCase());
        if (L) add("dependency", m[1], L[0], L[1], file, i + 1, { fix: L[2], language: "Python" }); });
    } else if (name === "pom.xml" && readable) {
      const t = text(); scanned++;
      for (const m of t.matchAll(/<artifactId>([^<]+)<\/artifactId>/g)) {
        const L = lib(m[1].toLowerCase()); if (L) add("dependency", m[1], L[0], L[1], file, lineOf(t, m.index), { fix: L[2], language: "Java" });
      }
    } else if ((CONF_EXT.has(ext) || /^(sshd|ssh)_config$/.test(name)) && readable) {
      scanned++;
      text().split(/\r?\n/).forEach((ln, i) => {
        if (/^\s*#/.test(ln)) return;
        const at = (n, r, why, fix) => add("config", n, r, why, file, i + 1, { fix });
        if (/^\s*Protocol\s+1\b/i.test(ln)) at("SSH protocol 1", "critical", "SSH protocol 1 is broken", "Use protocol 2 only.");
        if (/\b(SSLv2|SSLv3)\b/i.test(ln)) at("SSLv2/SSLv3", "critical", "SSLv2/v3 enabled (broken, e.g. POODLE)", "Allow TLS 1.2+ only.");
        else if (/ssl|tls|protocol/i.test(ln) && /TLSv?1(\.[01])?(?![.\d])/i.test(ln)) at("TLS 1.0/1.1", "high", "TLS 1.0/1.1 enabled (deprecated by RFC 8996)", "Allow TLS 1.2 and 1.3 only.");
        if (/cipher|mac/i.test(ln)) {
          const w = ln.replace(/[!-]\s*[A-Za-z0-9_]+/g, "").match(/\b(RC4|ARCFOUR|3DES|DES|MD5|EXPORT|NULL)\b/i);
          if (w) at(`Weak cipher/MAC: ${w[1].toUpperCase()}`, "high", `${w[1].toUpperCase()} allowed in cipher/MAC list`, "Remove it; prefer AES-GCM / ChaCha20-Poly1305.");
          else if (/hmac-sha1/i.test(ln)) at("hmac-sha1", "medium", "HMAC-SHA1 MAC allowed", "Prefer hmac-sha2-256/512 or AEAD ciphers.");
        }
      });
    } else if ([".go", ".c", ".cc", ".cpp", ".h", ".hpp"].includes(ext) && readable) {
      scanned++;
      const lang = ext === ".go" ? "Go" : "C/C++";
      text().split(/\r?\n/).forEach((ln, i) => { if (/^\s*(\/\/|\*|\/\*)/.test(ln)) return;
        for (const [re, algorithm, fn] of RULES) { const m = ln.match(re); if (m) addCode({ algorithm, ...(fn ? fn(m) : {}) }, file, i + 1, lang); } });
    }
  } catch (e) { console.error(`Skipped ${file}: ${e.message}`); }
}

const by = {}; items.forEach((i) => (by[i.risk] = (by[i.risk] || 0) + 1));
fs.writeFileSync(path.join(__dirname, "extra-report.json"), JSON.stringify({ generatedAt: new Date().toISOString(), summary: { files: scanned, byRisk: by }, items }, null, 2));
console.log(`\nExtra scan: ${scanned} files, ${items.length} items`, JSON.stringify(by));
