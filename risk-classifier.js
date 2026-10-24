"use strict";

/**
 * Risk classifier for CBOM findings.
 * Input : one scanner finding {algorithm, type, api, language, keySize, mode, operation}
 * Output: risk level, quantum status, resolved key size / mode, reasons, fixes.
 */

const LEVELS = ["safe", "unknown", "low", "medium", "high", "critical"];
const rank = (level) => LEVELS.indexOf(level);
const worst = (a, b) => (rank(b) > rank(a) ? b : a);

const SYMMETRIC_BLOCK = /^(AES|DES|DESEDE|3DES|TRIPLEDES|BLOWFISH|RC2|CAMELLIA|ARIA)/;

function analyse(finding) {
    const raw = String(finding.algorithm || "").trim();
    const A = raw.toUpperCase();
    const api = String(finding.api || "");
    const lang = String(finding.language || "").toLowerCase();
    const type = String(finding.type || "").toLowerCase();
    const parts = A.split("/");
    const base = parts[0];

    const out = {
        risk: "safe",
        quantum: "not-applicable", // vulnerable | weakened | resistant | unknown
        quantumSecurityLevel: null,
        keySize: null,
        sizeSource: null,
        mode: null,
        implicitMode: false,
        reasons: [],
        fixes: [],
    };

    const add = (risk, reason, fix) => {
        out.risk = worst(out.risk, risk);
        if (reason) out.reasons.push(reason);
        if (fix && !out.fixes.includes(fix)) out.fixes.push(fix);
    };

    const isHash =
        type === "hash" ||
        api === "MessageDigest" ||
        api.toLowerCase().endsWith("createhash");

    // ---------------- mode ----------------
    if (finding.mode && !/^(UNSPECIFIED|NONE|NULL)$/i.test(String(finding.mode))) {
        out.mode = String(finding.mode).toUpperCase();
    }
    if (!out.mode && parts[1]) out.mode = parts[1];
    if (!out.mode) {
        const m = A.match(/(?:^|[-_])(GCM|CBC|CTR|CCM|ECB|CFB|OFB|XTS)(?:$|[-_])/);
        if (m) out.mode = m[1];
    }
    // JCA: Cipher.getInstance("AES") silently means AES/ECB/PKCS5Padding
    if (
        !out.mode && lang === "java" && api === "Cipher" &&
        parts.length === 1 && /^(AES|DES|DESEDE|BLOWFISH|RC2)$/.test(base)
    ) {
        out.mode = "ECB";
        out.implicitMode = true;
    }

    // ---------------- key size ----------------
    if (!isHash) {
        let m = A.match(/(?:AES|RSA|DSA|DH)[-_]?(\d{3,4})\b/);
        if (!m && /ECDSA|ECDH|^EC\b|ECDSA|SECP|P-?\d{3}/.test(A)) {
            m = A.match(/(?:SECP|P-?|PRIME)(256|384|521)/);
        }
        if (m) {
            out.keySize = Number(m[1]);
            out.sizeSource = "algorithm-name";
        } else {
            const k = Number.parseInt(finding.keySize, 10);
            // The Java scanner used to hardcode AES=256; only trust it when resolved.
            const guessed =
                lang === "java" && ["Cipher", "KeyGenerator"].includes(api) &&
                !finding.keySizeResolved;
            if (k > 0 && !guessed) {
                out.keySize = k;
                out.sizeSource = "scanner";
            }
        }
    }

    const hashIn = (s) => {
        if (/MD[245]/.test(s)) return "critical";
        if (/SHA-?1(?!\d)/.test(s)) return "high";
        return null;
    };

    // ---------------- algorithm rules ----------------
    if (/WITH(RSA|ECDSA|DSA)$/.test(A) || /^(RSA|ECDSA)-(SHA|MD)/.test(A)) {
        // signature schemes: SHA256withRSA, RSA-SHA256 ...
        out.quantum = "vulnerable"; out.quantumSecurityLevel = 0;
        add("medium", "Public-key signature: breakable by Shor's algorithm.",
            "Plan migration to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).");
        const h = hashIn(A);
        if (h) add(h, "Signature uses a broken/deprecated hash.", "Use SHA-256 or stronger.");
    } else if (/HMAC/.test(A)) {
        out.quantum = "resistant";
        if (/MD5/.test(A)) add("medium", "HMAC-MD5 is deprecated.", "Use HMAC-SHA-256.");
        else if (/SHA-?1(?!\d)/.test(A)) add("low", "HMAC-SHA1 is deprecated.", "Use HMAC-SHA-256.");
    } else if (/ML-?KEM|KYBER|ML-?DSA|DILITHIUM|SLH-?DSA|SPHINCS|FALCON/.test(A)) {
        out.quantum = "resistant"; out.quantumSecurityLevel = 3;
    } else if (/^MD[245]\b|^MD[245]$/.test(A)) {
        add("critical", `${base} is cryptographically broken (practical collisions).`,
            "Replace with SHA-256 / SHA-3.");
        out.quantum = "weakened";
    } else if (/^SHA-?1$/.test(A) || A === "SHA") {
        add("high", "SHA-1 is broken for collision resistance (SHAttered).",
            "Replace with SHA-256 / SHA-3.");
        out.quantum = "weakened";
    } else if (/^SHA-?(224|256|384|512)|^SHA3|^BLAKE|^SHAKE/.test(A)) {
        out.quantum = "resistant";
        if (/256/.test(A)) out.quantumSecurityLevel = 2;
        else if (/384/.test(A)) out.quantumSecurityLevel = 4;
    } else if (/^(DESEDE|3DES|TRIPLEDES|TDEA)/.test(A)) {
        add("high", "3DES is deprecated by NIST (Sweet32, 64-bit block).", "Use AES-256-GCM.");
        out.quantum = "weakened";
    } else if (/^DES(\b|\/|$)/.test(A)) {
        add("critical", "DES has a 56-bit key and is trivially brute-forced.", "Use AES-256-GCM.");
        out.quantum = "weakened";
    } else if (/^(RC4|ARCFOUR)/.test(A)) {
        add("critical", "RC4 is broken (biased keystream).", "Use AES-GCM or ChaCha20-Poly1305.");
    } else if (/^RC2/.test(A)) {
        add("high", "RC2 is obsolete and weak.", "Use AES-256-GCM.");
    } else if (/^BLOWFISH/.test(A)) {
        add("medium", "Blowfish has a 64-bit block (Sweet32).", "Use AES-256-GCM.");
    } else if (/^AES/.test(A)) {
        const ks = out.keySize;
        if (ks === 128) {
            out.quantum = "weakened"; out.quantumSecurityLevel = 1;
            add("low", "AES-128 gives ~64-bit security against Grover's algorithm.", "Prefer AES-256.");
        } else if (ks === 192) {
            out.quantum = "resistant"; out.quantumSecurityLevel = 3;
        } else if (ks === 256) {
            out.quantum = "resistant"; out.quantumSecurityLevel = 5;
        } else {
            out.quantum = "unknown";
            add("low", "AES key size could not be resolved statically.", "Verify key length is 256 bits.");
        }
    } else if (/^CHACHA20/.test(A)) {
        out.quantum = "resistant";
    } else if (/^RSA/.test(A)) {
        out.quantum = "vulnerable"; out.quantumSecurityLevel = 0;
        add("medium",
            "RSA is breakable by Shor's algorithm (harvest-now-decrypt-later risk if used for encryption/key exchange).",
            "Plan migration to ML-KEM (FIPS 203) / ML-DSA (FIPS 204).");
        if (out.keySize && out.keySize < 1024) add("critical", `RSA-${out.keySize} is trivially factorable.`, "Use RSA-3072+ now.");
        else if (out.keySize && out.keySize < 2048) add("high", `RSA-${out.keySize} is below the NIST 2048-bit minimum.`, "Use RSA-3072+.");
        if (/PKCS1PADDING/.test(A)) add("medium", "PKCS#1 v1.5 padding is vulnerable to Bleichenbacher attacks.", "Use OAEP.");
    } else if (/^(ECDH|X25519|X448|DH|DIFFIE)/.test(A) || api === "KeyAgreement") {
        out.quantum = "vulnerable"; out.quantumSecurityLevel = 0;
        add("high", "Key agreement is breakable by Shor's algorithm (harvest-now-decrypt-later).",
            "Move to hybrid or ML-KEM key establishment.");
    } else if (/^(ECDSA|EC$|ED25519|ED448|EDDSA)/.test(A)) {
        out.quantum = "vulnerable"; out.quantumSecurityLevel = 0;
        add("medium", "Elliptic-curve signatures are breakable by Shor's algorithm.",
            "Plan migration to ML-DSA (FIPS 204).");
    } else if (/^DSA/.test(A)) {
        out.quantum = "vulnerable"; out.quantumSecurityLevel = 0;
        add("high", "DSA is deprecated and quantum-vulnerable.", "Use ECDSA now, ML-DSA later.");
    } else if (/PBKDF2|SCRYPT|ARGON2|BCRYPT|HKDF/.test(A)) {
        out.quantum = "resistant";
    } else {
        out.quantum = "unknown";
        add("unknown", "Algorithm not recognised by the classifier.");
    }

    // ---------------- mode rules (symmetric block ciphers only) ----------------
    if (SYMMETRIC_BLOCK.test(A) && !/WITH/.test(A)) {
        if (out.mode === "ECB") {
            add("high",
                out.implicitMode
                    ? "Cipher.getInstance(\"" + raw + "\") defaults to ECB, which leaks plaintext patterns."
                    : "ECB mode leaks plaintext patterns.",
                "Use AES/GCM/NoPadding with a unique IV.");
        } else if (out.mode === "CBC") {
            add("low", "CBC provides no integrity (padding-oracle risk).", "Use AES-GCM, or add HMAC.");
        } else if (!out.mode && /^AES/.test(A)) {
            add("low", "Cipher mode could not be resolved.", "Verify an authenticated mode (GCM) is used.");
        }
    }

    out.recommendation = out.fixes.join(" ");
    return out;
}

module.exports = { analyse, rank, worst, LEVELS };
