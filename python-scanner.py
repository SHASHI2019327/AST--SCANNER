#!/usr/bin/env python3
"""AST-based Python cryptographic API inventory and risk scanner.

Scans executable Python syntax (not comments or string contents), resolves common
import aliases, and emits the occurrence-based JSON shape used by AST-SCANNER.
This is a static-analysis tool: dynamic dispatch, reflection, native extensions,
and arbitrary data flow can prevent complete detection.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
from typing import Any

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "target", "build",
    "dist", ".venv", "venv", "__pycache__", ".next", "coverage", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
}

SAFE_HASHES = {
    "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
    "sha512": "SHA-512", "sha3_224": "SHA3-224", "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384", "sha3_512": "SHA3-512",
    "shake_128": "SHAKE-128", "shake_256": "SHAKE-256", "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
}

WEAK_HASHES = {
    "md5": ("MD5", "critical", "weakened",
            "MD5 is cryptographically broken for collision-resistant uses.",
            "Replace with SHA-256 or SHA-3 where a cryptographic hash is required."),
    "sha1": ("SHA-1", "high", "weakened",
             "SHA-1 is deprecated for collision-sensitive uses.",
             "Replace with SHA-256 or SHA-3 where compatible."),
}
HASH_NAMES = {**{k: (v, "safe", "unknown", f"{v} use detected.",
                     "Review protocol requirements and keep dependencies updated.")
                 for k, v in SAFE_HASHES.items()}, **WEAK_HASHES}

def dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))

def literal(node: ast.AST | None) -> Any:
    try:
        return ast.literal_eval(node) if node is not None else None
    except (ValueError, TypeError, SyntaxError):
        return None

class ImportResolver(ast.NodeVisitor):
    def __init__(self) -> None:
        self.modules: dict[str, str] = {}
        self.symbols: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".")[0]
            self.modules[bound] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name != "*":
                self.symbols[alias.asname or alias.name] = f"{module}.{alias.name}"

    def canonical(self, node: ast.AST) -> str:
        raw = dotted(node)
        if not raw:
            return ""
        first, dot, rest = raw.partition(".")
        if first in self.symbols:
            return self.symbols[first] + (("." + rest) if dot else "")
        if first in self.modules:
            return self.modules[first] + (("." + rest) if dot else "")
        return raw

def make_finding(algorithm: str, risk: str, quantum: str, reason: str,
                 recommendation: str, file_path: str, line: int, api: str,
                 key_size: int | None = None, mode: str | None = None,
                 category: str = "code") -> dict[str, Any]:
    return {
        "algorithm": algorithm, "category": category, "risk": risk,
        "quantum": quantum, "keySize": key_size, "mode": mode,
        "languages": ["Python"], "reasons": [reason],
        "recommendation": recommendation,
        "occurrences": [{"file": file_path.replace("\\", "/"), "line": line,
                         "language": "Python", "api": api}],
    }

class CryptoVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, resolver: ImportResolver) -> None:
        self.file_path = file_path
        self.resolver = resolver
        self.items: list[dict[str, Any]] = []
        self.key_sizes: dict[str, int] = {}
        self.cipher_modes: dict[str, str] = {}
        self.hash_objects: dict[str, str] = {}

    def add(self, algorithm: str, risk: str, quantum: str, reason: str,
            recommendation: str, node: ast.AST, api: str,
            key_size: int | None = None, mode: str | None = None, 
            category: str = "code") -> None:  # <--- FIXED HERE
        self.items.append(make_finding(
            algorithm, risk, quantum, reason, recommendation, self.file_path,
            getattr(node, "lineno", 1), api, key_size, mode, category))

    def _key_size(self, node: ast.AST | None) -> int | None:
        if isinstance(node, ast.Name):
            return self.key_sizes.get(node.id)
        if isinstance(node, ast.Call):
            name = self.resolver.canonical(node.func).lower()
            tail = name.rsplit(".", 1)[-1]
            if tail in {"token_bytes", "urandom", "get_random_bytes"} and node.args:
                n = literal(node.args[0])
                return n * 8 if isinstance(n, int) and n > 0 else None
            if tail in {"generate_key", "generate_key_bytes"}:
                for kw in node.keywords:
                    if kw.arg in {"bit_length", "key_size", "length"}:
                        n = literal(kw.value)
                        if isinstance(n, int):
                            return n if n > 64 else n * 8
        val = literal(node)
        if isinstance(val, (bytes, bytearray)):
            return len(val) * 8
        if isinstance(val, str):
            return len(val.encode()) * 8
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        val = node.value
        size = self._key_size(val)
        for target in node.targets:
            if isinstance(target, ast.Name) and size:
                self.key_sizes[target.id] = size
            if isinstance(target, ast.Name) and isinstance(val, ast.Call):
                api = self.resolver.canonical(val.func).lower()
                if api.endswith("cipher") and len(val.args) > 1:
                    mode = self.resolver.canonical(val.args[1]).rsplit(".", 1)[-1].upper()
                    if mode in {"GCM", "CBC", "CTR", "CFB", "OFB", "XTS", "CCM", "ECB"}:
                        self.cipher_modes[target.id] = mode
                if api.endswith(("sha256", "sha384", "sha512", "md5", "sha1", "sha3_256", "sha3_512")):
                    self.hash_objects[target.id] = api.rsplit(".", 1)[-1]
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolver.canonical(node.func)
        low = name.lower()
        short = low.rsplit(".", 1)[-1]
        
        # --- Insecure Randomness (random module) ---
        if low.startswith("random.") or short in {"random", "randint", "randrange", "choice", "choices", "shuffle", "sample"}:
            self.add("random", "high", "unknown", 
                     "Python's random module is not cryptographically secure.",
                     "Use secrets.token_bytes() or os.urandom() instead.",
                     node, name, category="PRNG")

        # --- Secure Randomness (secrets module) ---
        if low.startswith("secrets.") or low.startswith("os.urandom"):
            self.add("secrets", "safe", "unknown",
                     "Secure cryptographic randomness detected.",
                     "Ensure proper key length.",
                     node, name, category="PRNG")

        # hashlib and common hash constructor aliases.
        if (low.startswith("hashlib.") or name in self.resolver.symbols.values()
                or low in {"md5", "sha1", "sha256", "sha384", "sha512"}):
            hash_name = short.replace("-", "_")
            if hash_name in HASH_NAMES:
                alg, risk, quantum, reason, fix = HASH_NAMES[hash_name]
                self.add(alg, risk, quantum, reason, fix, node, name, category="Hash")
            elif short == "new" and node.args:
                value = literal(node.args[0])
                if isinstance(value, str):
                    key = value.lower().replace("-", "_")
                    if key in HASH_NAMES:
                        alg, risk, quantum, reason, fix = HASH_NAMES[key]
                        self.add(alg, risk, quantum, reason, fix, node, name, category="Hash")
                    else:
                        self.add(value.upper(), "unknown", "unknown",
                                 "Hash algorithm name is not in the scanner's classification table.",
                                 "Confirm the algorithm and classify it against your security policy.",
                                 node, name, category="Hash")

        # HMAC construction; infer digest from positional or keyword argument.
        if short in {"new", "digest"} and ("hmac" in low or name in self.resolver.symbols.values()):
            digest = next((k.value for k in node.keywords if k.arg == "digestmod"), None)
            if digest is None and len(node.args) >= 3 and short == "new":
                digest = node.args[2]
            dname = self.resolver.canonical(digest) if isinstance(digest, (ast.Name, ast.Attribute)) else literal(digest)
            if isinstance(dname, str):
                tail = dname.rsplit(".", 1)[-1].lower().replace("-", "_")
                if tail in HASH_NAMES:
                    alg, risk, quantum, reason, fix = HASH_NAMES[tail]
                    self.add("HMAC-" + alg, risk, quantum, "HMAC uses " + alg + ". " + reason,
                             fix, node, name, category="MAC")
                else:
                    self.add("HMAC (digest unknown)", "unknown", "unknown",
                             "HMAC use detected, but the digest could not be resolved.",
                             "Use a modern approved digest and verify protocol requirements.", node, name, category="MAC")

        # AESGCM and ChaCha20Poly1305 high-level AEAD APIs.
        if short in {"aesgcm", "aessiv", "aesocb3"} and "cryptography" in low:
            ks = self._key_size(node.args[0]) if node.args else None
            label = f"AES-{ks}-GCM" if short == "aesgcm" and ks else ("AES-GCM" if short == "aesgcm" else short.upper())
            self.add(label, "safe", "unknown",
                     "Authenticated-encryption API construction detected.",
                     "Use unique nonces where required, protect keys, and validate authentication failures.",
                     node, name, ks, "GCM" if short == "aesgcm" else None, category="Cipher")
        if short in {"chacha20poly1305", "xchacha20poly1305"} and (
            "cryptography" in low or "nacl" in low or "crypto" in low):
            ks = self._key_size(node.args[0]) if node.args else None
            self.add("XChaCha20-Poly1305" if "xchacha" in short else "ChaCha20-Poly1305",
                     "safe", "unknown", "Authenticated ChaCha20-Poly1305 API construction detected.",
                     "Use unique nonces and protect keys.", node, name, ks, "Poly1305", category="Cipher")

        # Low-level cipher algorithms and modes across cryptography / PyCryptodome.
        if short in {"aes", "triple_des", "des", "chacha20", "blowfish", "cast5", "idea", "arc2"} and (
            "cryptography" in low or "crypto.cipher" in low or "cryptodome.cipher" in low):
            ks = self._key_size(node.args[0]) if node.args else None
            if short == "aes":
                self.add("AES", "safe", "unknown", "AES cipher construction detected.",
                         "Prefer authenticated encryption (for example GCM) and manage keys securely.",
                         node, name, ks, category="Cipher")
            elif short in {"triple_des", "des", "blowfish", "cast5", "idea", "arc2"}:
                label = {"triple_des": "3DES", "des": "DES"}.get(short, short.upper())
                self.add(label, "high", "unknown", f"{label} is a legacy cipher and should be reviewed or retired.",
                         "Migrate to an approved modern authenticated cipher.", node, name, ks, category="Cipher")
            else:
                self.add("ChaCha20", "safe", "unknown", "ChaCha20 cipher construction detected.",
                         "Prefer an authenticated construction such as ChaCha20-Poly1305.",
                         node, name, ks, category="Cipher")

        if short in {"cipher", "new"} and (
            ("cryptography" in low and short == "cipher") or
            ("crypto.cipher" in low or "cryptodome.cipher" in low)):
            mode = None
            if short == "cipher" and len(node.args) > 1:
                mode = self.resolver.canonical(node.args[1]).rsplit(".", 1)[-1].upper()
            elif short == "new":
                if len(node.args) > 1:
                    mode = self.resolver.canonical(node.args[1]).rsplit(".", 1)[-1].upper()
                for kw in node.keywords:
                    if kw.arg == "mode":
                        mode = str(literal(kw.value)).upper()
            mode = mode.removeprefix("MODE_") if mode else None
            cipher_alg = next((a for a in ("AES", "DES", "3DES", "DES3", "Blowfish", "CAST", "ARC2")
                               if f".{a.lower()}.new" in low or f".{a.lower()}." in low), None)
            if cipher_alg in {"DES", "3DES", "DES3", "Blowfish", "CAST", "ARC2"}:
                self.add("3DES" if cipher_alg in {"3DES", "DES3"} else cipher_alg,
                         "high", "unknown", f"{cipher_alg} is a legacy cipher and should be reviewed or retired.",
                         "Migrate to an approved modern authenticated cipher.", node, name, mode=mode, category="Cipher")
            elif cipher_alg == "AES":
                self.add("AES", "safe", "unknown", "AES cipher construction detected.",
                         "Prefer authenticated encryption and verify mode, nonce/IV, and authentication handling.",
                         node, name, mode=mode, category="Cipher")
            if mode == "ECB":
                self.add("Cipher", "high", "unknown", "ECB mode does not provide semantic security for repeated blocks.",
                         "Use authenticated encryption such as AES-GCM where supported.", node, name, mode="ECB", category="Cipher")
            elif mode in {"CBC", "CTR", "CFB", "OFB", "XTS", "GCM", "CCM", "EAX", "SIV"}:
                self.add("Cipher", "safe" if mode in {"GCM", "CCM", "EAX", "SIV"} else "unknown",
                         "unknown", f"Cipher mode {mode} detected; mode safety depends on construction and use.",
                         "Prefer authenticated encryption and verify IV/nonce handling and authentication checks.",
                         node, name, mode=mode, category="Cipher")

        # RSA, DSA, EC and modern curve key generation / signatures.
        if short in {"generate_private_key", "generate_key", "generate", "generate_private_key_and_certificate"}:
            if any(x in low for x in ("rsa", "ec.", "ellipticcurve", "dsa", "ed25519", "ed448", "x25519", "x448")):
                ks = next((literal(k.value) for k in node.keywords if k.arg in {"key_size", "bits"}), None)
                if "rsa" in low:
                    self.add("RSA", "high", "vulnerable",
                             f"RSA key generation detected{f' ({ks} bits)' if isinstance(ks, int) else ''}; RSA is vulnerable to a sufficiently capable quantum computer.",
                             "Inventory RSA and plan migration to a standardized post-quantum scheme.", node, name, ks if isinstance(ks, int) else None, category="Public Key")
                elif "dsa" in low:
                    self.add("DSA", "high", "vulnerable", "DSA is vulnerable to a sufficiently capable quantum computer.",
                             "Plan migration to standardized post-quantum signatures.", node, name, ks if isinstance(ks, int) else None, category="Public Key")
                elif "ec" in low or "ellipticcurve" in low:
                    self.add("ECC", "high", "vulnerable", "Elliptic-curve cryptography is vulnerable to a sufficiently capable quantum computer.",
                             "Inventory ECDSA/ECDH and plan post-quantum migration.", node, name, ks if isinstance(ks, int) else None, category="Public Key")
                else:
                    alg = next((x for x in ("Ed25519", "Ed448", "X25519", "X448") if x.lower() in low), "Modern curve")
                    self.add(alg, "high", "vulnerable", f"{alg} is not quantum-resistant against a sufficiently capable quantum computer.",
                             "Plan migration to standardized post-quantum cryptography where applicable.", node, name, category="Public Key")

        # PyCryptodome RSA.generate(bits) and common key factory / signing APIs.
        if low.endswith(("rsa.generate", "rsa.generate_private_key")):
            bits = literal(node.args[0]) if node.args else None
            if not isinstance(bits, int):
                bits = next((literal(k.value) for k in node.keywords if k.arg in {"bits", "key_size"}), None)
            self.add("RSA", "high", "vulnerable", "RSA key generation detected; RSA is vulnerable to a sufficiently capable quantum computer.",
                     "Plan migration to a standardized post-quantum scheme.", node, name, bits if isinstance(bits, int) else None, category="Public Key")

        # TLS / SSL API use is inventoried, but settings cannot be proven safe statically.
        if short in {"sslcontext", "create_default_context", "wrap_socket", "wrap_bio"} and (
            "ssl" in low or "ssl" in name.lower()):
            self.add("TLS/SSL", "unknown", "unknown", "TLS/SSL context or transport API detected; effective protocol and certificate validation require review.",
                     "Use verified default contexts, modern TLS versions, and certificate validation.", node, name, category="TLS")

        # Password/KDF and key derivation APIs.
        if short in {"pbkdf2_hmac", "scrypt", "hkdf", "pbkdf2", "argon2id", "bcrypt", "kdf"}:
            label = {"pbkdf2_hmac": "PBKDF2", "scrypt": "scrypt", "hkdf": "HKDF",
                     "pbkdf2": "PBKDF2", "argon2id": "Argon2id", "bcrypt": "bcrypt"}.get(short, "Key derivation")
            self.add(label, "safe", "unknown", f"{label} / key-derivation API detected.",
                     "Review work factors, salts, parameters, and password-storage requirements.", node, name, category="KDF")

        # Fernet, token and secret-key construction.
        if short == "fernet" and "cryptography" in low:
            self.add("Fernet (AES/HMAC)", "safe", "unknown", "Fernet symmetric authenticated-encryption API detected.",
                     "Protect keys and follow key-rotation and token-expiry requirements.", node, name, category="Cipher")
        if short in {"load_pem_private_key", "load_der_private_key", "load_pem_public_key",
                     "load_der_public_key", "load_pkcs12", "serialize_key_and_certificates"}:
            self.add("Key/Certificate", "unknown", "unknown", "Cryptographic key or certificate serialization/loading API detected.",
                     "Review key protection, algorithms, key sizes, and certificate validation.", node, name, category="Key Management")

        self.generic_visit(node)

def scan_file(path: Path, root: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        return [], f"{path}: {exc}"
    resolver = ImportResolver()
    resolver.visit(tree)
    visitor = CryptoVisitor(path.relative_to(root).as_posix(), resolver)
    visitor.visit(tree)
    return visitor.items, None

def main() -> int:
    parser = argparse.ArgumentParser(description="AST-based Python cryptography inventory and risk scanner")
    parser.add_argument("target", help="Project directory to scan")
    parser.add_argument("--output", default=None, help="Output JSON path (default: beside this script)")
    parser.add_argument("--strict-parse", action="store_true", help="Return exit code 2 if any Python file has a parse/read error")
    args = parser.parse_args()
    root = Path(args.target).expanduser().resolve()
    if not root.is_dir():
        parser.error(f"target path is not a directory: {root}")

    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    scanned = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for filename in sorted(files):
            if not filename.endswith(".py"):
                continue
            scanned += 1
            items, error = scan_file(Path(current) / filename, root)
            findings.extend(items)
            if error:
                errors.append(error)

    seen: set[tuple[Any, ...]] = set()
    unique: list[dict[str, Any]] = []
    for item in findings:
        occ = item["occurrences"][0]
        key = (item["algorithm"], occ["file"], occ["line"], occ["api"], item["mode"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    output = Path(args.output).expanduser().resolve() if args.output else Path(__file__).resolve().with_name("python-findings.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    
    # FIX: Delete old findings before writing new ones
    if output.exists():
        output.unlink()
        
    output.write_text(json.dumps(unique, indent=2), encoding="utf-8")
    
    print(f"Python AST scan complete. Files scanned: {scanned}; findings: {len(unique)}; parse errors: {len(errors)}")
    print(f"Output: {output}")
    if errors:
        print("WARNING: one or more files could not be parsed/read.")
        return 2 if args.strict_parse else 0
    return 0

if __name__ == "__main__":
    raise SystemExit(main())