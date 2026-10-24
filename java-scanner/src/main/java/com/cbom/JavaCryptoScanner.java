package com.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

public class JavaCryptoScanner {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final Set<String> IGNORED_DIRS = Set.of(
        ".git", ".github", ".idea", "target", "build",
        "out", "node_modules", "vendor"
    );

    private static final Set<String> CRYPTO_APIS = Set.of(
        "MessageDigest", "Mac", "Cipher", "Signature",
        "KeyPairGenerator", "KeyFactory", "KeyGenerator", "KeyAgreement"
    );

    private static final Set<String> WEAK_SYMMETRIC = Set.of(
        "DES", "DESEDE", "RC2", "RC4", "ARCFOUR", "BLOWFISH", "IDEA"
    );

    public static void main(String[] args) throws Exception {
        String targetValue = System.getenv("CBOM_TARGET");
        if (targetValue == null || targetValue.isBlank()) {
            System.err.println("Error: Set CBOM_TARGET to the Java project directory.");
            System.exit(1);
        }

        Path target = Paths.get(targetValue).toAbsolutePath().normalize();
        if (!Files.isDirectory(target)) {
            System.err.println("Error: Target directory not found: " + target);
            System.exit(1);
        }

        Path findingsFile = Paths.get("java-findings.json").toAbsolutePath().normalize();

        // FIX 1: Delete the old findings file if it exists
        if (Files.exists(findingsFile)) {
            Files.delete(findingsFile);
        }
        
        // FIX 2: Create a brand new empty Array instead of loading old data
        ArrayNode findings = MAPPER.createArrayNode();

        // FIX 3: setAttributeComments(false) ensures comments are NEVER parsed by the AST
        ParserConfiguration configuration = new ParserConfiguration()
            .setLanguageLevel(ParserConfiguration.LanguageLevel.BLEEDING_EDGE)
            .setAttributeComments(false);

        JavaParser parser = new JavaParser(configuration);
        int[] count = {0};

        try (Stream<Path> paths = Files.walk(target)) {
            paths.filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".java"))
                .filter(p -> !isIgnored(target, p))
                .forEach(file -> {
                    try {
                        ParseResult<CompilationUnit> result = parser.parse(file);
                        if (result.getResult().isPresent()) {
                            CompilationUnit unit = result.getResult().get();
                            unit.accept(new CryptoVisitor(target, findings, count), null);
                        }
                    } catch (Exception e) {
                        System.err.println("Warning: Skipping " + file + ": " + e.getMessage());
                    }
                });
        }

        MAPPER.writerWithDefaultPrettyPrinter().writeValue(findingsFile.toFile(), findings);
        System.out.println("Java scan completed.");
        System.out.println("Java findings added: " + count[0]);
        System.out.println("Combined findings file: " + findingsFile);
    }

    private static boolean isIgnored(Path root, Path file) {
        Path relative = root.relativize(file);
        for (Path part : relative) {
            if (IGNORED_DIRS.contains(part.toString())) return true;
        }
        return false;
    }

    private static String simpleName(String scope) {
        int index = scope.lastIndexOf('.');
        return index >= 0 ? scope.substring(index + 1) : scope;
    }

    private static String determineCategory(String algorithm, String api) {
        String upper = algorithm.toUpperCase(Locale.ROOT);
        if (api.equals("MessageDigest") || upper.startsWith("SHA") || upper.startsWith("MD")) return "Hash";
        if (api.equals("Mac") || upper.startsWith("HMAC")) return "MAC";
        if (api.equals("Signature") || upper.contains("RSA") || upper.contains("ECDSA")) return "Signature";
        if (api.equals("KeyGenerator") || upper.startsWith("AES") || upper.startsWith("DES")) return "Symmetric Encryption";
        if (api.equals("KeyPairGenerator") || api.equals("KeyAgreement")) return "Key Exchange / Generation";
        if (api.equals("Cipher")) return "Cipher";
        if (api.equals("SecureRandom")) return "PRNG";
        return "Cryptography";
    }

    private static boolean isConstantExpression(Expression expr) {
        if (expr.isStringLiteralExpr() || expr.isIntegerLiteralExpr() || expr.isArrayInitializerExpr()) return true;
        if (expr.isArrayCreationExpr()) {
            ArrayCreationExpr ace = expr.asArrayCreationExpr();
            return ace.getInitializer().map(init -> init.getValues().stream()
                .allMatch(JavaCryptoScanner::isConstantExpression)).orElse(true);
        }
        if (expr.isBinaryExpr()) {
            BinaryExpr be = expr.asBinaryExpr();
            return isConstantExpression(be.getLeft()) && isConstantExpression(be.getRight());
        }
        return false;
    }

    private static class CryptoVisitor extends VoidVisitorAdapter<Void> {
        private final Path root;
        private final ArrayNode findings;
        private final int[] count;

        // Track variable declarations for Key size validation
        private final Map<String, String> variableTypes = new HashMap<>();

        CryptoVisitor(Path root, ArrayNode findings, int[] count) {
            this.root = root;
            this.findings = findings;
            this.count = count;
        }

        @Override
        public void visit(VariableDeclarator var, Void arg) {
            super.visit(var, arg);
            if (var.getInitializer().isPresent()) {
                Expression init = var.getInitializer().get();
                if (init.isMethodCallExpr() && init.asMethodCallExpr().getNameAsString().equals("getInstance")) {
                    MethodCallExpr mce = init.asMethodCallExpr();
                    if (mce.getScope().isPresent() && simpleName(mce.getScope().get().toString()).equals("KeyPairGenerator")) {
                        variableTypes.put(var.getNameAsString(), "KeyPairGenerator");
                    }
                }
                if (init.isObjectCreationExpr()) {
                    String typeName = init.asObjectCreationExpr().getType().getNameAsString();
                    if (typeName.equals("SecureRandom")) {
                        variableTypes.put(var.getNameAsString(), "SecureRandom");
                    }
                }
            }
        }

        @Override
        public void visit(MethodCallExpr call, Void arg) {
            super.visit(call, arg);
            String method = call.getNameAsString();

            // 1. Hash/Cipher/Signature Factory Methods
            if (method.equals("getInstance") && call.getScope().isPresent() && !call.getArguments().isEmpty()) {
                String scope = simpleName(call.getScope().get().toString());
                if (CRYPTO_APIS.contains(scope)) {
                    Expression firstArg = call.getArgument(0);
                    if (firstArg.isStringLiteralExpr()) {
                        String algorithm = firstArg.asStringLiteralExpr().asString();
                        processAlgorithm(call, scope, algorithm);
                    }
                }
            }

            // 2. Insecure Random Seed
            if (method.equals("setSeed") && call.getScope().isPresent()) {
                if (!call.getArguments().isEmpty() && isConstantExpression(call.getArgument(0))) {
                    addFinding(call, "PRNG", "HIGH", "CWE-330", "SecureRandom", "SecureRandom seeded with a constant value");
                }
            }

            // 3. Weak RSA Key Size
            if (method.equals("initialize") && call.getScope().isPresent()) {
                String scopeName = call.getScope().get().toString();
                if (variableTypes.get(scopeName) != null && variableTypes.get(scopeName).equals("KeyPairGenerator")) {
                    if (!call.getArguments().isEmpty() && call.getArgument(0).isIntegerLiteralExpr()) {
                        int size = call.getArgument(0).asIntegerLiteralExpr().asInt();
                        if (size < 2048) {
                            addFinding(call, "Key Exchange / Generation", "HIGH", "CWE-326", "KeyPairGenerator", "RSA Key Size too small: " + size + " bits");
                        }
                    }
                }
            }

            // 4. SSL Endpoint Verification
            if (method.equals("setEndpointIdentificationAlgorithm")) {
                if (!call.getArguments().isEmpty() && call.getArgument(0).isStringLiteralExpr()) {
                    String algo = call.getArgument(0).asStringLiteralExpr().asString();
                    if (algo.isEmpty()) {
                        addFinding(call, "TLS", "HIGH", "CWE-295", "SSLSocket", "Endpoint identification disabled (empty algorithm)");
                    }
                }
            }
            
            // 5. Hardcoded KeyStore Password
            if (method.equals("load") && call.getArguments().size() >= 2) {
                Expression pwdArg = call.getArgument(1);
                if (isConstantExpression(pwdArg)) {
                    addFinding(call, "KeyStore", "HIGH", "CWE-798", "KeyStore.load", "Hardcoded keystore password");
                }
            }
        }

        @Override
        public void visit(ObjectCreationExpr expr, Void arg) {
            super.visit(expr, arg);
            String typeName = expr.getType().getNameAsString();

            // 1. Hardcoded SecretKey
            if (typeName.equals("SecretKeySpec") && !expr.getArguments().isEmpty() && isConstantExpression(expr.getArgument(0))) {
                addFinding(expr, "Symmetric Encryption", "HIGH", "CWE-798", "SecretKeySpec", "Hardcoded symmetric key detected");
            }

            // 2. Hardcoded PBE Password
            if (typeName.equals("PBEKeySpec") && !expr.getArguments().isEmpty() && isConstantExpression(expr.getArgument(0))) {
                addFinding(expr, "Symmetric Encryption", "HIGH", "CWE-798", "PBEKeySpec", "Hardcoded PBE password detected");
            }

            // 3. Static IV
            if (typeName.equals("IvParameterSpec") || typeName.equals("GCMParameterSpec")) {
                int ivIndex = typeName.equals("GCMParameterSpec") ? 1 : 0;
                if (expr.getArguments().size() > ivIndex && isConstantExpression(expr.getArgument(ivIndex))) {
                    addFinding(expr, "Symmetric Encryption", "MEDIUM", "CWE-329", typeName, "Hardcoded/Static IV detected");
                }
            }

            // 4. Hardcoded PBE Salt
            if (typeName.equals("PBEParameterSpec")) {
                if (expr.getArguments().size() >= 1 && isConstantExpression(expr.getArgument(0))) {
                    addFinding(expr, "Symmetric Encryption", "HIGH", "CWE-760", "PBEParameterSpec", "Hardcoded salt detected in PBE");
                }
            }

            // 5. Insecure TrustManager / HostnameVerifier
            if (typeName.equals("X509TrustManager") || typeName.equals("HostnameVerifier")) {
                expr.getAnonymousClassBody().ifPresent(body -> {
                    body.forEach(member -> {
                        if (member instanceof MethodDeclaration) {
                            MethodDeclaration md = (MethodDeclaration) member;
                            String mName = md.getNameAsString();
                            if (mName.equals("checkServerTrusted") || mName.equals("checkClientTrusted") || mName.equals("verify")) {
                                addFinding(md, "TLS", "CRITICAL", "CWE-295", typeName, "Insecure " + typeName + " implementation (trusts all)");
                            }
                        }
                    });
                });
            }

            // 6. Insecure HTTP Protocol
            if (typeName.equals("URL") && !expr.getArguments().isEmpty()) {
                Expression urlArg = expr.getArgument(0);
                if (urlArg.isStringLiteralExpr() && urlArg.asStringLiteralExpr().asString().toLowerCase().startsWith("http://")) {
                    addFinding(expr, "Network", "HIGH", "CWE-319", "URL", "Insecure HTTP protocol used instead of HTTPS");
                }
            }
        }

        private void processAlgorithm(Node node, String api, String algorithm) {
            String upper = algorithm.toUpperCase(Locale.ROOT);
            String category = determineCategory(algorithm, api);
            String risk = "LOW";
            String message = "Cryptographic algorithm detected: " + algorithm;
            String cwe = "N/A";

            // Broken Hashes
            if (Set.of("MD2", "MD4", "MD5", "SHA-1", "SHA1", "RIPEMD-160").contains(upper)) {
                risk = "HIGH";
                cwe = "CWE-328";
                message = "Weak hash algorithm used: " + algorithm;
            }
            // Legacy Ciphers
            else if (WEAK_SYMMETRIC.contains(upper) || upper.startsWith("DES/") || upper.startsWith("RC4/") || upper.contains("BLOWFISH")) {
                risk = "CRITICAL";
                cwe = "CWE-327";
                message = "Weak symmetric cipher used: " + algorithm;
            }
            // Insecure Modes
            else if (upper.contains("/ECB/") || upper.equals("AES") || upper.equals("DES")) {
                risk = "HIGH";
                cwe = "CWE-327";
                message = "ECB mode (or default ECB) detected: " + algorithm;
            }
            else if (upper.contains("/CBC/") && (upper.contains("PKCS5") || upper.contains("PKCS7"))) {
                risk = "MEDIUM";
                cwe = "CWE-327";
                message = "CBC mode with padding is vulnerable to Padding Oracle: " + algorithm;
            }
            // Post-Quantum Vulnerable
            else if (upper.contains("RSA") || upper.contains("EC") || upper.contains("DSA") || upper.contains("ECDSA") || upper.contains("ED25519")) {
                risk = "MEDIUM";
                cwe = "CWE-327";
                message = "Quantum-vulnerable algorithm (migration planning needed): " + algorithm;
            }

            addFinding(node, category, risk, cwe, algorithm, message);
        }

        private void addFinding(Node node, String category, String risk, String cwe, String algorithm, String message) {
            ObjectNode finding = MAPPER.createObjectNode();
            finding.put("algorithm", algorithm);
            finding.put("category", category);
            finding.put("risk", risk);
            finding.put("cwe", cwe);
            finding.put("message", message);
            finding.put("type", "vulnerability");
            finding.put("language", "Java");
            finding.put("file", getRelativePath(node));
            finding.put("line", node.getBegin().map(p -> p.line).orElse(0));
            findings.add(finding);
            count[0]++;
        }

        private String getRelativePath(Node node) {
            return root.relativize(
                node.findCompilationUnit()
                    .flatMap(cu -> cu.getStorage().map(s -> s.getPath()))
                    .orElse(root)
            ).toString().replace('\\', '/');
        }
    }
}