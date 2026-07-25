package com.forward.security.util;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * Utility that encrypts a payment file using a PGP public key (no compression).
 *
 * <p>Input files (read from classpath / src/main/resources):
 * <ul>
 *   <li>Payment file : {@code payment-files/pain008/pain.008.001.08.xml}</li>
 *   <li>Public key   : {@code keys/bank/public/Forward_Bank_0x7C56E1A820421C1D_public.asc}</li>
 * </ul>
 *
 * <p>Output file written to:
 * <pre>
 *   fwb-security-service/src/main/resources/payment-files/pain008/encrypted/pain.008.001.08.PM.pgp
 * </pre>
 *
 * <p>Encryption scheme:
 * <ul>
 *   <li>Cipher       : AES-256 symmetric session key</li>
 *   <li>Key exchange : recipient's RSA public key wraps the session key</li>
 *   <li>MDC          : enabled (tamper detection)</li>
 *   <li>Compression  : none — plaintext is encrypted directly</li>
 *   <li>Output format: binary PGP (.pgp) — NOT ASCII-armored</li>
 * </ul>
 *
 * <p><b>How to run:</b> right-click → Run {@code main()}.
 * Ensure {@code mvn compile} has been run at least once so Maven copies
 * resources into {@code target/classes}.
 */
public class FileEncryptionUtil {

    // ── Classpath resource paths (under src/main/resources) ──────────────────
    private static final String PAYMENT_FILE_RESOURCE =
            "payment-files/pain008/pain.008.001.08.xml";

    private static final String PUBLIC_KEY_RESOURCE =
            "keys/bank/public/Forward_Bank_0x7C56E1A820421C1D_public.asc";

    // ── Output path relative to src/main/resources ────────────────────────────
    // resolveOutputPath() anchors this to the actual src/main/resources directory
    // by walking up from target/classes to the project root, so it works
    // regardless of IDE / Maven working directory settings.
    private static final String OUTPUT_RESOURCE_RELATIVE =
            "payment-files/pain008/encrypted/pain.008.001.08.PM.pgp";

    // ── PGP settings ──────────────────────────────────────────────────────────
    private static final int SYMMETRIC_ALGORITHM = SymmetricKeyAlgorithmTags.AES_256;
    private static final int BUFFER_SIZE         = 1 << 16; // 64 KB write buffer

    // ── Entry point ───────────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {

        System.out.println("=".repeat(70));
        System.out.println("  FWB Payment File PGP Encryption Utility");
        System.out.println("=".repeat(70));
        System.out.println("  Payment file : " + PAYMENT_FILE_RESOURCE);
        System.out.println("  Public key   : " + PUBLIC_KEY_RESOURCE);
        System.out.println("  Output       : src/main/resources/" + OUTPUT_RESOURCE_RELATIVE);
        System.out.println("  Cipher       : AES-256 + MDC");
        System.out.println("  Compression  : none");
        System.out.println("-".repeat(70));

        // Step 1 — load plaintext bytes from classpath
        byte[] plaintextBytes = readFromClasspath(PAYMENT_FILE_RESOURCE);
        System.out.println("  Plaintext size  : " + plaintextBytes.length + " bytes");

        // Step 2 — load and parse the PGP public key
        PGPPublicKey encryptionKey = loadEncryptionKey(PUBLIC_KEY_RESOURCE);
        System.out.println("  Key ID          : 0x" + Long.toHexString(encryptionKey.getKeyID()).toUpperCase());
        System.out.println("  Key algorithm   : " + algorithmName(encryptionKey.getAlgorithm()));
        System.out.println("  Key bit strength: " + encryptionKey.getBitStrength());

        // Step 3 — encrypt
        byte[] encryptedBytes = encrypt(
                plaintextBytes,
                encryptionKey,
                extractFilename(PAYMENT_FILE_RESOURCE));
        System.out.println("  Encrypted size  : " + encryptedBytes.length + " bytes");

        // Step 4 — resolve the absolute output path anchored to src/main/resources
        Path outputPath = resolveOutputPath(OUTPUT_RESOURCE_RELATIVE);
        Files.createDirectories(outputPath.getParent());
        Files.write(outputPath, encryptedBytes);

        System.out.println("-".repeat(70));
        System.out.println("  ✓ Encrypted file written to:");
        System.out.println("    " + outputPath.toAbsolutePath());
        System.out.println("=".repeat(70));
    }

    // ── Core encryption ───────────────────────────────────────────────────────

    /**
     * Encrypts {@code plaintext} for the given PGP public key recipient.
     *
     * <p>PGP packet structure (no compression):
     * <pre>
     *   PGPEncryptedDataGenerator   ← AES-256 session key wrapped with recipient public key
     *     └── PGPLiteralDataGenerator  ← plaintext bytes with filename + timestamp metadata
     *           └── plaintext bytes
     * </pre>
     *
     * @param plaintext     raw bytes of the payment XML file
     * @param encryptionKey recipient's encryption-capable PGP public key
     * @param originalName  filename embedded in the literal data packet
     * @return binary PGP-encrypted bytes (.pgp, not ASCII-armored)
     */
    public static byte[] encrypt(byte[] plaintext,
                                  PGPPublicKey encryptionKey,
                                  String originalName) throws IOException, PGPException {

        ByteArrayOutputStream encryptedOut = new ByteArrayOutputStream();

        // AES-256 with MDC integrity protection
        BcPGPDataEncryptorBuilder encryptorBuilder =
                new BcPGPDataEncryptorBuilder(SYMMETRIC_ALGORITHM)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom());

        PGPEncryptedDataGenerator encDataGen = new PGPEncryptedDataGenerator(encryptorBuilder);
        // Recipient: public key encrypts (wraps) the AES session key
        encDataGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encryptionKey));

        try (OutputStream encOut = encDataGen.open(encryptedOut, new byte[BUFFER_SIZE])) {
            // Write plaintext directly as a literal data packet — no compression layer
            PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
            try (OutputStream literalOut = literalGen.open(
                    encOut,
                    PGPLiteralData.BINARY,
                    originalName,
                    plaintext.length,
                    new Date())) {
                literalOut.write(plaintext);
            }
        }

        return encryptedOut.toByteArray();
    }

    // ── Public key loading ────────────────────────────────────────────────────

    /**
     * Reads an ASCII-armored PGP public key from the classpath and returns the
     * first encryption-capable key found in the ring.
     */
    public static PGPPublicKey loadEncryptionKey(String resourcePath)
            throws IOException, PGPException {

        byte[] keyBytes = readFromClasspath(resourcePath);

        try (InputStream decoded = PGPUtil.getDecoderStream(
                new BufferedInputStream(new ByteArrayInputStream(keyBytes)))) {

            PGPPublicKeyRingCollection rings = new PGPPublicKeyRingCollection(
                    decoded, new BcKeyFingerprintCalculator());

            Iterator<PGPPublicKeyRing> ringIt = rings.getKeyRings();
            while (ringIt.hasNext()) {
                Iterator<PGPPublicKey> keyIt = ringIt.next().getPublicKeys();
                while (keyIt.hasNext()) {
                    PGPPublicKey key = keyIt.next();
                    if (key.isEncryptionKey()) {
                        return key;
                    }
                }
            }
        }

        throw new IllegalStateException(
                "No encryption-capable public key found in: " + resourcePath);
    }

    // ── Classpath helper ──────────────────────────────────────────────────────

    /**
     * Reads all bytes from a classpath resource.
     * Run {@code mvn compile} first so Maven copies resources to target/classes.
     */
    static byte[] readFromClasspath(String resourcePath) throws IOException {
        try (InputStream in = FileEncryptionUtil.class
                .getClassLoader()
                .getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IllegalStateException(
                        "Resource not found on classpath: " + resourcePath + "\n"
                        + "  → Ensure it exists under src/main/resources/\n"
                        + "  → Run 'mvn compile' so Maven copies it to target/classes");
            }
            return in.readAllBytes();
        }
    }

    // ── Output path resolution ────────────────────────────────────────────────

    /**
     * Resolves the output path anchored to {@code src/main/resources/} by:
     * <ol>
     *   <li>Locating {@code target/classes} via the classloader.</li>
     *   <li>Walking up two levels: {@code classes → target → project root}.</li>
     *   <li>Descending into {@code src/main/resources/<relativeOutputPath>}.</li>
     * </ol>
     * Falls back to a CWD-relative path if the classloader cannot supply a URL
     * (e.g. running from a packaged JAR — not the normal use case for this utility).
     */
    private static Path resolveOutputPath(String relativeOutputPath) {
        try {
            URL classesUrl = FileEncryptionUtil.class.getClassLoader().getResource(".");
            if (classesUrl != null) {
                // target/classes  →  target  →  project root
                Path projectRoot = Paths.get(classesUrl.toURI())
                        .toAbsolutePath()
                        .getParent()   // target
                        .getParent();  // project root
                System.out.println("  Project root    : " + projectRoot);
                return projectRoot.resolve("src/main/resources/" + relativeOutputPath);
            }
        } catch (Exception e) {
            System.out.println("  WARN: cannot resolve project root via classloader ("
                    + e.getMessage() + ") — falling back to working directory");
        }
        // Fallback — works when CWD == project root (default in IntelliJ and Maven)
        return Paths.get("src/main/resources/" + relativeOutputPath).toAbsolutePath();
    }

    // ── Small utilities ───────────────────────────────────────────────────────

    /** Extracts the filename from a resource path, e.g. {@code "pain.008.001.08.xml"}. */
    private static String extractFilename(String resourcePath) {
        int slash = resourcePath.lastIndexOf('/');
        return slash >= 0 ? resourcePath.substring(slash + 1) : resourcePath;
    }

    /** Human-readable label for a PGP public key algorithm tag. */
    private static String algorithmName(int algorithm) {
        return switch (algorithm) {
            case 1  -> "RSA (encrypt or sign)";
            case 2  -> "RSA (encrypt only)";
            case 3  -> "RSA (sign only)";
            case 16 -> "ElGamal (encrypt only)";
            case 17 -> "DSA";
            case 18 -> "ECDH";
            case 19 -> "ECDSA";
            case 22 -> "EdDSA";
            default -> "Unknown (" + algorithm + ")";
        };
    }
}
