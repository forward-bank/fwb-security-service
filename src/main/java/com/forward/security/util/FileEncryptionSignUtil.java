package com.forward.security.util;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * Utility that encrypts a payment file using a PGP public key AND signs it
 * using a PGP private key (no compression) — the signed counterpart to
 * {@link FileEncryptionUtil}.
 *
 * <p>Input files (read from classpath / src/main/resources):
 * <ul>
 *   <li>Payment file       : {@code payment-files/pain008/pain.008.001.08.xml}</li>
 *   <li>Bank public key    : {@code keys/bank/public/Forward_Bank_0x7C56E1A820421C1D_public.asc}</li>
 *   <li>Customer secret key: {@code keys/customer/private/Hexa_Consulting_0x3497C5F5C5F1D494_SECRET.asc}</li>
 * </ul>
 *
 * <p>Output file written to:
 * <pre>
 *   fwb-security-service/src/main/resources/payment-files/pain008/encrypted/pain.008.001.08.PM.signed.pgp
 * </pre>
 *
 * <p>Encryption/signing scheme:
 * <ul>
 *   <li>Cipher         : AES-256 symmetric session key</li>
 *   <li>Key exchange   : recipient's (bank's) RSA public key wraps the session key</li>
 *   <li>MDC            : enabled (tamper detection)</li>
 *   <li>Signature      : customer's private key, SHA-256, one-pass signature over the literal data</li>
 *   <li>Compression    : none — signed plaintext is encrypted directly, matching {@code FileEncryptionUtil}</li>
 *   <li>Output format  : binary PGP (.pgp) — NOT ASCII-armored</li>
 * </ul>
 *
 * <p>Resulting packet structure inside the encrypted envelope:
 * <pre>
 *   PGPOnePassSignatureList  ← customer signs
 *     PGPLiteralData         ← plaintext bytes
 *   PGPSignatureList         ← trailing signature
 * </pre>
 * This is the structure {@code PgpDecryptionService.decryptSigned()} expects
 * when {@code pgpSigningEnabled = true}.
 *
 * <p><b>Passphrase:</b> the customer secret key's passphrase must be supplied via the
 * {@code CUSTOMER_KEY_PASSPHRASE} environment variable before running — it is never
 * hardcoded in source. See {@link #resolvePassphrase()}.
 *
 * <p><b>How to run:</b> right-click → Run {@code main()}.
 * Ensure {@code mvn compile} has been run at least once so Maven copies
 * resources into {@code target/classes}.
 */
public class FileEncryptionSignUtil {

    // ── Classpath resource paths (under src/main/resources) ──────────────────
    private static final String PAYMENT_FILE_RESOURCE =
            "payment-files/pain008/pain.008.001.08.xml";

    private static final String BANK_PUBLIC_KEY_RESOURCE =
            "keys/bank/public/Forward_Bank_0x7C56E1A820421C1D_public.asc";

    private static final String CUSTOMER_SECRET_KEY_RESOURCE =
            "keys/customer/private/Hexa_Consulting_0x3497C5F5C5F1D494_SECRET.asc";

    // ── Output path relative to src/main/resources ────────────────────────────
    // resolveOutputPath() anchors this to the actual src/main/resources directory
    // by walking up from target/classes to the project root, so it works
    // regardless of IDE / Maven working directory settings.
    private static final String OUTPUT_RESOURCE_RELATIVE =
            "payment-files/pain008/encrypted/pain.008.001.08.PM.signed.pgp";

    // ── Passphrase env var (never hardcode secret key passphrases) ───────────
    private static final String PASSPHRASE_ENV_VAR = "HexaPass0!";

    // ── PGP settings ──────────────────────────────────────────────────────────
    private static final int SYMMETRIC_ALGORITHM = SymmetricKeyAlgorithmTags.AES_256;
    private static final int HASH_ALGORITHM      = HashAlgorithmTags.SHA256;
    private static final int BUFFER_SIZE         = 1 << 16; // 64 KB write buffer

    // ── Entry point ───────────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {

        System.out.println("=".repeat(70));
        System.out.println("  FWB Payment File PGP Encrypt+Sign Utility");
        System.out.println("=".repeat(70));
        System.out.println("  Payment file        : " + PAYMENT_FILE_RESOURCE);
        System.out.println("  Bank public key     : " + BANK_PUBLIC_KEY_RESOURCE);
        System.out.println("  Customer secret key : " + CUSTOMER_SECRET_KEY_RESOURCE);
        System.out.println("  Output              : src/main/resources/" + OUTPUT_RESOURCE_RELATIVE);
        System.out.println("  Cipher              : AES-256 + MDC");
        System.out.println("  Signature hash      : SHA-256");
        System.out.println("  Compression         : none");
        System.out.println("-".repeat(70));

        // Step 1 — load plaintext bytes from classpath
        byte[] plaintextBytes = readFromClasspath(PAYMENT_FILE_RESOURCE);
        System.out.println("  Plaintext size      : " + plaintextBytes.length + " bytes");

        // Step 2 — load and parse the bank's PGP public key
        PGPPublicKey encryptionKey = loadEncryptionKey(BANK_PUBLIC_KEY_RESOURCE);
        System.out.println("  Bank key ID         : 0x" + Long.toHexString(encryptionKey.getKeyID()).toUpperCase());
        System.out.println("  Bank key algorithm  : " + algorithmName(encryptionKey.getAlgorithm()));

        // Step 3 — load the customer's PGP secret key and extract the private key
        char[] passphrase = resolvePassphrase();
        PGPSecretKey signingSecretKey = loadSigningSecretKey(CUSTOMER_SECRET_KEY_RESOURCE);
        PGPPrivateKey signingPrivateKey = signingSecretKey.extractPrivateKey(
                new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                        .build(passphrase));
        System.out.println("  Customer key ID     : 0x"
                + Long.toHexString(signingSecretKey.getKeyID()).toUpperCase());

        // Step 4 — encrypt + sign
        byte[] outputBytes = encryptAndSign(
                plaintextBytes,
                encryptionKey,
                signingSecretKey,
                signingPrivateKey,
                extractFilename(PAYMENT_FILE_RESOURCE));
        System.out.println("  Output size         : " + outputBytes.length + " bytes");

        // Step 5 — resolve the absolute output path anchored to src/main/resources
        Path outputPath = resolveOutputPath(OUTPUT_RESOURCE_RELATIVE);
        Files.createDirectories(outputPath.getParent());
        Files.write(outputPath, outputBytes);

        System.out.println("-".repeat(70));
        System.out.println("  ✓ Encrypted+signed file written to:");
        System.out.println("    " + outputPath.toAbsolutePath());
        System.out.println("=".repeat(70));
    }

    // ── Core encryption + signing ─────────────────────────────────────────────

    /**
     * Encrypts {@code plaintext} for {@code encryptionKey}, embedding a signature
     * from {@code signingSecretKey}/{@code signingPrivateKey} over the literal data.
     *
     * <p>PGP packet structure (no compression):
     * <pre>
     *   PGPEncryptedDataGenerator     ← AES-256 session key wrapped with recipient public key
     *     └── PGPOnePassSignature       ← one-pass signature header
     *     └── PGPLiteralDataGenerator   ← plaintext bytes with filename + timestamp metadata
     *           └── plaintext bytes (also fed into the signature generator)
     *     └── PGPSignature              ← trailing signature
     * </pre>
     *
     * @param plaintext         raw bytes of the payment XML file
     * @param encryptionKey     recipient's (bank's) encryption-capable PGP public key
     * @param signingSecretKey  signer's (customer's) PGP secret key — used for its public metadata
     * @param signingPrivateKey signer's (customer's) extracted private key — used to sign
     * @param originalName      filename embedded in the literal data packet
     * @return binary PGP-encrypted, signed bytes (.pgp, not ASCII-armored)
     */
    public static byte[] encryptAndSign(byte[] plaintext,
                                        PGPPublicKey encryptionKey,
                                        PGPSecretKey signingSecretKey,
                                        PGPPrivateKey signingPrivateKey,
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

            // ── One-pass signature header ──────────────────────────────────
            PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                    new BcPGPContentSignerBuilder(
                            signingSecretKey.getPublicKey().getAlgorithm(), HASH_ALGORITHM));
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingPrivateKey);

            Iterator<String> userIds = signingSecretKey.getPublicKey().getUserIDs();
            if (userIds.hasNext()) {
                PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
                subpacketGenerator.setSignerUserID(false, userIds.next());
                signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());
            }

            signatureGenerator.generateOnePassVersion(false).encode(encOut);

            // ── Literal data (plaintext), fed through the signature ──────────
            PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
            try (OutputStream literalOut = literalGen.open(
                    encOut,
                    PGPLiteralData.BINARY,
                    originalName,
                    plaintext.length,
                    new Date())) {
                literalOut.write(plaintext);
                signatureGenerator.update(plaintext);
            }

            // ── Trailing signature ────────────────────────────────────────────
            signatureGenerator.generate().encode(encOut);
        }

        return encryptedOut.toByteArray();
    }

    // ── Key loading ────────────────────────────────────────────────────────────

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

    /**
     * Reads a PGP secret key ring from the classpath (armored or binary, tolerated
     * transparently) and returns the first signing-capable secret key found.
     */
    public static PGPSecretKey loadSigningSecretKey(String resourcePath)
            throws IOException, PGPException {

        byte[] keyBytes = readFromClasspath(resourcePath);

        try (InputStream decoded = dearmour(new ByteArrayInputStream(keyBytes))) {

            PGPSecretKeyRingCollection rings = new PGPSecretKeyRingCollection(
                    decoded, new BcKeyFingerprintCalculator());

            Iterator<PGPSecretKeyRing> ringIt = rings.getKeyRings();
            while (ringIt.hasNext()) {
                Iterator<PGPSecretKey> keyIt = ringIt.next().getSecretKeys();
                while (keyIt.hasNext()) {
                    PGPSecretKey key = keyIt.next();
                    if (key.isSigningKey()) {
                        return key;
                    }
                }
            }
        }

        throw new IllegalStateException(
                "No signing-capable secret key found in: " + resourcePath);
    }

    /**
     * Wraps the stream in an {@link ArmoredInputStream} if it appears to be ASCII-armored
     * (starts with "-----"), otherwise returns the original stream unchanged.
     */
    private static InputStream dearmour(InputStream raw) throws IOException {
        BufferedInputStream buffered = new BufferedInputStream(raw);
        buffered.mark(6);
        byte[] header = new byte[5];
        int bytesRead = buffered.read(header);
        buffered.reset();

        if (bytesRead == 5 && header[0] == '-' && header[1] == '-') {
            return new ArmoredInputStream(buffered);
        }
        return buffered;
    }

    // ── Passphrase resolution ──────────────────────────────────────────────────

    /**
     * Reads the customer secret key passphrase from the {@code CUSTOMER_KEY_PASSPHRASE}
     * environment variable. Passphrases are never hardcoded or logged.
     */
    private static char[] resolvePassphrase() {
        String value = PASSPHRASE_ENV_VAR;
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(
                    "Missing passphrase — set the " + PASSPHRASE_ENV_VAR
                            + " environment variable before running this utility");
        }
        return value.toCharArray();
    }

    // ── Classpath helper ──────────────────────────────────────────────────────

    /**
     * Reads all bytes from a classpath resource.
     * Run {@code mvn compile} first so Maven copies it to target/classes.
     */
    static byte[] readFromClasspath(String resourcePath) throws IOException {
        try (InputStream in = FileEncryptionSignUtil.class
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
     * Falls back to a CWD-relative path if the classloader cannot supply a URL.
     */
    private static Path resolveOutputPath(String relativeOutputPath) {
        try {
            URL classesUrl = FileEncryptionSignUtil.class.getClassLoader().getResource(".");
            if (classesUrl != null) {
                // target/classes  →  target  →  project root
                Path projectRoot = Paths.get(classesUrl.toURI())
                        .toAbsolutePath()
                        .getParent()   // target
                        .getParent();  // project root
                System.out.println("  Project root        : " + projectRoot);
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

    /** Human-readable label for a PGP key algorithm tag. */
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