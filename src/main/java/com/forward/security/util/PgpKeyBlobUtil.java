package com.forward.security.util;

import org.bouncycastle.bcpg.ArmoredInputStream;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utility that reads an ASCII-armored PGP private key (.asc) from the
 * classpath directory {@code keys/bank/private/}, de-armors it to raw binary
 * PGP packet bytes, and prints everything needed to INSERT those bytes into
 * the {@code KEY} column (BYTEA) of {@code FWB_MST_BANK_PGP_PRIVATE_KEY}.
 *
 * <h2>What "de-armor" means</h2>
 * An {@code .asc} file looks like:
 * <pre>
 *   -----BEGIN PGP PRIVATE KEY BLOCK-----
 *
 *   lQPGBGpgYbkBCADP1rEAeOxs...  (Base64-encoded binary PGP packets)
 *   =zXAD
 *   -----END PGP PRIVATE KEY BLOCK-----
 * </pre>
 * The armor is simply Base64 + header/footer + a CRC-24 checksum line.
 * De-armoring decodes the Base64 back to the underlying binary bytes —
 * those bytes are the actual PGP packet stream and are what PostgreSQL
 * stores in a BYTEA column.
 *
 * <h2>How to run</h2>
 * Place your {@code .asc} file under:
 * <pre>
 *   src/main/resources/keys/bank/private/your-key.asc
 * </pre>
 * Then run this class. If there is more than one {@code .asc} file in the
 * directory, pass the filename as {@code args[0]}:
 * <pre>
 *   args[0] — (optional) filename, e.g. "Forward_Bank_SECRET.asc"
 *             If omitted, the first .asc found in the directory is used.
 * </pre>
 *
 * <h2>Output</h2>
 * <ul>
 *   <li>Binary byte count and first/last 8 bytes for verification.</li>
 *   <li>PostgreSQL hex literal ({@code \x...}) for use with {@code COPY} or
 *       {@code psql}.</li>
 *   <li>Base64 string for use with PostgreSQL's {@code decode()} function
 *       inside a SQL {@code INSERT}.</li>
 *   <li>A ready-to-paste SQL {@code INSERT} statement.</li>
 * </ul>
 *
 * <h2>⚠ Security note</h2>
 * This utility prints the raw (unencrypted) private key bytes to stdout.
 * Use it only in a secure, offline environment. For production, use
 * {@link PGPPrivateKeyEncryptionService} to encrypt the bytes before
 * storing them.
 */
public class PgpKeyBlobUtil {

    private static final String KEY_RESOURCE_DIR  = "keys/bank/private/";
    private static final String DEFAULT_FILENAME  = "Forward_Bank_0x7C56E1A820421C1D_SECRET.asc";

    public static void main(String[] args) throws Exception {

        // ── Locate the .asc file ──────────────────────────────────────────────
        String filename = resolveFilename(args);
        String resourcePath = KEY_RESOURCE_DIR + filename;

        System.out.println("=".repeat(70));
        System.out.println("  FWB PGP Key → Raw Binary Blob Utility");
        System.out.println("=".repeat(70));
        System.out.println("  Source      : classpath:" + resourcePath);

        // ── Read the .asc file from classpath ─────────────────────────────────
        byte[] ascBytes = readFromClasspath(resourcePath);
        System.out.println("  ASC size    : " + ascBytes.length + " bytes");

        // ── De-armor: strip armor wrapper → raw binary PGP packet bytes ───────
        byte[] binaryBytes = dearmor(ascBytes);
        System.out.println("  Binary size : " + binaryBytes.length + " bytes");
        System.out.println("-".repeat(70));

        // ── Verification: show first and last 8 bytes ─────────────────────────
        System.out.println("  First 8 bytes (hex) : " + toHex(Arrays.copyOf(binaryBytes, 8)));
        System.out.println("  Last  8 bytes (hex) : " + toHex(Arrays.copyOfRange(
                binaryBytes, binaryBytes.length - 8, binaryBytes.length)));
        System.out.println("-".repeat(70));

        // ── Produce outputs for PostgreSQL ────────────────────────────────────
        String base64Blob  = Base64.getEncoder().encodeToString(binaryBytes);
        String hexLiteral  = toHex(binaryBytes);

        System.out.println();
        System.out.println("  ── Option 1: SQL INSERT using decode() ─────────────────────────");
        System.out.println();
        System.out.println("  INSERT INTO FWB_MST_BANK_PGP_PRIVATE_KEY (");
        System.out.println("      KEY_NAME,");
        System.out.println("      KEY,");
        System.out.println("      VALID_FROM,");
        System.out.println("      VALID_TO,");
        System.out.println("      KEY_ACTIVE_FLAG,");
        System.out.println("      KEY_TYPE,");
        System.out.println("      PASSPHRASE,");
        System.out.println("      BANK_PVT_KEY_S3_PATH");
        System.out.println("  ) VALUES (");
        System.out.println("      'BANK_KEY_2026_Q1',");
        System.out.println("      decode('" + base64Blob + "', 'base64'),");
        System.out.println("      '2026-01-01',");
        System.out.println("      '2026-12-31',");
        System.out.println("      'Y',");
        System.out.println("      'RSA-4096',");
        System.out.println("      'REPLACE_WITH_ENCRYPTED_PASSPHRASE',");
        System.out.println("      'PGP_KEYS/BANK/PRIVATE/" + filename + "'");
        System.out.println("  );");

        System.out.println();
        System.out.println("  ── Option 2: PostgreSQL hex literal (\\x...) ────────────────────");
        System.out.println();
        System.out.println("  KEY = '\\x" + hexLiteral + "'");

        System.out.println();
        System.out.println("  ── Option 3: Raw Base64 (for copy-paste or scripting) ──────────");
        System.out.println();
        System.out.println("  " + base64Blob);

        System.out.println();
        System.out.println("=".repeat(70));
        System.out.println("  ✓ Done — " + binaryBytes.length + " raw binary bytes ready for BYTEA storage");
        System.out.println("=".repeat(70));
    }

    // ── Core: de-armor ASCII-armored PGP → raw binary bytes ──────────────────

    /**
     * Strips the PGP ASCII armor (BEGIN/END headers, Base64 encoding,
     * CRC-24 checksum) and returns the raw binary PGP packet bytes.
     *
     * <p>Uses Bouncy Castle's {@link ArmoredInputStream} which handles:
     * <ul>
     *   <li>Standard {@code -----BEGIN PGP PRIVATE KEY BLOCK-----} headers</li>
     *   <li>Optional blank line between headers and body</li>
     *   <li>The {@code =xxxx} CRC-24 checksum line (verified automatically)</li>
     * </ul>
     *
     * @param ascBytes the raw bytes of the {@code .asc} file (UTF-8 text)
     * @return binary PGP packet bytes suitable for BYTEA storage
     * @throws IOException if the input is not valid ASCII-armored PGP data
     */
    public static byte[] dearmor(byte[] ascBytes) throws IOException {
        try (InputStream raw = new BufferedInputStream(
                     new java.io.ByteArrayInputStream(ascBytes));
             ArmoredInputStream armoredIn = new ArmoredInputStream(raw);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8192];
            int n;
            while ((n = armoredIn.read(buffer)) >= 0) {
                out.write(buffer, 0, n);
            }

            byte[] result = out.toByteArray();
            if (result.length == 0) {
                throw new IOException(
                        "De-armoring produced zero bytes — the .asc file may be "
                        + "empty, malformed, or not a PGP armored block");
            }
            return result;
        }
    }

    // ── Classpath loader ──────────────────────────────────────────────────────

    /**
     * Reads all bytes from a classpath resource.
     *
     * @param resourcePath path relative to classpath root
     * @return file bytes
     * @throws IllegalStateException if the resource is not found
     * @throws IOException           on any read error
     */
    public static byte[] readFromClasspath(String resourcePath) throws IOException {
        try (InputStream in = PgpKeyBlobUtil.class
                .getClassLoader()
                .getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IllegalStateException(
                        "File not found on classpath: " + resourcePath + "\n"
                        + "  → Ensure the file exists at: "
                        + "src/main/resources/" + resourcePath + "\n"
                        + "  → Run 'mvn compile' so Maven copies resources to target/classes\n"
                        + "  → Expected file: src/main/resources/keys/bank/private/"
                        + DEFAULT_FILENAME);
            }
            return in.readAllBytes();
        }
    }

    // ── Filename resolution ───────────────────────────────────────────────────

    /**
     * Resolves the .asc filename to use.
     * If {@code args[0]} is supplied, that filename is used.
     * Otherwise falls back to {@link #DEFAULT_FILENAME}.
     */
    private static String resolveFilename(String[] args) {
        if (args.length > 0 && !args[0].isBlank()) {
            return args[0].trim();
        }
        return DEFAULT_FILENAME;
    }

    // ── Hex formatting ────────────────────────────────────────────────────────

    /**
     * Converts a byte array to a lowercase hex string (no spaces, no prefix).
     * Suitable for PostgreSQL {@code '\\x...'} byte literals.
     */
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
