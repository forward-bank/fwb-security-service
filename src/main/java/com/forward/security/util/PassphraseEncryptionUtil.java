package com.forward.security.util;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utility for encrypting a plain-text PGP key passphrase using AES-256-CBC
 * with PKCS7 padding (Bouncy Castle), matching the encryption scheme used by
 * the existing EncryptionServiceImpl in the bank's platform.
 *
 * <p><b>How to run from the IDE:</b><br>
 * Add two Program Arguments in the Run Configuration:
 * <pre>
 *   args[0] — plain-text passphrase   e.g.  ForwardPass0!!
 *   args[1] — Base64-encoded AES key  e.g.  USSAArji5KItcGYI+D2LPodDnnXIY6uygOKevaAgdj0=
 * </pre>
 *
 * <p><b>How to run from Maven:</b>
 * <pre>
 *   mvn compile exec:java \
 *       -Dexec.mainClass="com.forward.security.util.PassphraseEncryptionUtil" \
 *       -Dexec.args="ForwardPass0!! USSAArji5KItcGYI+D2LPodDnnXIY6uygOKevaAgdj0="
 * </pre>
 *
 * <p><b>Output format stored in DB (PASSPHRASE column):</b>
 * <pre>
 *   Base64( IV[16 bytes] | AES-256-CBC-ciphertext[N bytes] )
 * </pre>
 */
public class PassphraseEncryptionUtil {

    // ── Initialization Vector ────────────────────────────────────────────────

    /**
     * 16-byte AES-CBC Initialization Vector — the ASCII string "INITIALIZATION V".
     *
     * <pre>
     *  I    N    I    T    I    A    L    I    Z    A    T    I    O    N   ' '  V
     * 0x49 0x4E 0x49 0x54 0x49 0x41 0x4C 0x49 0x5A 0x41 0x54 0x49 0x4F 0x4E 0x20 0x56
     * </pre>
     */
    private static final byte[] INITIALIZATION_VECTOR = {
        0x49, 0x4E, 0x49, 0x54, 0x49, 0x41, 0x4C, 0x49,
        0x5A, 0x41, 0x54, 0x49, 0x4F, 0x4E, 0x20, 0x56
    };

    // ── Entry point ──────────────────────────────────────────────────────────

    /**
     * Program entry point.
     *
     * <p>Required arguments:
     * <ul>
     *   <li>{@code args[0]} — plain-text passphrase to encrypt</li>
     *   <li>{@code args[1]} — Base64-encoded AES-256 key (must decode to exactly 32 bytes);
     *       this is the value of {@code crypto.key} from {@code cryptoProperties}</li>
     * </ul>
     */
    public static void main(String[] args) throws Exception {

//        if (args.length < 2) {
//            System.err.println("Usage: PassphraseEncryptionUtil <passphrase> <base64AesKey>");
//            System.err.println();
//            System.err.println("  <passphrase>   — plain-text passphrase to encrypt");
//            System.err.println("  <base64AesKey> — crypto.key value (Base64, must decode to 32 bytes)");
//            System.exit(1);
//        }

        String plaintext    = "ForwardPass0!";
        String base64AesKey = "USSAArji5KItcGYI+D2LPodDnnXIY6uygOKevaAgdj0=";

        // Validate the key upfront so we get a clear error before doing anything else
        byte[] keyBytes = decodeAndValidateKey(base64AesKey);

        System.out.println("=".repeat(60));
        System.out.println(" FWB Passphrase Encryption Utility");
        System.out.println("=".repeat(60));
        System.out.println(" Algorithm  : AES-256-CBC / PKCS7 (Bouncy Castle)");
        System.out.println(" IV         : INITIALIZATION V  (16 ASCII bytes)");
        System.out.println(" Key        : " + base64AesKey.substring(0, 8) + "***  (" + keyBytes.length + " bytes decoded)");
        System.out.println("-".repeat(60));
        System.out.println(" Plain-text : " + plaintext);
        System.out.println("-".repeat(60));

        String encrypted = encryptPassphrase(plaintext, base64AesKey);

        System.out.println(" Encrypted  : " + encrypted);
        System.out.println("-".repeat(60));
        System.out.println(" SQL snippet:");
        System.out.println();
        System.out.println("   INSERT INTO FWB_MST_BANK_PGP_PRIVATE_KEY (");
        System.out.println("       KEY_NAME, KEY, VALID_FROM, VALID_TO,");
        System.out.println("       KEY_ACTIVE_FLAG, KEY_TYPE, PASSPHRASE)");
        System.out.println("   VALUES (");
        System.out.println("       'BANK_KEY_2026_Q1',");
        System.out.println("       decode('REPLACE_WITH_ENCRYPTED_KEY_BLOB_BASE64','base64'),");
        System.out.println("       '2026-01-01', '2026-12-31', 'Y', 'RSA-4096',");
        System.out.println("       '" + encrypted + "'");
        System.out.println("   );");
        System.out.println("=".repeat(60));

        // Round-trip check
        String decrypted   = decryptPassphrase(encrypted, base64AesKey);
        boolean ok         = plaintext.equals(decrypted);
        System.out.println(" Round-trip : " + (ok ? "✓ PASS" : "✗ FAIL"));
        System.out.println(" Decrypted  : " + decrypted);
        System.out.println("=".repeat(60));

        if (!ok) {
            throw new IllegalStateException("Round-trip failed: decrypted value does not match original");
        }
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Encrypts a plain-text passphrase and returns a Base64 string of
     * {@code IV (16 bytes) + ciphertext}, ready to store in the PASSPHRASE column.
     *
     * @param plainTextPassphrase passphrase to encrypt; must not be null or blank
     * @param base64AesKey        Base64-encoded 32-byte AES-256 key (crypto.key value)
     * @return Base64-encoded {@code IV + ciphertext}
     */
    public static String encryptPassphrase(String plainTextPassphrase, String base64AesKey) {
        if (plainTextPassphrase == null || plainTextPassphrase.isBlank()) {
            throw new IllegalArgumentException("Passphrase must not be null or blank");
        }
        byte[] plainBytes    = plainTextPassphrase.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBlob = encryptBytes(plainBytes, base64AesKey);
        return Base64.getEncoder().encodeToString(encryptedBlob);
    }

    /**
     * Decrypts a Base64-encoded {@code IV + ciphertext} string back to plain text.
     * Mirrors the decryption path in the service for round-trip verification.
     *
     * @param base64EncryptedPassphrase value stored in the PASSPHRASE column
     * @param base64AesKey              the same AES-256 key used to encrypt
     * @return the original plain-text passphrase
     */
    public static String decryptPassphrase(String base64EncryptedPassphrase, String base64AesKey) {
        byte[] combined   = Base64.getDecoder().decode(base64EncryptedPassphrase);

        // Split: first 16 bytes = IV, remainder = ciphertext
        byte[] iv         = Arrays.copyOfRange(combined, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(combined, 16, combined.length);

        byte[] plainBytes = performCipher(ciphertext, iv, base64AesKey, false);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    // ── Core encryption logic ────────────────────────────────────────────────

    /**
     * Mirrors {@code EncryptionServiceImpl.encryptBytes(byte[] aBytes)}.
     *
     * <ol>
     *   <li>Register BouncyCastle provider.</li>
     *   <li>Copy the static IV into a fresh 16-byte array.</li>
     *   <li>Encrypt via AES-256-CBC/PKCS7.</li>
     *   <li>Return {@code IV + ciphertext}.</li>
     * </ol>
     */
    private static byte[] encryptBytes(byte[] plainBytes, String base64AesKey) {

        // Step 2 — Register BouncyCastle (idempotent; safe to call multiple times)
        Security.addProvider(new BouncyCastleProvider());

        // Step 3 — Prepare IV: copy constant into a fresh working array
        byte[] ivData = new byte[16];
        System.arraycopy(INITIALIZATION_VECTOR, 0, ivData, 0, INITIALIZATION_VECTOR.length);

        // Steps 4-7 — AES-256-CBC/PKCS7 encryption
        byte[] ciphertext = performCipher(plainBytes, ivData, base64AesKey, true);

        // Step 8 — Prepend IV: [ IV (16 bytes) | ciphertext ]
        byte[] combined = new byte[ivData.length + ciphertext.length];
        System.arraycopy(ivData,     0, combined, 0,           ivData.length);
        System.arraycopy(ciphertext, 0, combined, ivData.length, ciphertext.length);
        return combined;
    }

    /**
     * AES-256-CBC cipher operation (encrypt or decrypt).
     *
     * <p>Mirrors {@code EncryptionServiceImpl.performEncryption(byte[], String)}.
     *
     * @param inputBytes  plaintext bytes (encrypt) or ciphertext bytes (decrypt)
     * @param ivData      16-byte initialization vector
     * @param base64AesKey Base64-encoded AES-256 key
     * @param forEncrypt  {@code true} = encrypt, {@code false} = decrypt
     * @return output bytes
     */
    private static byte[] performCipher(byte[] inputBytes,
                                        byte[] ivData,
                                        String base64AesKey,
                                        boolean forEncrypt) {
        try {
            // Step 4 — Configure cipher: AES / CBC / PKCS7
            PKCS7Padding padding = new PKCS7Padding();
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
                    CBCBlockCipher.newInstance(AESEngine.newInstance()), padding);

            // Step 5 — Decode the AES-256 key (must be exactly 32 bytes)
            byte[] keyBytes = decodeAndValidateKey(base64AesKey);
            KeyParameter keyParam = new KeyParameter(keyBytes);

            // Step 6 — Initialise cipher with key + IV
            CipherParameters params = new ParametersWithIV(keyParam, ivData);
            cipher.reset();
            cipher.init(forEncrypt, params);

            // Step 7 — Encrypt / decrypt the input
            int    bufLen     = cipher.getOutputSize(inputBytes.length);
            byte[] output     = new byte[bufLen];
            int    nBytes     = cipher.processBytes(inputBytes, 0, inputBytes.length, output, 0);
            nBytes           += cipher.doFinal(output, nBytes);

            // Trim to actual output length (PaddedBufferedBlockCipher may over-allocate)
            return (nBytes < output.length) ? Arrays.copyOf(output, nBytes) : output;

        } catch (IllegalArgumentException e) {
            // Re-throw key/IV decode errors with a clearer message
            throw new IllegalArgumentException(
                    "Failed to decode AES key — ensure it is a valid Base64 string "
                    + "that decodes to exactly 32 bytes: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new RuntimeException("AES-256-CBC cipher operation failed: " + e.getMessage(), e);
        }
    }

    // ── Key validation helper ────────────────────────────────────────────────

    /**
     * Base64-decodes the AES key and validates it is exactly 32 bytes (AES-256).
     *
     * <p>Uses {@link Base64#getMimeDecoder()} which tolerates whitespace and
     * lenient padding — consistent with how {@code crypto.key} values are
     * read from properties files in the bank's platform.
     *
     * @param base64AesKey Base64-encoded AES key string
     * @return decoded 32-byte key array
     * @throws IllegalArgumentException if the string is not valid Base64 or
     *                                  does not decode to exactly 32 bytes
     */
    static byte[] decodeAndValidateKey(String base64AesKey) {
        if (base64AesKey == null || base64AesKey.isBlank()) {
            throw new IllegalArgumentException("AES key must not be null or blank");
        }
        byte[] keyBytes;
        try {
            // getMimeDecoder() is lenient: handles whitespace and imperfect padding
            keyBytes = Base64.getMimeDecoder().decode(base64AesKey.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "AES key is not valid Base64: " + e.getMessage(), e);
        }
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException(
                    "AES key must decode to exactly 32 bytes (AES-256) but decoded to "
                    + keyBytes.length + " bytes. "
                    + "Check the crypto.key property value.");
        }
        return keyBytes;
    }
}
