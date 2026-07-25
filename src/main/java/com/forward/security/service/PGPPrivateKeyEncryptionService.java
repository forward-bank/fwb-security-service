package com.forward.security.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Encrypts the exported bank PGP private key (.asc) for storage as a
 * Postgres BLOB and/or S3 object, using only javax.crypto — no AWS SDK,
 * no KMS. Suitable for local dev now; swap the key-derivation step for
 * KMS/Vault later without touching the DB schema or S3 layout, since
 * both just store an opaque byte[].
 *
 * Master secret (MASTER_KEY_SECRET below) must be:
 *   - at least 32 random bytes worth of entropy (a long random string,
 *     not a dictionary passphrase)
 *   - supplied via env var / external config, never committed to source
 *   - the SAME value across app restarts, or previously-encrypted blobs
 *     become undecryptable
 *
 * Stored blob layout:
 *   [16 bytes: PBKDF2 salt]
 *   [12 bytes: GCM IV]
 *   [ciphertext + 16-byte GCM tag appended by the cipher]
 *
 * A fresh random salt is used on every encrypt call (even for the same
 * master secret), which means the derived AES key differs per call too
 * — this is what makes the scheme non-deterministic without needing a
 * KMS-issued data key.
 */
@Service
public class PGPPrivateKeyEncryptionService {

    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 210_000; // OWASP 2023+ minimum for PBKDF2-HMAC-SHA256
    private static final int KEY_LEN_BITS = 256;

    // Load from env var / Vault / application.yml — e.g.
    // security.bank-key.master-secret: ${BANK_KEY_MASTER_SECRET}
    @Value("${security.bank-key.master-secret}")
    private String masterSecret;

    private final SecureRandom secureRandom = new SecureRandom();

    public byte[] encrypt(byte[] plaintext) {
        try {
            byte[] salt = new byte[SALT_LEN];
            secureRandom.nextBytes(salt);
            SecretKey key = deriveKey(salt);

            byte[] iv = new byte[IV_LEN];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);

            return ByteBuffer.allocate(SALT_LEN + IV_LEN + ciphertext.length)
                    .put(salt)
                    .put(iv)
                    .put(ciphertext)
                    .array();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt bank private key", e);
        }
    }

    public byte[] decrypt(byte[] blob) {
        try {
            ByteBuffer buf = ByteBuffer.wrap(blob);
            byte[] salt = new byte[SALT_LEN];
            buf.get(salt);
            byte[] iv = new byte[IV_LEN];
            buf.get(iv);
            byte[] ciphertext = new byte[buf.remaining()];
            buf.get(ciphertext);

            SecretKey key = deriveKey(salt);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            // Deliberately vague — don't leak whether it was a bad key,
            // tampered ciphertext, or corrupt data to a caller/log that
            // might be less trusted than this service.
            throw new IllegalStateException("Failed to decrypt bank private key");
        }
    }

    /**
     * Derives a 256-bit AES key from {@link #masterSecret} + the given salt
     * via PBKDF2-HMAC-SHA256.
     *
     * IMPORTANT — determinism: this is a pure function. Same masterSecret +
     * same salt + same iteration count + same output length ALWAYS produces
     * the exact same 32 key bytes. There is no randomness inside this method
     * itself; all the randomness lives in whoever generates the salt before
     * calling it. Concretely, in this class:
     *   - encrypt() generates a FRESH random salt on every call, so two
     *     encrypt() calls on the same plaintext derive two different keys
     *     and produce two different ciphertexts. This is intentional — it's
     *     what makes the scheme non-deterministic without a KMS-issued
     *     fresh data key each time.
     *   - decrypt() does NOT generate a salt; it reads the salt back out of
     *     the stored blob (the same bytes encrypt() packed in) and passes
     *     that into deriveKey(). Same salt + same masterSecret reproduces
     *     the IDENTICAL key bytes used to encrypt that blob — this is why
     *     the salt has to be stored alongside the ciphertext rather than
     *     discarded: without it there'd be no way to reconstruct the key.
     *   - Each call still returns a distinct SecretKeySpec object (so `==`
     *     is always false between two calls), but SecretKeySpec.equals()
     *     compares the underlying bytes, so two keys derived from the same
     *     salt+secret are `.equals()` even though they're different objects.
     *
     * Step by step:
     *
     * 1. PBEKeySpec spec = new PBEKeySpec(masterSecret.toCharArray(), salt,
     *    PBKDF2_ITERATIONS, KEY_LEN_BITS);
     *    Just a parameter bundle — doesn't derive anything itself, it
     *    packages up what the derivation function needs:
     *      - masterSecret.toCharArray(): the password as char[] rather than
     *        String, because a char[] can be forcibly zeroed when done with
     *        it; a String is immutable/interned and can't be wiped.
     *      - salt: makes the derivation "salted" — the same masterSecret
     *        run through PBKDF2 twice with two different salts produces two
     *        completely different keys. Defeats precomputed dictionary
     *        attacks and ensures encrypting the same plaintext twice never
     *        yields the same ciphertext.
     *      - PBKDF2_ITERATIONS (210,000): how many times the internal HMAC
     *        is chained. This is the "slow it down on purpose" knob that
     *        makes brute-forcing masterSecret computationally expensive.
     *      - KEY_LEN_BITS (256): PBKDF2 is a generic key-stretching
     *        function, so you tell it how many output bits you want.
     *
     * 2. SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
     *    The JCE "engine class" that turns a KeySpec into an actual
     *    SecretKey. The algorithm string says PBKDF2 using HMAC-SHA256 as
     *    its internal pseudorandom function — each of the 210,000
     *    iterations above is one HMAC-SHA256 operation. Resolved against
     *    whatever JCE provider is registered (SunJCE by default in the JDK).
     *
     * 3. byte[] keyBytes = factory.generateSecret(spec).getEncoded();
     *    Where the actual work happens: repeatedly HMACs the password
     *    against the salt 210,000 times, producing a pseudorandom output
     *    sized to 256 bits. generateSecret(spec) returns a SecretKey;
     *    getEncoded() pulls out the raw 32 bytes.
     *
     * 4. return new SecretKeySpec(keyBytes, "AES");
     *    SecretKeySpec is the simplest SecretKey implementation — wraps raw
     *    bytes plus an algorithm label. The "AES" label isn't cryptographic,
     *    it's metadata telling Cipher.init() later "interpret these 32
     *    bytes as an AES key."
     *
     * 5. finally { Arrays.fill(keyBytes, (byte) 0); }
     *    Intent: scrub the raw key bytes from the heap as soon as we're
     *    done with the local array, so a later heap dump doesn't turn it up.
     *
     *    KNOWN LIMITATION — this doesn't fully work: SecretKeySpec's
     *    constructor calls key.clone() internally, so by the time we zero
     *    out keyBytes here, the SecretKeySpec object we're returning
     *    already holds its OWN independent copy of those same 32 bytes,
     *    unaffected by this Arrays.fill. This finally block only wipes the
     *    now-redundant local array, not the copy actually used by the
     *    cipher afterwards — and that copy sits in memory for as long as
     *    the SecretKey object is alive, with no guaranteed zeroing on GC.
     *    This is a general gap in plain JCE, not a bug specific to this
     *    method — the standard library gives no real way to guarantee key
     *    material is wiped from the JVM heap. If that matters for PCI-DSS
     *    scope, treat it as an accepted residual risk (common in practice
     *    for JCE-based systems), or move key handling to something built
     *    for secure memory (libsodium bindings, HSM/KMS where key material
     *    never enters this process's heap at all).
     */
    private SecretKey deriveKey(byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(
                masterSecret.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LEN_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        try {
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    public static void main(String[] args) throws Exception {
        PGPPrivateKeyEncryptionService svc = new PGPPrivateKeyEncryptionService();
        svc.masterSecret = "replace-with-a-long-random-value-from-env-var";

        // File lives at src/main/resources/keys/..., so at runtime (IDE run
        // from source, or a built jar) it's on the classpath as
        // "keys/Forward_Bank_Cert32891_0xD7FF763288E575FD_SECRET.asc" — NOT
        // as a filesystem path. Use the classloader to load it, not
        // Files.readAllBytes(Path.of("src/main/resources/...")), which only
        // works by accident when your working directory happens to be the
        // project root and breaks the moment this runs from a packaged jar.
        String resourcePath = "keys/bank/private/Forward_Bank_0x7C56E1A820421C1D_SECRET.asc";
        byte[] realAsc;
        try (java.io.InputStream in = PGPPrivateKeyEncryptionService.class
                .getClassLoader()
                .getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IllegalStateException(
                        "Resource not found on classpath: " + resourcePath
                                + " — check it's under src/main/resources/keys/ and the build has run at least once");
            }
            realAsc = in.readAllBytes();
        }
        // log time it took to encrypt and decrypt, to verify PBKDF2 isn't too slow for a user-facing request
        long start = System.currentTimeMillis();
        byte[] encrypted = svc.encrypt(realAsc);
        long encryptTime = System.currentTimeMillis() - start;
        System.out.println("Encrypt time: " + encryptTime + " ms");
        // log time it took to decrypt, to verify PBKDF2 isn't too slow for a user-facing request
        start = System.currentTimeMillis();
        byte[] decrypted = svc.decrypt(encrypted);
        // log time it took to decrypt, to verify PBKDF2 isn't too slow for a user-facing request
        long decryptTime = System.currentTimeMillis() - start;
        System.out.println("Decrypt time: " + decryptTime + " ms");
        System.out.println("Round-trip OK: " + Arrays.equals(realAsc, decrypted));
        System.out.println("Original size: " + realAsc.length + " bytes");
        System.out.println("Encrypted (stored) blob size: " + encrypted.length + " bytes");
        System.out.println("Encrypted blob (base64): "
                + java.util.Base64.getEncoder().encodeToString(encrypted));
    }
}