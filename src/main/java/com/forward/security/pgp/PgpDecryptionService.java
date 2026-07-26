package com.forward.security.pgp;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.springframework.stereotype.Service;

import java.io.*;
import java.util.Iterator;

/**
 * PGP decryption and (optional) signature verification using the Bouncy Castle library.
 *
 * Two modes are supported:
 *
 *  1. Encryption only (pgpSigningEnabled = false)
 *     The encrypted stream contains a single literal-data packet.
 *     The bank's private key is used to decrypt; no signature is expected.
 *
 *  2. Encryption + signing (pgpSigningEnabled = true)
 *     The encrypted stream wraps a signed-data structure (one-pass signature + literal data).
 *     The bank's private key decrypts the outer envelope, then the customer's public key
 *     is used to verify the embedded signature.
 *
 * Both modes support ASCII-armored and binary PGP files.
 * The encrypted file is consumed as a streaming {@link InputStream} — it is never
 * fully loaded into memory at once.
 *
 * Error codes produced:
 *  SSE_001 — input validation failure (null/empty arguments)
 *  SSE_002 — no matching private key found in the bank's secret key ring
 *  SSE_003 — wrong passphrase / unable to extract private key
 *  SSE_004 — PGP data integrity check failed
 *  SSE_005 — signature verification failed (bad signature or wrong public key)
 *  SSE_006 — signature packet missing from a signed message
 *  SSE_007 — IO error reading encrypted stream
 *  SSE_008 — unexpected PGP structure (unsupported packet type or format)
 *  SSE_INTERNAL_ERROR — unexpected runtime exception
 */
@Service
public class PgpDecryptionService {

    /**
     * Decrypts a PGP-encrypted payment file and optionally verifies its signature.
     *
     * @param encryptedStream   streaming content of the PGP-encrypted file; the caller
     *                          retains responsibility for closing this stream.
     * @param bankPrivateKeyBytes  armored (.asc) or binary PGP secret key ring for the bank.
     * @param passphraseChars      plaintext passphrase characters for the bank's private key.
     * @param customerPublicKeyBytes armored or binary PGP public key for the customer;
     *                               required only when {@code pgpSigningEnabled} is true.
     * @param pgpSigningEnabled    when true, signature verification is performed after
     *                             decryption; the decryption fails if the signature is
     *                             absent or invalid.
     * @return {@link PgpDecryptionResult} — never null.
     */
    public PgpDecryptionResult decrypt(InputStream   encryptedStream,
                                       byte[]        bankPrivateKeyBytes,
                                       char[]        passphraseChars,
                                       byte[]        customerPublicKeyBytes,
                                       boolean       pgpSigningEnabled) {

        // ── Input validation ──────────────────────────────────────────────────
        if (encryptedStream == null) {
            return PgpDecryptionResult.failure("SSE_001", "Encrypted input stream must not be null");
        }
        if (bankPrivateKeyBytes == null || bankPrivateKeyBytes.length == 0) {
            return PgpDecryptionResult.failure("SSE_001", "Bank private key bytes must not be null or empty");
        }
        if (passphraseChars == null) {
            return PgpDecryptionResult.failure("SSE_001", "Bank key passphrase must not be null");
        }
        if (pgpSigningEnabled && (customerPublicKeyBytes == null || customerPublicKeyBytes.length == 0)) {
            return PgpDecryptionResult.failure("SSE_001",
                    "Customer public key is required when PGP signing is enabled");
        }

        try {
            // Load the bank's secret key collection
            PGPSecretKeyRingCollection secretKeyRings = loadSecretKeyRingCollection(bankPrivateKeyBytes);

            // De-armor the encrypted input — handles both armored and binary transparently
            InputStream decodedStream = PGPUtil.getDecoderStream(
                    new BufferedInputStream(encryptedStream));

            PGPObjectFactory objectFactory = new PGPObjectFactory(
                    decodedStream, new BcKeyFingerprintCalculator());

            // The outermost object should be an encrypted-data list
            Object firstObject = objectFactory.nextObject();
            if (firstObject == null) {
                return PgpDecryptionResult.failure("SSE_008",
                        "Empty or unrecognisable PGP stream — no objects found");
            }

            // Skip past any PGPMarker packets (RFC 4880 §5.8)
            if (firstObject instanceof PGPMarker) {
                firstObject = objectFactory.nextObject();
            }

            if (!(firstObject instanceof PGPEncryptedDataList encryptedDataList)) {
                return PgpDecryptionResult.failure("SSE_008",
                        "Expected PGP encrypted data list but found: "
                                + firstObject.getClass().getSimpleName());
            }

            // ── Find matching decryption key ──────────────────────────────────
            PGPPublicKeyEncryptedData encryptedData = null;
            PGPPrivateKey             privateKey    = null;

            Iterator<PGPEncryptedData> it = encryptedDataList.getEncryptedDataObjects();
            while (it.hasNext()) {
                PGPEncryptedData encData = it.next();
                if (!(encData instanceof PGPPublicKeyEncryptedData pkEncData)) {
                    continue;
                }
                long keyId = pkEncData.getKeyID();
                PGPSecretKey secretKey = secretKeyRings.getSecretKey(keyId);
                if (secretKey == null) {
                    continue; // not our key — try next recipient sub-packet
                }
                try {
                    privateKey = secretKey.extractPrivateKey(
                            new BcPBESecretKeyDecryptorBuilder(
                                    new BcPGPDigestCalculatorProvider())
                                    .build(passphraseChars));
                } catch (PGPException e) {
                    return PgpDecryptionResult.failure("SSE_003",
                            "Failed to extract bank private key (wrong passphrase?): " + e.getMessage());
                }
                encryptedData = pkEncData;
                break;
            }

            if (privateKey == null || encryptedData == null) {
                return PgpDecryptionResult.failure("SSE_002",
                        "No matching bank private key found for any recipient in the encrypted file");
            }

            // ── Decrypt the payload ────────────────────────────────────────────
            InputStream decryptedStream;
            try {
                decryptedStream = encryptedData.getDataStream(
                        new BcPublicKeyDataDecryptorFactory(privateKey));
            } catch (PGPException e) {
                return PgpDecryptionResult.failure("SSE_003",
                        "Decryption failed — unable to open decrypted data stream: " + e.getMessage());
            }

            PGPObjectFactory plainFactory = new PGPObjectFactory(
                    decryptedStream, new BcKeyFingerprintCalculator());

            // ── Dispatch to signed or unsigned decryption path ────────────────
            PgpDecryptionResult result;
            if (pgpSigningEnabled) {
                result = decryptSigned(plainFactory, customerPublicKeyBytes);
            } else {
                result = decryptUnsigned(plainFactory);
            }

            if (!result.isSuccess()) {
                return result;
            }

            // ── Verify PGP integrity protection (MDC) ─────────────────────────
            try {
                if (encryptedData.isIntegrityProtected() && !encryptedData.verify()) {
                    return PgpDecryptionResult.failure("SSE_004",
                            "PGP message integrity check (MDC) failed — data may have been tampered with");
                }
            } catch (PGPException e) {
                return PgpDecryptionResult.failure("SSE_004",
                        "PGP integrity check error: " + e.getMessage());
            }

            return result;

        } catch (IOException e) {
            return PgpDecryptionResult.failure("SSE_007",
                    "IO error reading encrypted stream: " + e.getMessage());
        } catch (PGPException e) {
            return PgpDecryptionResult.failure("SSE_008",
                    "PGP processing error: " + e.getMessage());
        } catch (Exception e) {
            return PgpDecryptionResult.failure("SSE_INTERNAL_ERROR",
                    "Unexpected error during PGP decryption: " + e.getMessage());
        }
    }

    // ── Signed decryption path ────────────────────────────────────────────────

    /**
     * Handles a signed-then-encrypted message.
     *
     * Expected structure inside the decrypted stream:
     *   PGPOnePassSignatureList  — begins the signature verification
     *   PGPLiteralData           — contains the plaintext bytes
     *   PGPSignatureList         — completes and verifies the signature
     */
    private PgpDecryptionResult decryptSigned(PGPObjectFactory plainFactory,
                                              byte[] customerPublicKeyBytes)
            throws IOException, PGPException {

        Object obj = plainFactory.nextObject();
        if (obj == null) {
            return PgpDecryptionResult.failure("SSE_008",
                    "Empty decrypted stream — no PGP objects found");
        }

        // ── One-pass signature header ─────────────────────────────────────────
        if (!(obj instanceof PGPOnePassSignatureList opsList) || opsList.isEmpty()) {
            return PgpDecryptionResult.failure("SSE_006",
                    "Expected one-pass signature list in signed message but found: "
                            + obj.getClass().getSimpleName());
        }

        PGPOnePassSignature onePassSig = opsList.get(0);

        // Load the customer's public key ring to find the signer key
        PGPPublicKeyRingCollection publicKeyRings = loadPublicKeyRingCollection(customerPublicKeyBytes);
        PGPPublicKey signerPublicKey;
        try {
            signerPublicKey = publicKeyRings.getPublicKey(onePassSig.getKeyID());
        } catch (Exception e) {
            return PgpDecryptionResult.failure("SSE_005",
                    "Failed to look up customer public key for key ID 0x"
                            + Long.toHexString(onePassSig.getKeyID())
                            + ": " + e.getMessage());
        }

        if (signerPublicKey == null) {
            return PgpDecryptionResult.failure("SSE_005",
                    "Customer public key not found for key ID 0x"
                            + Long.toHexString(onePassSig.getKeyID())
                            + " — cannot verify signature");
        }

        onePassSig.init(new BcPGPContentVerifierBuilderProvider(), signerPublicKey);

        // ── Literal data (plaintext) ──────────────────────────────────────────
        obj = plainFactory.nextObject();
        if (!(obj instanceof PGPLiteralData literalData)) {
            return PgpDecryptionResult.failure("SSE_008",
                    "Expected literal data after one-pass signature but found: "
                            + (obj != null ? obj.getClass().getSimpleName() : "null"));
        }

        byte[] plaintext = readAndUpdateSignature(literalData.getInputStream(), onePassSig);

        // ── Trailing signature ────────────────────────────────────────────────
        obj = plainFactory.nextObject();
        if (!(obj instanceof PGPSignatureList sigList) || sigList.isEmpty()) {
            return PgpDecryptionResult.failure("SSE_006",
                    "Signature packet missing or empty at end of signed message");
        }

        PGPSignature signature = sigList.get(0);
        boolean signatureValid;
        try {
            // IMPORTANT: verify against the one-pass signature object that accumulated
            // the hash via update() above — NOT signature.verify(), which would require
            // `signature` itself to have been init()'d and fed data (it never was, and
            // calling it directly throws an NPE on the internal, never-initialized
            // output stream).
            signatureValid = onePassSig.verify(signature);
        } catch (Exception e) {
            return PgpDecryptionResult.failure("SSE_005",
                    "Signature verification threw an exception: " + e.getMessage());
        }

        if (!signatureValid) {
            return PgpDecryptionResult.failure("SSE_005",
                    "PGP signature verification failed — file may have been tampered with "
                            + "or signed with an unregistered key");
        }
        System.out.println("  [PgpDecryptionService] ✓ signature verified successfully");
        return PgpDecryptionResult.success(plaintext, true);
    }

    // ── Unsigned (encryption only) path ──────────────────────────────────────

    /**
     * Handles an encrypt-only (no signature) message.
     *
     * Expected structure: PGPLiteralData (possibly wrapped in PGPCompressedData)
     */
    private PgpDecryptionResult decryptUnsigned(PGPObjectFactory plainFactory)
            throws IOException, PGPException {

        Object obj = plainFactory.nextObject();
        if (obj == null) {
            return PgpDecryptionResult.failure("SSE_008",
                    "Empty decrypted stream — no PGP objects found");
        }

        // Unwrap optional compression layer
        if (obj instanceof PGPCompressedData compressedData) {
            plainFactory = new PGPObjectFactory(
                    compressedData.getDataStream(), new BcKeyFingerprintCalculator());
            obj = plainFactory.nextObject();
        }

        if (!(obj instanceof PGPLiteralData literalData)) {
            return PgpDecryptionResult.failure("SSE_008",
                    "Expected literal data in encrypted message but found: "
                            + (obj != null ? obj.getClass().getSimpleName() : "null"));
        }

        byte[] plaintext = literalData.getInputStream().readAllBytes();
        return PgpDecryptionResult.success(plaintext, false);
    }

    // ── Key loading helpers ───────────────────────────────────────────────────

    /**
     * Loads a PGP secret key ring collection from armored or binary bytes.
     */
    private PGPSecretKeyRingCollection loadSecretKeyRingCollection(byte[] keyBytes)
            throws IOException, PGPException {
        InputStream keyStream = dearmour(new ByteArrayInputStream(keyBytes));
        return new PGPSecretKeyRingCollection(keyStream, new BcKeyFingerprintCalculator());
    }

    /**
     * Loads a PGP public key ring collection from armored or binary bytes.
     */
    private PGPPublicKeyRingCollection loadPublicKeyRingCollection(byte[] keyBytes)
            throws IOException, PGPException {
        InputStream keyStream = dearmour(new ByteArrayInputStream(keyBytes));
        return new PGPPublicKeyRingCollection(keyStream, new BcKeyFingerprintCalculator());
    }

    /**
     * Wraps the stream in an {@link ArmoredInputStream} if it appears to be ASCII-armored
     * (starts with "-----"), otherwise returns the original stream unchanged.
     * This makes the service tolerant of both .asc and binary .gpg key files.
     */
    private InputStream dearmour(InputStream raw) throws IOException {
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

    /**
     * Reads all bytes from {@code in} while feeding each chunk to the one-pass signature
     * updater so the signature can be verified after the stream is exhausted.
     */
    private byte[] readAndUpdateSignature(InputStream in,
                                          PGPOnePassSignature onePassSig)
            throws IOException, PGPException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        while ((n = in.read(chunk)) >= 0) {
            onePassSig.update(chunk, 0, n);
            buffer.write(chunk, 0, n);
        }
        return buffer.toByteArray();
    }
}