package com.forward.security.service;

import com.forward.security.entity.CustomerKeyConfig;
import com.forward.security.model.DecryptionRequest;
import com.forward.security.model.DecryptionResponse;
import com.forward.security.pgp.PgpDecryptionResult;
import com.forward.security.pgp.PgpDecryptionService;
import com.forward.security.repository.CustomerKeyConfigRepository;
import com.forward.security.s3.S3StreamDownloader;
import com.forward.security.s3.S3Uploader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Base64;
import java.util.Optional;

/**
 * Orchestrates the end-to-end file decryption flow:
 *
 *  1. Validate the request fields.
 *  2. Look up the customer's key configuration (key S3 paths + passphrase) from the DB.
 *  3. Download the bank's private key bytes from S3.
 *  4. Download the customer's public key bytes from S3 (only when signing is enabled).
 *  5. Decode the Base64 passphrase.
 *  6. Open a streaming InputStream for the encrypted payment file.
 *  7. Invoke {@link PgpDecryptionService} to decrypt and optionally verify the signature.
 *  8. Upload the plaintext to S3 at the computed decrypted file path.
 *  9. Return a {@link DecryptionResponse}.
 *
 * The decrypted file is placed next to the encrypted file under a DECRYPTED sub-path.
 * For example:
 *   encrypted : FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/payment.xml.pgp
 *   decrypted : FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/DECRYPTED/payment.xml
 */
@Service
public class FileDecryptionOrchestrator {

    private final CustomerKeyConfigRepository keyConfigRepository;
    private final S3StreamDownloader          s3Downloader;
    private final S3Uploader                  s3Uploader;
    private final PgpDecryptionService        pgpDecryptionService;

    public FileDecryptionOrchestrator(CustomerKeyConfigRepository keyConfigRepository,
                                      S3StreamDownloader s3Downloader,
                                      S3Uploader s3Uploader,
                                      PgpDecryptionService pgpDecryptionService) {
        this.keyConfigRepository  = keyConfigRepository;
        this.s3Downloader         = s3Downloader;
        this.s3Uploader           = s3Uploader;
        this.pgpDecryptionService = pgpDecryptionService;
    }

    /**
     * Processes one decryption request end-to-end.
     *
     * @param request the inbound MQ message payload; never null.
     * @return a {@link DecryptionResponse} — always non-null.
     */
    public DecryptionResponse process(DecryptionRequest request) {

        // ── Step 1: input validation ──────────────────────────────────────────
        if (request.getCustomerId() == null || request.getCustomerId().isBlank()) {
            return DecryptionResponse.failure(null, "SSE_001", "customerId must not be null or blank");
        }
        if (request.getEncryptedFilePath() == null || request.getEncryptedFilePath().isBlank()) {
            return DecryptionResponse.failure(request.getEncryptedFilePath(),
                    "SSE_001", "encryptedFilePath must not be null or blank");
        }

        String customerId         = request.getCustomerId();
        String encryptedFilePath  = request.getEncryptedFilePath();
        boolean pgpSigningEnabled = request.isPgpSigningEnabled();

        // ── Step 2: load key configuration from DB ────────────────────────────
        Optional<CustomerKeyConfig> configOpt = keyConfigRepository.findById(customerId);
        if (configOpt.isEmpty()) {
            return DecryptionResponse.failure(encryptedFilePath, "SSE_009",
                    "No key configuration found for customer ID: " + customerId);
        }
        CustomerKeyConfig keyConfig = configOpt.get();

        // ── Step 3: download the bank's private key from S3 ──────────────────
        byte[] bankPrivateKeyBytes;
        try {
            bankPrivateKeyBytes = s3Downloader.downloadBytes(keyConfig.getBankPrivateKeyPath());
        } catch (S3StreamDownloader.S3DownloadException e) {
            return DecryptionResponse.failure(encryptedFilePath, "SSE_010",
                    "Failed to download bank private key from S3: " + e.getMessage());
        }

        // ── Step 4: download the customer's public key from S3 (if signing) ──
        byte[] customerPublicKeyBytes = null;
        if (pgpSigningEnabled) {
            try {
                customerPublicKeyBytes = s3Downloader.downloadBytes(keyConfig.getCustomerPublicKeyPath());
            } catch (S3StreamDownloader.S3DownloadException e) {
                return DecryptionResponse.failure(encryptedFilePath, "SSE_010",
                        "Failed to download customer public key from S3: " + e.getMessage());
            }
        }

        // ── Step 5: decode the Base64 passphrase ──────────────────────────────
        char[] passphraseChars;
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(keyConfig.getBankKeyPassphraseBase64());
            passphraseChars = new String(decodedBytes, java.nio.charset.StandardCharsets.UTF_8).toCharArray();
        } catch (IllegalArgumentException e) {
            return DecryptionResponse.failure(encryptedFilePath, "SSE_011",
                    "Bank key passphrase is not valid Base64: " + e.getMessage());
        }

        // ── Step 6: open a streaming InputStream for the encrypted file ───────
        InputStream encryptedStream = null;
        try {
            encryptedStream = s3Downloader.openStream(encryptedFilePath);

            // ── Step 7: PGP decryption + optional signature verification ──────
            PgpDecryptionResult pgpResult = pgpDecryptionService.decrypt(
                    encryptedStream,
                    bankPrivateKeyBytes,
                    passphraseChars,
                    customerPublicKeyBytes,
                    pgpSigningEnabled
            );

            if (!pgpResult.isSuccess()) {
                return DecryptionResponse.failure(encryptedFilePath,
                        pgpResult.getErrorCode(),
                        pgpResult.getErrorMessage());
            }

            // ── Step 8: upload the decrypted plaintext to S3 ─────────────────
            String decryptedFilePath = buildDecryptedFilePath(encryptedFilePath);
            try {
                s3Uploader.upload(decryptedFilePath, pgpResult.getPlaintext());
            } catch (S3Uploader.S3UploadException e) {
                return DecryptionResponse.failure(encryptedFilePath, "SSE_012",
                        "Failed to upload decrypted file to S3: " + e.getMessage());
            }

            // ── Step 9: return success ────────────────────────────────────────
            System.out.println("  [FileDecryptionOrchestrator] ✓ decryption complete"
                    + " | customerId=" + customerId
                    + " | signatureVerified=" + pgpResult.isSignatureVerified()
                    + " | decryptedPath=" + decryptedFilePath);

            return DecryptionResponse.success(encryptedFilePath, decryptedFilePath);

        } catch (S3StreamDownloader.S3DownloadException e) {
            return DecryptionResponse.failure(encryptedFilePath, "SSE_010",
                    "Failed to open encrypted file stream from S3: " + e.getMessage());
        } finally {
            // Always close the stream — the PGP engine reads lazily
            if (encryptedStream != null) {
                try {
                    encryptedStream.close();
                } catch (Exception ignored) {
                    // best effort
                }
            }
            // Zero out the passphrase from memory as soon as it is no longer needed
            if (passphraseChars != null) {
                java.util.Arrays.fill(passphraseChars, '\0');
            }
        }
    }

    // ── Path computation ──────────────────────────────────────────────────────

    /**
     * Derives the S3 key for the decrypted output file from the encrypted file path.
     *
     * Strategy:
     *  - Replace the path segment "INCOMING" with "DECRYPTED".
     *  - Strip the trailing ".pgp" or ".gpg" extension if present.
     *
     * Example:
     *   input  : FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/payment.xml.pgp
     *   output : FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/DECRYPTED/payment.xml
     */
    private String buildDecryptedFilePath(String encryptedFilePath) {
        String path = encryptedFilePath;

        // Replace INCOMING directory with DECRYPTED
        path = path.replace("/INCOMING/", "/DECRYPTED/");

        // Strip PGP file extension
        if (path.endsWith(".pgp")) {
            path = path.substring(0, path.length() - 4);
        } else if (path.endsWith(".gpg")) {
            path = path.substring(0, path.length() - 4);
        } else if (path.endsWith(".asc")) {
            path = path.substring(0, path.length() - 4);
        }

        return path;
    }
}
