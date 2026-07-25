package com.forward.security.service;

import com.forward.security.entity.BankPgpPrivateKey;
import com.forward.security.entity.CustomerPublicKey;
import com.forward.security.model.DecryptionRequest;
import com.forward.security.model.DecryptionResponse;
import com.forward.security.pgp.PgpDecryptionResult;
import com.forward.security.pgp.PgpDecryptionService;
import com.forward.security.repository.BankCustPgpKeyLinkRepository;
import com.forward.security.repository.CustomerPublicKeyRepository;
import com.forward.security.s3.S3StreamDownloader;
import com.forward.security.s3.S3Uploader;
import com.forward.security.util.PassphraseEncryptionUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Arrays;
import java.util.Optional;

/**
 * Orchestrates end-to-end PGP decryption of a customer payment file.
 *
 * <h2>DB lookup</h2>
 * Joins {@code FWB_MST_BANK_CUST_PGP_KEY_LINK} and
 * {@code FWB_MST_BANK_PGP_PRIVATE_KEY} on {@code BANK_KEY_SEQ} for the given
 * {@code CUST_ID} to obtain:
 * <ul>
 *   <li>The {@code BANK_PVT_KEY_S3_PATH} column — S3 path to the armored PGP
 *       private key file. The {@code KEY} BYTEA column is null; the key material
 *       is always fetched from S3 at runtime.</li>
 *   <li>The {@code PASSPHRASE} column, which holds the bank key passphrase
 *       AES-256-CBC encrypted (via {@link PassphraseEncryptionUtil}) and then
 *       Base64-encoded — NOT a plain Base64-encoded passphrase. It must be
 *       decrypted with {@code crypto.key} before use, not just Base64-decoded.</li>
 * </ul>
 *
 * <h2>Decrypted file path rule</h2>
 * Given an input {@code fileS3Path}:
 * <pre>
 *   forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/
 *       I1234567890123.FWB.pain00800108.ABCD123.PM.pgp_12345145
 * </pre>
 * The decrypted path is built by:
 * <ol>
 *   <li>Replace {@code /INCOMING/} with {@code /DECRYPTED/} in the directory part.</li>
 *   <li>Take the filename up to and including {@code .PM}, then append {@code .xml}.</li>
 * </ol>
 * Result:
 * <pre>
 *   forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/DECRYPTED/
 *       I1234567890123.FWB.pain00800108.ABCD123.PM.xml
 * </pre>
 */
@Service
public class FileDecryptionOrchestrator {

    private final BankCustPgpKeyLinkRepository keyLinkRepository;
    private final CustomerPublicKeyRepository  customerKeyRepository;
    private final S3StreamDownloader           s3Downloader;
    private final S3Uploader                   s3Uploader;
    private final PgpDecryptionService         pgpDecryptionService;
    private final String                       cryptoAesKey;

    public FileDecryptionOrchestrator(BankCustPgpKeyLinkRepository keyLinkRepository,
                                      CustomerPublicKeyRepository customerKeyRepository,
                                      S3StreamDownloader s3Downloader,
                                      S3Uploader s3Uploader,
                                      PgpDecryptionService pgpDecryptionService,
                                      @Value("${crypto.key}") String cryptoAesKey) {
        this.keyLinkRepository    = keyLinkRepository;
        this.customerKeyRepository = customerKeyRepository;
        this.s3Downloader          = s3Downloader;
        this.s3Uploader            = s3Uploader;
        this.pgpDecryptionService  = pgpDecryptionService;
        this.cryptoAesKey          = cryptoAesKey;
    }

    /**
     * Processes one decryption request end-to-end.
     *
     * @param request inbound MQ message payload; never null
     * @return {@link DecryptionResponse} — always non-null
     */
    public DecryptionResponse process(DecryptionRequest request) {

        // ── Step 1: input validation ──────────────────────────────────────────
        Long custId = request.getCustId();
        if (custId == null) {
            return DecryptionResponse.failure(null, "SSE_001",
                    "custId must not be null");
        }
        String fileS3Path = request.getFileS3Path();
        if (fileS3Path == null || fileS3Path.isBlank()) {
            return DecryptionResponse.failure(custId, "SSE_001",
                    "fileS3Path must not be null or blank");
        }
        boolean pgpSigningEnabled = request.isPgpSigningEnabled();

        System.out.println("  [FileDecryptionOrchestrator] processing"
                + " | custId=" + custId
                + " | fileS3Path=" + fileS3Path
                + " | pgpSigning=" + pgpSigningEnabled);

        // ── Step 2: join FWB_MST_BANK_CUST_PGP_KEY_LINK → FWB_MST_BANK_PGP_PRIVATE_KEY
        //           to get the active bank private key for this customer ────────
        Optional<BankPgpPrivateKey> bankKeyOpt =
                keyLinkRepository.findActiveBankKeyByCustId(custId);
        if (bankKeyOpt.isEmpty()) {
            return DecryptionResponse.failure(custId, "SSE_009",
                    "No active bank private key linked to customer ID: " + custId
                            + ". Check FWB_MST_BANK_CUST_PGP_KEY_LINK and FWB_MST_BANK_PGP_PRIVATE_KEY.");
        }
        BankPgpPrivateKey bankKey = bankKeyOpt.get();

        System.out.println("  [FileDecryptionOrchestrator] found bank key"
                + " | bankKeySeq=" + bankKey.getBankKeySeq()
                + " | keyName=" + bankKey.getKeyName());

        // ── Step 3: download the bank's PGP private key bytes from S3 ───────────
        //    The KEY column in FWB_MST_BANK_PGP_PRIVATE_KEY is null;
        //    the actual key material lives in S3 at BANK_PVT_KEY_S3_PATH.
        String bankPvtKeyS3Path = bankKey.getBankPvtKeyS3Path();
        if (bankPvtKeyS3Path == null || bankPvtKeyS3Path.isBlank()) {
            return DecryptionResponse.failure(custId, "SSE_009",
                    "BANK_PVT_KEY_S3_PATH is null or blank for bankKeySeq: "
                            + bankKey.getBankKeySeq() + ". Cannot locate private key in S3.");
        }

        byte[] bankPrivateKeyBytes;
        try {
            bankPrivateKeyBytes = s3Downloader.downloadBytes(bankPvtKeyS3Path);
            System.out.println("  [FileDecryptionOrchestrator] downloaded bank private key from S3"
                    + " | s3Path=" + bankPvtKeyS3Path
                    + " | bytes=" + bankPrivateKeyBytes.length);
        } catch (S3StreamDownloader.S3DownloadException e) {
            return DecryptionResponse.failure(custId, "SSE_010",
                    "Failed to download bank private key from S3 path '"
                            + bankPvtKeyS3Path + "': " + e.getMessage());
        }

        if (bankPrivateKeyBytes.length == 0) {
            return DecryptionResponse.failure(custId, "SSE_009",
                    "Bank private key downloaded from S3 is empty: " + bankPvtKeyS3Path);
        }

        // ── Step 4: download the customer's public key from S3 (signing only) ──
        byte[] customerPublicKeyBytes = null;
        if (pgpSigningEnabled) {
            Optional<CustomerPublicKey> custKeyOpt =
                    customerKeyRepository.findFirstByCustIdAndKeyActiveFlag(custId, "Y");
            if (custKeyOpt.isEmpty()) {
                return DecryptionResponse.failure(custId, "SSE_009",
                        "No active public key found for customer ID: " + custId);
            }
            CustomerPublicKey custKey = custKeyOpt.get();
            try {
                customerPublicKeyBytes = s3Downloader.downloadBytes(custKey.getCustPubKeyS3Path());
            } catch (S3StreamDownloader.S3DownloadException e) {
                return DecryptionResponse.failure(custId, "SSE_010",
                        "Failed to download customer public key from S3: " + e.getMessage());
            }
        }

        // ── Step 5: decrypt the AES-256-CBC-encrypted, Base64-wrapped passphrase ─
        char[] passphraseChars = null;
        try {
            String decryptedPassphrase = PassphraseEncryptionUtil.decryptPassphrase(
                    bankKey.getPassphrase().trim(), cryptoAesKey);
            passphraseChars = decryptedPassphrase.toCharArray();
        } catch (IllegalArgumentException e) {
            return DecryptionResponse.failure(custId, "SSE_011",
                    "Bank key passphrase is not valid Base64 or the AES key is invalid: "
                            + e.getMessage());
        } catch (Exception e) {
            return DecryptionResponse.failure(custId, "SSE_011",
                    "Failed to decrypt bank key passphrase: " + e.getMessage());
        }

        // ── Step 6: stream the encrypted file from S3 and decrypt ─────────────
        InputStream encryptedStream = null;
        try {
            encryptedStream = s3Downloader.openStream(fileS3Path);

            PgpDecryptionResult pgpResult = pgpDecryptionService.decrypt(
                    encryptedStream,
                    bankPrivateKeyBytes,
                    passphraseChars,
                    customerPublicKeyBytes,
                    pgpSigningEnabled);

            if (!pgpResult.isSuccess()) {
                return DecryptionResponse.failure(custId,
                        pgpResult.getErrorCode(),
                        pgpResult.getErrorMessage());
            }

            // ── Step 7: build decrypted S3 path and upload ────────────────────
            String decryptedFilePath = buildDecryptedFilePath(fileS3Path);

            try {
                s3Uploader.upload(decryptedFilePath, pgpResult.getPlaintext());
            } catch (S3Uploader.S3UploadException e) {
                return DecryptionResponse.failure(custId, "SSE_012",
                        "Failed to upload decrypted file to S3: " + e.getMessage());
            }

            System.out.println("  [FileDecryptionOrchestrator] ✓ decryption complete"
                    + " | custId=" + custId
                    + " | bankKeySeq=" + bankKey.getBankKeySeq()
                    + " | signatureVerified=" + pgpResult.isSignatureVerified()
                    + " | decryptedPath=" + decryptedFilePath);

            return DecryptionResponse.success(custId, decryptedFilePath);

        } catch (S3StreamDownloader.S3DownloadException e) {
            return DecryptionResponse.failure(custId, "SSE_010",
                    "Failed to open encrypted file stream from S3: " + e.getMessage());
        } finally {
            if (encryptedStream != null) {
                try { encryptedStream.close(); } catch (Exception ignored) {}
            }
            // Zero out passphrase bytes from memory immediately after use
            if (passphraseChars != null) {
                Arrays.fill(passphraseChars, '\0');
            }
        }
    }

    // ── Decrypted file path computation ───────────────────────────────────────

    /**
     * Builds the S3 path for the decrypted output file.
     *
     * <p>Rules:
     * <ol>
     *   <li>Replace {@code /INCOMING/} with {@code /DECRYPTED/} in the path.</li>
     *   <li>Take the filename up to and including the {@code .PM} segment, then
     *       append {@code .xml} — discarding everything after {@code .PM}.</li>
     * </ol>
     *
     * <p>Examples:
     * <pre>
     *   Input : forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/I1234567890123.FWB.pain00800108.ABCD123.PM.pgp_12345145
     *   Output: forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/DECRYPTED/I1234567890123.FWB.pain00800108.ABCD123.PM.xml
     *
     *   Input : forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/I9876543210987.FWB.pain00800108.XYZ999.PM.pgp
     *   Output: forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/DECRYPTED/I9876543210987.FWB.pain00800108.XYZ999.PM.xml
     * </pre>
     *
     * @param fileS3Path full S3 path of the encrypted file (bucket + key)
     * @return full S3 path for the decrypted file
     * @throws IllegalArgumentException if the path does not contain {@code .PM}
     */
    static String buildDecryptedFilePath(String fileS3Path) {
        // 1. Replace /INCOMING/ with /DECRYPTED/ (directory segment only)
        String path = fileS3Path.replace("/INCOMING/", "/DECRYPTED/");

        // 2. Split directory from filename
        int lastSlash = path.lastIndexOf('/');
        String directory = (lastSlash >= 0) ? path.substring(0, lastSlash + 1) : "";
        String filename  = (lastSlash >= 0) ? path.substring(lastSlash + 1)    : path;

        // 3. Trim filename to everything up to and including ".PM"
        //    The marker is ".PM" followed by either "." or end-of-string.
        //    We search for ".PM" and take the portion up to and including it.
        int pmIndex = filename.indexOf(".PM.");
        if (pmIndex == -1) {
            // Handle case where .PM is the very end of the filename (no trailing dot)
            if (filename.endsWith(".PM")) {
                pmIndex = filename.length() - 3;
            } else {
                throw new IllegalArgumentException(
                        "Cannot build decrypted file path: '.PM' marker not found in filename '"
                                + filename + "' (full path: " + fileS3Path + ")");
            }
        }

        // Keep everything up to and including ".PM"
        String decryptedFilename = filename.substring(0, pmIndex + 3) + ".xml";

        return directory + decryptedFilename;
    }
}