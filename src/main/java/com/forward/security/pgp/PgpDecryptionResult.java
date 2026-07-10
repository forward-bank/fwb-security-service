package com.forward.security.pgp;

/**
 * Immutable result returned by {@link PgpDecryptionService}.
 *
 * On success: plaintext bytes are present, signatureVerified reflects whether
 * signature verification was attempted and passed.
 *
 * On failure: plaintext is null, errorCode and errorMessage describe the cause.
 */
public final class PgpDecryptionResult {

    private final boolean  success;
    private final byte[]   plaintext;
    private final boolean  signatureVerified;
    private final String   errorCode;
    private final String   errorMessage;

    private PgpDecryptionResult(boolean success,
                                byte[] plaintext,
                                boolean signatureVerified,
                                String errorCode,
                                String errorMessage) {
        this.success           = success;
        this.plaintext         = plaintext;
        this.signatureVerified = signatureVerified;
        this.errorCode         = errorCode;
        this.errorMessage      = errorMessage;
    }

    // ── Factory methods ───────────────────────────────────────────────────────

    /**
     * Decryption succeeded (signature verified when signing was enabled).
     */
    public static PgpDecryptionResult success(byte[] plaintext, boolean signatureVerified) {
        return new PgpDecryptionResult(true, plaintext, signatureVerified, null, null);
    }

    /**
     * Decryption or signature verification failed.
     */
    public static PgpDecryptionResult failure(String errorCode, String errorMessage) {
        return new PgpDecryptionResult(false, null, false, errorCode, errorMessage);
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public boolean  isSuccess()            { return success; }
    public byte[]   getPlaintext()         { return plaintext; }
    public boolean  isSignatureVerified()  { return signatureVerified; }
    public String   getErrorCode()         { return errorCode; }
    public String   getErrorMessage()      { return errorMessage; }

    @Override
    public String toString() {
        return "PgpDecryptionResult{success=" + success
                + ", signatureVerified=" + signatureVerified
                + ", errorCode='" + errorCode + "'}";
    }
}
