package com.forward.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Inbound message received from {@code SECURITY.SERVICE.REQUEST.QUEUE}.
 *
 * <pre>
 * {
 *   "custId"           : 1001,
 *   "fileS3Path"       : "forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/I1234567890123.FWB.pain00800108.ABCD123.PM.pgp_12345145",
 *   "pgpSigningEnabled": false
 * }
 * </pre>
 *
 * <p>{@code custId} is the numeric customer identifier that maps to
 * {@code CUST_ID} in {@code FWB_MST_BANK_CUST_PGP_KEY_LINK}.
 *
 * <p>{@code fileS3Path} is the full S3 path (bucket + key) of the
 * PGP-encrypted payment file.
 *
 * <p>{@code pgpSigningEnabled} — when {@code true} the file was signed
 * by the customer and signature verification is performed after decryption.
 */
public class DecryptionRequest {

    @JsonProperty("custId")
    private Long custId;

    @JsonProperty("fileS3Path")
    private String fileS3Path;

    @JsonProperty("pgpSigningEnabled")
    private boolean pgpSigningEnabled;

    public DecryptionRequest() {}

    public DecryptionRequest(Long custId, String fileS3Path, boolean pgpSigningEnabled) {
        this.custId            = custId;
        this.fileS3Path        = fileS3Path;
        this.pgpSigningEnabled = pgpSigningEnabled;
    }

    public Long    getCustId()             { return custId; }
    public String  getFileS3Path()         { return fileS3Path; }
    public boolean isPgpSigningEnabled()   { return pgpSigningEnabled; }

    public void setCustId(Long custId)                        { this.custId = custId; }
    public void setFileS3Path(String fileS3Path)              { this.fileS3Path = fileS3Path; }
    public void setPgpSigningEnabled(boolean pgpSigningEnabled) { this.pgpSigningEnabled = pgpSigningEnabled; }

    @Override
    public String toString() {
        return "DecryptionRequest{custId=" + custId
                + ", fileS3Path='" + fileS3Path
                + "', pgpSigningEnabled=" + pgpSigningEnabled + '}';
    }
}
