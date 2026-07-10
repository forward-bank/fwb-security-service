package com.forward.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Inbound message received from the IBM MQ request queue.
 *
 * Fields:
 *  - customerId      : unique customer identifier; used to look up the customer's
 *                      public key in S3 (required for signature verification).
 *  - encryptedFilePath : bucket-relative S3 key of the PGP-encrypted payment file.
 *  - pgpSigningEnabled : true  → the file was signed by the customer; verify the signature.
 *                        false → the file is encrypted only; skip signature verification.
 */
public class DecryptionRequest {

    @JsonProperty("customerId")
    private String customerId;

    @JsonProperty("encryptedFilePath")
    private String encryptedFilePath;

    @JsonProperty("pgpSigningEnabled")
    private boolean pgpSigningEnabled;

    public DecryptionRequest() {}

    public DecryptionRequest(String customerId, String encryptedFilePath, boolean pgpSigningEnabled) {
        this.customerId         = customerId;
        this.encryptedFilePath  = encryptedFilePath;
        this.pgpSigningEnabled  = pgpSigningEnabled;
    }

    public String getCustomerId()          { return customerId; }
    public String getEncryptedFilePath()   { return encryptedFilePath; }
    public boolean isPgpSigningEnabled()   { return pgpSigningEnabled; }

    public void setCustomerId(String customerId)                  { this.customerId = customerId; }
    public void setEncryptedFilePath(String encryptedFilePath)    { this.encryptedFilePath = encryptedFilePath; }
    public void setPgpSigningEnabled(boolean pgpSigningEnabled)   { this.pgpSigningEnabled = pgpSigningEnabled; }

    @Override
    public String toString() {
        return "DecryptionRequest{customerId='" + customerId
                + "', encryptedFilePath='" + encryptedFilePath
                + "', pgpSigningEnabled=" + pgpSigningEnabled + '}';
    }
}
