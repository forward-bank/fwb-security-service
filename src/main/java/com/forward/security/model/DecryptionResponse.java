package com.forward.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Outbound message written to the IBM MQ response queue.
 *
 * Fields:
 *  - encryptedFilePath  : the original S3 key of the encrypted file (echoed from request).
 *  - decryptedFilePath  : S3 key where the decrypted plaintext was stored;
 *                         null when decryptionSuccessful=false.
 *  - decryptionSuccessful : true when decryption (and signature verification, if opted)
 *                           completed without errors.
 *  - errorCode          : short error code for failures; null on success.
 *  - errorMessage       : human-readable failure reason; null on success.
 */
public class DecryptionResponse {

    @JsonProperty("encryptedFilePath")
    private String encryptedFilePath;

    @JsonProperty("decryptedFilePath")
    private String decryptedFilePath;

    @JsonProperty("decryptionSuccessful")
    private boolean decryptionSuccessful;

    @JsonProperty("errorCode")
    private String errorCode;

    @JsonProperty("errorMessage")
    private String errorMessage;

    public DecryptionResponse() {}

    // ── Factory methods ───────────────────────────────────────────────────────

    public static DecryptionResponse success(String encryptedFilePath, String decryptedFilePath) {
        DecryptionResponse r = new DecryptionResponse();
        r.encryptedFilePath   = encryptedFilePath;
        r.decryptedFilePath   = decryptedFilePath;
        r.decryptionSuccessful = true;
        return r;
    }

    public static DecryptionResponse failure(String encryptedFilePath,
                                              String errorCode,
                                              String errorMessage) {
        DecryptionResponse r = new DecryptionResponse();
        r.encryptedFilePath   = encryptedFilePath;
        r.decryptedFilePath   = null;
        r.decryptionSuccessful = false;
        r.errorCode           = errorCode;
        r.errorMessage        = errorMessage;
        return r;
    }

    // ── Getters / setters ─────────────────────────────────────────────────────

    public String  getEncryptedFilePath()    { return encryptedFilePath; }
    public String  getDecryptedFilePath()    { return decryptedFilePath; }
    public boolean isDecryptionSuccessful()  { return decryptionSuccessful; }
    public String  getErrorCode()            { return errorCode; }
    public String  getErrorMessage()         { return errorMessage; }

    public void setEncryptedFilePath(String encryptedFilePath)     { this.encryptedFilePath = encryptedFilePath; }
    public void setDecryptedFilePath(String decryptedFilePath)     { this.decryptedFilePath = decryptedFilePath; }
    public void setDecryptionSuccessful(boolean decryptionSuccessful) { this.decryptionSuccessful = decryptionSuccessful; }
    public void setErrorCode(String errorCode)                     { this.errorCode = errorCode; }
    public void setErrorMessage(String errorMessage)               { this.errorMessage = errorMessage; }

    @Override
    public String toString() {
        return "DecryptionResponse{encryptedFilePath='" + encryptedFilePath
                + "', decryptedFilePath='" + decryptedFilePath
                + "', decryptionSuccessful=" + decryptionSuccessful
                + ", errorCode='" + errorCode
                + "', errorMessage='" + errorMessage + "'}";
    }
}
