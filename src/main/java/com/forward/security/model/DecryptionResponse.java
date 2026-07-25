package com.forward.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Outbound message written to {@code SECURITY.SERVICE.RESPONSE.QUEUE}.
 *
 * <p>Success:
 * <pre>
 * {
 *   "custId"            : 1001,
 *   "decrypted"         : true,
 *   "decryptedFilePath" : "forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/DECRYPTED/I1234567890123.FWB.pain00800108.ABCD123.PM.xml"
 * }
 * </pre>
 *
 * <p>Failure:
 * <pre>
 * {
 *   "custId"            : 1001,
 *   "decrypted"         : false,
 *   "decryptedFilePath" : "",
 *   "errorCode"         : "SSE_002",
 *   "errorMessage"      : "No matching bank private key found ..."
 * }
 * </pre>
 */
public class DecryptionResponse {

    @JsonProperty("custId")
    private Long custId;

    @JsonProperty("decrypted")
    private boolean decrypted;

    @JsonProperty("decryptedFilePath")
    private String decryptedFilePath;

    @JsonProperty("errorCode")
    private String errorCode;

    @JsonProperty("errorMessage")
    private String errorMessage;

    public DecryptionResponse() {}

    // ── Factory methods ───────────────────────────────────────────────────────

    public static DecryptionResponse success(Long custId, String decryptedFilePath) {
        DecryptionResponse r = new DecryptionResponse();
        r.custId            = custId;
        r.decrypted         = true;
        r.decryptedFilePath = decryptedFilePath;
        return r;
    }

    public static DecryptionResponse failure(Long custId,
                                              String errorCode,
                                              String errorMessage) {
        DecryptionResponse r = new DecryptionResponse();
        r.custId            = custId;
        r.decrypted         = false;
        r.decryptedFilePath = null;
        r.errorCode         = errorCode;
        r.errorMessage      = errorMessage;
        return r;
    }

    // ── Getters / setters ─────────────────────────────────────────────────────

    public Long    getCustId()            { return custId; }
    public boolean isDecrypted()          { return decrypted; }
    public String  getDecryptedFilePath() { return decryptedFilePath; }
    public String  getErrorCode()         { return errorCode; }
    public String  getErrorMessage()      { return errorMessage; }

    public void setCustId(Long custId)                        { this.custId = custId; }
    public void setDecrypted(boolean decrypted)               { this.decrypted = decrypted; }
    public void setDecryptedFilePath(String decryptedFilePath){ this.decryptedFilePath = decryptedFilePath; }
    public void setErrorCode(String errorCode)                { this.errorCode = errorCode; }
    public void setErrorMessage(String errorMessage)          { this.errorMessage = errorMessage; }

    @Override
    public String toString() {
        return "DecryptionResponse{custId=" + custId
                + ", decrypted=" + decrypted
                + ", decryptedFilePath='" + decryptedFilePath
                + "', errorCode='" + errorCode + "'}";
    }
}
