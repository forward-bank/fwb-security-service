package com.forward.security.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA entity for FWB_MST_BANK_CUST_PGP_KEY_LINK table.
 *
 * Links a bank PGP private key to a customer. The orchestrator queries this
 * table to find the active bank key and customer public key for a given
 * customer ID at decryption time.
 */
@Entity
@Table(name = "FWB_MST_BANK_CUST_PGP_KEY_LINK")
public class BankCustPgpKeyLink {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "BANK_CUST_KEY_LINK_SEQ")
    private Long bankCustKeyLinkSeq;

    @Column(name = "BANK_KEY_SEQ", nullable = false)
    private Long bankKeySeq;

    @Column(name = "CUST_PUBLIC_KEY_SEQ", nullable = false)
    private Long custPublicKeySeq;

    /**
     * Denormalised customer ID — stored directly for fast lookup by CUST_ID
     * without needing to join to FWB_MST_PUBLIC_KEY.
     */
    @Column(name = "CUST_ID", nullable = false)
    private Long custId;

    @Column(name = "KEY_ACTIVE_FLAG", nullable = false, length = 1)
    private String keyActiveFlag = "Y";

    @Column(name = "CREATION_TIMESTAMP", nullable = false, updatable = false)
    private LocalDateTime creationTimestamp;

    @PrePersist
    protected void onCreate() {
        if (creationTimestamp == null) {
            creationTimestamp = LocalDateTime.now();
        }
    }

    // ── Constructors ──────────────────────────────────────────────────────────

    public BankCustPgpKeyLink() {}

    // ── Getters / Setters ─────────────────────────────────────────────────────

    public Long getBankCustKeyLinkSeq() { return bankCustKeyLinkSeq; }
    public void setBankCustKeyLinkSeq(Long bankCustKeyLinkSeq) { this.bankCustKeyLinkSeq = bankCustKeyLinkSeq; }

    public Long getBankKeySeq() { return bankKeySeq; }
    public void setBankKeySeq(Long bankKeySeq) { this.bankKeySeq = bankKeySeq; }

    public Long getCustPublicKeySeq() { return custPublicKeySeq; }
    public void setCustPublicKeySeq(Long custPublicKeySeq) { this.custPublicKeySeq = custPublicKeySeq; }

    public Long getCustId() { return custId; }
    public void setCustId(Long custId) { this.custId = custId; }

    public String getKeyActiveFlag() { return keyActiveFlag; }
    public void setKeyActiveFlag(String keyActiveFlag) { this.keyActiveFlag = keyActiveFlag; }

    public LocalDateTime getCreationTimestamp() { return creationTimestamp; }
    public void setCreationTimestamp(LocalDateTime creationTimestamp) { this.creationTimestamp = creationTimestamp; }
}
