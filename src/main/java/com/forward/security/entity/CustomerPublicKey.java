package com.forward.security.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * JPA entity for FWB_MST_PUBLIC_KEY table.
 *
 * Stores customer PGP public keys. The KEY column can optionally hold the
 * public key bytes, but primarily we use CUST_PUB_KEY_S3_PATH to fetch the
 * armored .asc file from S3.
 */
@Entity
@Table(name = "FWB_MST_PUBLIC_KEY")
public class CustomerPublicKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "CUST_PUBLIC_KEY_SEQ")
    private Long custPublicKeySeq;

    @Column(name = "CUST_ID", nullable = false)
    private Long custId;

    @Column(name = "KEY_ACTIVE_FLAG", nullable = false, length = 1)
    private String keyActiveFlag = "Y";

    @Column(name = "KEY_NAME", nullable = false, length = 100)
    private String keyName;

    @Column(name = "KEY_TYPE", nullable = false, length = 30)
    private String keyType;

    /**
     * Optional: public key bytes (not encrypted).
     * Can be null if we only store the key in S3.
     */
    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "KEY")
    private byte[] key;

    @Column(name = "VALID_FROM", nullable = false)
    private LocalDate validFrom;

    @Column(name = "VALID_TO", nullable = false)
    private LocalDate validTo;

    /**
     * S3 path to the customer's armored PGP public key (.asc file).
     */
    @Column(name = "CUST_PUB_KEY_S3_PATH", nullable = false, length = 100)
    private String custPubKeyS3Path;

    @Column(name = "CREATION_TIMESTAMP", nullable = false, updatable = false)
    private LocalDateTime creationTimestamp;

    @PrePersist
    protected void onCreate() {
        if (creationTimestamp == null) {
            creationTimestamp = LocalDateTime.now();
        }
    }

    // ── Constructors ──────────────────────────────────────────────────────────

    public CustomerPublicKey() {}

    // ── Getters / Setters ─────────────────────────────────────────────────────

    public Long getCustPublicKeySeq() { return custPublicKeySeq; }
    public void setCustPublicKeySeq(Long custPublicKeySeq) { this.custPublicKeySeq = custPublicKeySeq; }

    public Long getCustId() { return custId; }
    public void setCustId(Long custId) { this.custId = custId; }

    public String getKeyActiveFlag() { return keyActiveFlag; }
    public void setKeyActiveFlag(String keyActiveFlag) { this.keyActiveFlag = keyActiveFlag; }

    public String getKeyName() { return keyName; }
    public void setKeyName(String keyName) { this.keyName = keyName; }

    public String getKeyType() { return keyType; }
    public void setKeyType(String keyType) { this.keyType = keyType; }

    public byte[] getKey() { return key; }
    public void setKey(byte[] key) { this.key = key; }

    public LocalDate getValidFrom() { return validFrom; }
    public void setValidFrom(LocalDate validFrom) { this.validFrom = validFrom; }

    public LocalDate getValidTo() { return validTo; }
    public void setValidTo(LocalDate validTo) { this.validTo = validTo; }

    public String getCustPubKeyS3Path() { return custPubKeyS3Path; }
    public void setCustPubKeyS3Path(String custPubKeyS3Path) { this.custPubKeyS3Path = custPubKeyS3Path; }

    public LocalDateTime getCreationTimestamp() { return creationTimestamp; }
    public void setCreationTimestamp(LocalDateTime creationTimestamp) { this.creationTimestamp = creationTimestamp; }
}
