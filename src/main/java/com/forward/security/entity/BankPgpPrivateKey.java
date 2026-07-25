package com.forward.security.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * JPA entity for FWB_MST_BANK_PGP_PRIVATE_KEY table.
 *
 * Stores the bank's encrypted PGP private keys. The KEY column holds the
 * encrypted blob (encrypted by {@link com.forward.security.service.PGPPrivateKeyEncryptionService}).
 * The PASSPHRASE is Base64-encoded and will be decoded at runtime.
 */
@Entity
@Table(name = "FWB_MST_BANK_PGP_PRIVATE_KEY")
public class BankPgpPrivateKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "BANK_KEY_SEQ")
    private Long bankKeySeq;

    @Column(name = "KEY_NAME", nullable = false, length = 30)
    private String keyName;

    /**
     * Encrypted PGP private key blob (encrypted using AES-256-GCM).
     */
    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "KEY", nullable = false)
    private byte[] key;

    @Column(name = "VALID_FROM", nullable = false)
    private LocalDate validFrom;

    @Column(name = "VALID_TO", nullable = false)
    private LocalDate validTo;

    @Column(name = "KEY_ACTIVE_FLAG", nullable = false, length = 1)
    private String keyActiveFlag = "Y";

    @Column(name = "KEY_TYPE", nullable = false, length = 30)
    private String keyType;

    /**
     * Base64-encoded passphrase for the PGP private key.
     * This will be decoded at runtime before passing to Bouncy Castle.
     */
    @Column(name = "PASSPHRASE", nullable = false, length = 100)
    private String passphrase;

    @Column(name = "BANK_PVT_KEY_S3_PATH", length = 100)
    private String bankPvtKeyS3Path;

    @Column(name = "CREATION_TIMESTAMP", nullable = false, updatable = false)
    private LocalDateTime creationTimestamp;

    @PrePersist
    protected void onCreate() {
        if (creationTimestamp == null) {
            creationTimestamp = LocalDateTime.now();
        }
    }

    // ── Constructors ──────────────────────────────────────────────────────────

    public BankPgpPrivateKey() {}

    // ── Getters / Setters ─────────────────────────────────────────────────────

    public Long getBankKeySeq() { return bankKeySeq; }
    public void setBankKeySeq(Long bankKeySeq) { this.bankKeySeq = bankKeySeq; }

    public String getKeyName() { return keyName; }
    public void setKeyName(String keyName) { this.keyName = keyName; }

    public byte[] getKey() { return key; }
    public void setKey(byte[] key) { this.key = key; }

    public LocalDate getValidFrom() { return validFrom; }
    public void setValidFrom(LocalDate validFrom) { this.validFrom = validFrom; }

    public LocalDate getValidTo() { return validTo; }
    public void setValidTo(LocalDate validTo) { this.validTo = validTo; }

    public String getKeyActiveFlag() { return keyActiveFlag; }
    public void setKeyActiveFlag(String keyActiveFlag) { this.keyActiveFlag = keyActiveFlag; }

    public String getKeyType() { return keyType; }
    public void setKeyType(String keyType) { this.keyType = keyType; }

    public String getPassphrase() { return passphrase; }
    public void setPassphrase(String passphrase) { this.passphrase = passphrase; }

    public String getBankPvtKeyS3Path() { return bankPvtKeyS3Path; }
    public void setBankPvtKeyS3Path(String bankPvtKeyS3Path) { this.bankPvtKeyS3Path = bankPvtKeyS3Path; }

    public LocalDateTime getCreationTimestamp() { return creationTimestamp; }
    public void setCreationTimestamp(LocalDateTime creationTimestamp) { this.creationTimestamp = creationTimestamp; }
}
