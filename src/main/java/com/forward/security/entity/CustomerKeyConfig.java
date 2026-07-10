package com.forward.security.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Stores per-customer PGP key metadata.
 *
 * The bank's private key passphrase is Base64-encoded and stored in this table.
 * The actual private key material is stored in S3.
 *
 * Table: CUSTOMER_KEY_CONFIG
 *
 * Columns:
 *  CUSTOMER_ID           — primary key
 *  BANK_PRIVATE_KEY_PATH — S3 key of the bank's PGP private key (armored .asc)
 *  BANK_KEY_PASSPHRASE   — Base64-encoded passphrase for the bank's private key
 *  CUSTOMER_PUBLIC_KEY_PATH — S3 key of the customer's PGP public key (armored .asc)
 */
@Entity
@Table(name = "CUSTOMER_KEY_CONFIG")
public class CustomerKeyConfig {

    @Id
    @Column(name = "CUSTOMER_ID", nullable = false, length = 50)
    private String customerId;

    @Column(name = "BANK_PRIVATE_KEY_PATH", nullable = false, length = 500)
    private String bankPrivateKeyPath;

    /**
     * Base64-encoded passphrase protecting the bank's PGP private key.
     * Decoded at runtime before key ring extraction — never logged or stored in plaintext.
     */
    @Column(name = "BANK_KEY_PASSPHRASE", nullable = false, length = 500)
    private String bankKeyPassphraseBase64;

    @Column(name = "CUSTOMER_PUBLIC_KEY_PATH", nullable = false, length = 500)
    private String customerPublicKeyPath;

    public CustomerKeyConfig() {}

    public String getCustomerId()               { return customerId; }
    public String getBankPrivateKeyPath()        { return bankPrivateKeyPath; }
    public String getBankKeyPassphraseBase64()   { return bankKeyPassphraseBase64; }
    public String getCustomerPublicKeyPath()     { return customerPublicKeyPath; }

    public void setCustomerId(String customerId)                         { this.customerId = customerId; }
    public void setBankPrivateKeyPath(String bankPrivateKeyPath)         { this.bankPrivateKeyPath = bankPrivateKeyPath; }
    public void setBankKeyPassphraseBase64(String bankKeyPassphraseBase64) { this.bankKeyPassphraseBase64 = bankKeyPassphraseBase64; }
    public void setCustomerPublicKeyPath(String customerPublicKeyPath)   { this.customerPublicKeyPath = customerPublicKeyPath; }
}
