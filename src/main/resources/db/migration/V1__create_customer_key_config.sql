-- ============================================================
-- CUSTOMER_KEY_CONFIG
-- Stores per-customer PGP key metadata for the security service.
-- ============================================================

CREATE TABLE IF NOT EXISTS customer_key_config (
    customer_id                VARCHAR(50)  NOT NULL,
    bank_private_key_path      VARCHAR(500) NOT NULL,
    -- Base64-encoded passphrase for the bank's PGP private key
    bank_key_passphrase        VARCHAR(500) NOT NULL,
    customer_public_key_path   VARCHAR(500) NOT NULL,

    CONSTRAINT pk_customer_key_config PRIMARY KEY (customer_id)
);

COMMENT ON TABLE  customer_key_config                    IS 'PGP key configuration per customer';
COMMENT ON COLUMN customer_key_config.customer_id        IS 'Unique customer identifier';
COMMENT ON COLUMN customer_key_config.bank_private_key_path
    IS 'Bucket-relative S3 key of the bank PGP private key (armored .asc)';
COMMENT ON COLUMN customer_key_config.bank_key_passphrase
    IS 'Base64-encoded passphrase for the bank PGP private key';
COMMENT ON COLUMN customer_key_config.customer_public_key_path
    IS 'Bucket-relative S3 key of the customer PGP public key (armored .asc)';
