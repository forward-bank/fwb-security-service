-- ==============================================================================
-- FWB Security Service — PGP Key Management Tables
-- Database: APP_DB_1967
-- ==============================================================================

\c APP_DB_1967

-- Drop existing tables if they exist (for clean re-runs)
DROP TABLE IF EXISTS FWB_MST_BANK_CUST_PGP_KEY_LINK CASCADE;
DROP TABLE IF EXISTS FWB_MST_PUBLIC_KEY CASCADE;
DROP TABLE IF EXISTS FWB_MST_BANK_PGP_PRIVATE_KEY CASCADE;

-- ==============================================================================
-- FWB_MST_BANK_PGP_PRIVATE_KEY
-- Stores the bank's PGP private keys.
-- The KEY BLOB is the encrypted private key (encrypted by PGPPrivateKeyEncryptionService).
-- BANK_PVT_KEY_S3_PATH is the S3 path where the encrypted key is also stored.
-- PASSPHRASE is the Base64-encoded PGP key passphrase.
-- ==============================================================================
CREATE TABLE FWB_MST_BANK_PGP_PRIVATE_KEY (
    BANK_KEY_SEQ            BIGSERIAL PRIMARY KEY,
    KEY_NAME                VARCHAR(30) NOT NULL,
    KEY                     BYTEA NOT NULL,              -- Encrypted PGP private key blob
    VALID_FROM              DATE NOT NULL,
    VALID_TO                DATE NOT NULL,
    KEY_ACTIVE_FLAG         CHAR(1) NOT NULL DEFAULT 'Y' CHECK (KEY_ACTIVE_FLAG IN ('Y', 'N')),
    KEY_TYPE                VARCHAR(30) NOT NULL,        -- e.g. 'PGP', 'RSA-4096'
    PASSPHRASE              VARCHAR(100) NOT NULL,       -- Base64-encoded PGP key passphrase
    BANK_PVT_KEY_S3_PATH    VARCHAR(100),                -- Optional S3 path
    CREATION_TIMESTAMP      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE  FWB_MST_BANK_PGP_PRIVATE_KEY IS 'Stores bank PGP private keys (encrypted)';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.BANK_KEY_SEQ IS 'Primary key sequence';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.KEY_NAME IS 'Friendly name for the key';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.KEY IS 'Encrypted PGP private key blob (AES-256-GCM)';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.VALID_FROM IS 'Key validity start date';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.VALID_TO IS 'Key validity end date';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.KEY_ACTIVE_FLAG IS 'Y = active, N = inactive';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.KEY_TYPE IS 'Key algorithm type (e.g. PGP, RSA-4096)';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.PASSPHRASE IS 'Base64-encoded passphrase for the PGP key';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.BANK_PVT_KEY_S3_PATH IS 'Optional S3 path where encrypted key is stored';
COMMENT ON COLUMN FWB_MST_BANK_PGP_PRIVATE_KEY.CREATION_TIMESTAMP IS 'Record creation timestamp';

-- ==============================================================================
-- FWB_MST_PUBLIC_KEY
-- Stores customer public keys.
-- The KEY BLOB stores the public key bytes (NOT encrypted).
-- CUST_PUB_KEY_S3_PATH is the S3 path to the armored .asc public key file.
-- ==============================================================================
CREATE TABLE FWB_MST_PUBLIC_KEY (
    CUST_PUBLIC_KEY_SEQ     BIGSERIAL PRIMARY KEY,
    CUST_ID                 BIGINT NOT NULL,
    KEY_ACTIVE_FLAG         CHAR(1) NOT NULL DEFAULT 'Y' CHECK (KEY_ACTIVE_FLAG IN ('Y', 'N')),
    KEY_NAME                VARCHAR(100) NOT NULL,
    KEY_TYPE                VARCHAR(30) NOT NULL,
    KEY                     BYTEA,                       -- Optional: public key bytes (unencrypted)
    VALID_FROM              DATE NOT NULL,
    VALID_TO                DATE NOT NULL,
    CUST_PUB_KEY_S3_PATH    VARCHAR(100) NOT NULL,       -- S3 path to customer's public key
    CREATION_TIMESTAMP      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE  FWB_MST_PUBLIC_KEY IS 'Stores customer PGP public keys';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.CUST_PUBLIC_KEY_SEQ IS 'Primary key sequence';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.CUST_ID IS 'Customer identifier';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.KEY_ACTIVE_FLAG IS 'Y = active, N = inactive';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.KEY_NAME IS 'Friendly name for the key';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.KEY_TYPE IS 'Key algorithm type';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.KEY IS 'Optional public key bytes (unencrypted)';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.VALID_FROM IS 'Key validity start date';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.VALID_TO IS 'Key validity end date';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.CUST_PUB_KEY_S3_PATH IS 'S3 path to armored .asc public key';
COMMENT ON COLUMN FWB_MST_PUBLIC_KEY.CREATION_TIMESTAMP IS 'Record creation timestamp';

-- ==============================================================================
-- FWB_MST_BANK_CUST_PGP_KEY_LINK
-- Links a bank private key with a customer public key.
-- This is the join table used to look up which bank key should be used
-- for a given customer's decryption request.
-- ==============================================================================
CREATE TABLE FWB_MST_BANK_CUST_PGP_KEY_LINK (
    BANK_CUST_KEY_LINK_SEQ  BIGSERIAL PRIMARY KEY,
    BANK_KEY_SEQ            BIGINT NOT NULL,
    CUST_PUBLIC_KEY_SEQ     BIGINT NOT NULL,
    CUST_ID                 BIGINT NOT NULL,
    KEY_ACTIVE_FLAG         CHAR(1) NOT NULL DEFAULT 'Y' CHECK (KEY_ACTIVE_FLAG IN ('Y', 'N')),
    CREATION_TIMESTAMP      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_bank_key
        FOREIGN KEY (BANK_KEY_SEQ)
        REFERENCES FWB_MST_BANK_PGP_PRIVATE_KEY(BANK_KEY_SEQ),

    CONSTRAINT fk_cust_pub_key
        FOREIGN KEY (CUST_PUBLIC_KEY_SEQ)
        REFERENCES FWB_MST_PUBLIC_KEY(CUST_PUBLIC_KEY_SEQ),
);

COMMENT ON TABLE  FWB_MST_BANK_CUST_PGP_KEY_LINK IS 'Links bank private keys to customer public keys';
COMMENT ON COLUMN FWB_MST_BANK_CUST_PGP_KEY_LINK.BANK_CUST_KEY_LINK_SEQ IS 'Primary key sequence';
COMMENT ON COLUMN FWB_MST_BANK_CUST_PGP_KEY_LINK.BANK_KEY_SEQ IS 'References FWB_MST_BANK_PGP_PRIVATE_KEY';
COMMENT ON COLUMN FWB_MST_BANK_CUST_PGP_KEY_LINK.CUST_PUBLIC_KEY_SEQ IS 'References FWB_MST_PUBLIC_KEY primary key';
COMMENT ON COLUMN FWB_MST_BANK_CUST_PGP_KEY_LINK.CUST_ID IS 'Denormalised customer ID for fast lookup without join';
COMMENT ON COLUMN FWB_MST_BANK_CUST_PGP_KEY_LINK.KEY_ACTIVE_FLAG IS 'Y = active link, N = inactive';
COMMENT ON COLUMN FWB_MST_BANK_CUST_PGP_KEY_LINK.CREATION_TIMESTAMP IS 'Record creation timestamp';

-- ==============================================================================
-- Indexes for performance
-- ==============================================================================
CREATE INDEX idx_bank_key_active ON FWB_MST_BANK_PGP_PRIVATE_KEY(KEY_ACTIVE_FLAG, VALID_FROM, VALID_TO);
CREATE INDEX idx_public_key_cust_id ON FWB_MST_PUBLIC_KEY(CUST_ID, KEY_ACTIVE_FLAG);
CREATE INDEX idx_key_link_cust_id ON FWB_MST_BANK_CUST_PGP_KEY_LINK(CUST_ID, KEY_ACTIVE_FLAG);

-- ==============================================================================
-- Grant permissions (adjust user as needed)
-- ==============================================================================
-- GRANT SELECT, INSERT, UPDATE ON FWB_MST_BANK_PGP_PRIVATE_KEY TO fwb_security_user;
-- GRANT SELECT, INSERT, UPDATE ON FWB_MST_PUBLIC_KEY TO fwb_security_user;
-- GRANT SELECT, INSERT, UPDATE ON FWB_MST_BANK_CUST_PGP_KEY_LINK TO fwb_security_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fwb_security_user;

-- ==============================================================================
-- Sample data for testing (optional)
-- ==============================================================================
-- INSERT INTO FWB_MST_BANK_PGP_PRIVATE_KEY (KEY_NAME, KEY, VALID_FROM, VALID_TO, KEY_TYPE, PASSPHRASE)
-- VALUES ('BANK_KEY_2026_Q1', decode('...encrypted blob base64...', 'base64'), '2026-01-01', '2026-12-31', 'RSA-4096', 'base64encodedpassphrase');

-- INSERT INTO FWB_MST_PUBLIC_KEY (CUST_ID, KEY_NAME, KEY_TYPE, VALID_FROM, VALID_TO, CUST_PUB_KEY_S3_PATH)
-- VALUES (1001, 'CUST1001_PUB_2026', 'RSA-4096', '2026-01-01', '2026-12-31', 'PGP_KEYS/CUSTOMERS/1001/pub_2026.asc');

-- INSERT INTO FWB_MST_BANK_CUST_PGP_KEY_LINK (BANK_KEY_SEQ, CUST_ID)
-- VALUES (1, 1001);

\echo '✓ Tables created successfully in APP_DB_1967'
