-- ==============================================================================
-- Sample INSERT Statements for FWB Security Service
-- Database: APP_DB_1967
-- ==============================================================================
-- IMPORTANT NOTES:
-- 1. The KEY column in FWB_MST_BANK_PGP_PRIVATE_KEY must contain an ENCRYPTED blob.
--    Use PGPPrivateKeyEncryptionService.encrypt() to generate this blob.
--    The placeholder below ('REPLACE_WITH_ENCRYPTED_BLOB_BASE64') must be replaced
--    with the actual encrypted output from the encryption service.
--
-- 2. The PASSPHRASE is Base64-encoded. Decode it at runtime to get the actual PGP passphrase.
--
-- 3. Customer public keys are stored UNENCRYPTED in S3 at CUST_PUB_KEY_S3_PATH.
-- ==============================================================================

\c APP_DB_1967

-- ==============================================================================
-- Step 1: Insert Bank PGP Private Key
-- ==============================================================================
-- This represents the bank's PGP private key (encrypted at rest).
--
-- TO GENERATE THE ENCRYPTED BLOB:
-- 1. Run PGPPrivateKeyEncryptionService.main() with your actual .asc private key file
-- 2. Copy the Base64 output from the console (the "Encrypted blob (base64): ..." line)
-- 3. Replace 'REPLACE_WITH_ENCRYPTED_BLOB_BASE64' below with that value
--
-- Example encrypted blob format:
--   The output is: [16 bytes salt][12 bytes IV][ciphertext + 16 byte GCM tag]
--   Encoded as Base64 for storage in this SQL script.
--
-- PASSPHRASE ENCODING:
--   The PASSPHRASE column stores the PGP key passphrase in Base64.
--   Example: if the passphrase is "BankPrivateKey2026!", encode it:
--     echo -n "BankPrivateKey2026!" | base64
--     Result: QmFua1ByaXZhdGVLZXkyMDI2IQ==
-- ==============================================================================

INSERT INTO FWB_MST_BANK_PGP_PRIVATE_KEY (
    KEY_NAME,
    KEY,
    VALID_FROM,
    VALID_TO,
    KEY_ACTIVE_FLAG,
    KEY_TYPE,
    PASSPHRASE,
    BANK_PVT_KEY_S3_PATH
) VALUES (
    'BANK_KEY_2026_Q1',                               -- Friendly name for the key
    decode('REPLACE_WITH_ENCRYPTED_BLOB_BASE64', 'base64'),  -- *** REPLACE THIS ***
    '2026-01-01',                                     -- Valid from date
    '2026-12-31',                                     -- Valid to date
    'Y',                                              -- Active flag
    'RSA-4096',                                       -- Key type
    'QmFua1ByaXZhdGVLZXkyMDI2IQ==',                  -- Base64('BankPrivateKey2026!')
    'PGP_KEYS/BANK/PRIVATE/bank_2026_q1_encrypted.bin'  -- Optional S3 path
);

-- Verify the insert
SELECT BANK_KEY_SEQ, KEY_NAME, KEY_ACTIVE_FLAG, KEY_TYPE, VALID_FROM, VALID_TO
FROM FWB_MST_BANK_PGP_PRIVATE_KEY
WHERE KEY_NAME = 'BANK_KEY_2026_Q1';

-- ==============================================================================
-- Step 2: Insert Customer Public Key
-- ==============================================================================
-- This represents a customer's PGP public key metadata.
-- The actual public key file (.asc) is stored UNENCRYPTED in S3 at CUST_PUB_KEY_S3_PATH.
--
-- The KEY column is optional (can be NULL) — the service primarily uses the S3 path
-- to download the key at decryption time.
--
-- CUST_ID:
--   Customer identifier (e.g., 1001).
--   This is the value sent in the DecryptionRequest.customerId field.
-- ==============================================================================

INSERT INTO FWB_MST_PUBLIC_KEY (
    CUST_ID,
    KEY_ACTIVE_FLAG,
    KEY_NAME,
    KEY_TYPE,
    KEY,
    VALID_FROM,
    VALID_TO,
    CUST_PUB_KEY_S3_PATH
) VALUES (
    1001,                                             -- Customer ID
    'Y',                                              -- Active flag
    'CUST1001_PUB_2026',                             -- Friendly name
    'RSA-4096',                                       -- Key type
    NULL,                                             -- Optional: public key bytes (not used by default)
    '2026-01-01',                                     -- Valid from date
    '2026-12-31',                                     -- Valid to date
    'PGP_KEYS/CUSTOMERS/1001/customer_1001_pub_2026.asc'  -- S3 path to .asc public key
);

-- Verify the insert
SELECT CUST_PUBLIC_KEY_SEQ, CUST_ID, KEY_NAME, KEY_ACTIVE_FLAG, CUST_PUB_KEY_S3_PATH
FROM FWB_MST_PUBLIC_KEY
WHERE CUST_ID = 1001;

-- ==============================================================================
-- Step 3: Link Bank Key to Customer Public Key
-- ==============================================================================
-- This creates the association between:
--   - The bank's private key (used to DECRYPT incoming payment files)
--   - The customer's public key (used to VERIFY SIGNATURES on signed files)
--
-- BANK_KEY_SEQ:
--   References FWB_MST_BANK_PGP_PRIVATE_KEY.BANK_KEY_SEQ from Step 1.
--   If the insert above auto-generated BANK_KEY_SEQ = 1, use 1 here.
--
-- CUST_PUBLIC_KEY_SEQ:
--   References FWB_MST_PUBLIC_KEY.CUST_PUBLIC_KEY_SEQ from Step 2.
--   If the insert above auto-generated CUST_PUBLIC_KEY_SEQ = 1, use 1 here.
--
-- CUST_ID:
--   Denormalised customer ID (stored here for fast lookup by CUST_ID without a join).
--   Must match the CUST_ID from Step 2.
--
-- KEY_ACTIVE_FLAG:
--   'Y' = this link is active (used for decryption)
--   'N' = inactive (e.g., during key rotation)
-- ==============================================================================

INSERT INTO FWB_MST_BANK_CUST_PGP_KEY_LINK (
    BANK_KEY_SEQ,
    CUST_PUBLIC_KEY_SEQ,
    CUST_ID,
    KEY_ACTIVE_FLAG
) VALUES (
    1,          -- References FWB_MST_BANK_PGP_PRIVATE_KEY(BANK_KEY_SEQ)
    1,          -- References FWB_MST_PUBLIC_KEY(CUST_PUBLIC_KEY_SEQ)
    1001,       -- Denormalised CUST_ID (must match the customer record above)
    'Y'         -- Active flag
);

-- Verify the insert
SELECT 
    lnk.BANK_CUST_KEY_LINK_SEQ,
    lnk.BANK_KEY_SEQ,
    lnk.CUST_PUBLIC_KEY_SEQ,
    lnk.CUST_ID,
    lnk.KEY_ACTIVE_FLAG,
    bank.KEY_NAME AS BANK_KEY_NAME,
    cust.KEY_NAME AS CUSTOMER_KEY_NAME
FROM FWB_MST_BANK_CUST_PGP_KEY_LINK lnk
JOIN FWB_MST_BANK_PGP_PRIVATE_KEY bank ON lnk.BANK_KEY_SEQ = bank.BANK_KEY_SEQ
JOIN FWB_MST_PUBLIC_KEY cust ON lnk.CUST_PUBLIC_KEY_SEQ = cust.CUST_PUBLIC_KEY_SEQ
WHERE lnk.CUST_ID = 1001;

-- ==============================================================================
-- Verification Query: Check Complete Setup for Customer 1001
-- ==============================================================================
-- This query shows the full key configuration for a customer.
-- Use this to verify all three tables are correctly linked.
-- ==============================================================================

SELECT 
    lnk.CUST_ID,
    lnk.KEY_ACTIVE_FLAG AS LINK_ACTIVE,
    bank.KEY_NAME AS BANK_KEY_NAME,
    bank.KEY_TYPE AS BANK_KEY_TYPE,
    bank.VALID_FROM AS BANK_VALID_FROM,
    bank.VALID_TO AS BANK_VALID_TO,
    cust.KEY_NAME AS CUSTOMER_KEY_NAME,
    cust.KEY_TYPE AS CUSTOMER_KEY_TYPE,
    cust.CUST_PUB_KEY_S3_PATH
FROM FWB_MST_BANK_CUST_PGP_KEY_LINK lnk
JOIN FWB_MST_BANK_PGP_PRIVATE_KEY bank 
    ON lnk.BANK_KEY_SEQ = bank.BANK_KEY_SEQ
JOIN FWB_MST_PUBLIC_KEY cust 
    ON lnk.CUST_PUBLIC_KEY_SEQ = cust.CUST_PUBLIC_KEY_SEQ
WHERE lnk.CUST_ID = 1001 
  AND lnk.KEY_ACTIVE_FLAG = 'Y';

-- ==============================================================================
-- Expected Output:
-- ==============================================================================
-- cust_id | link_active | bank_key_name      | bank_key_type | bank_valid_from | bank_valid_to | customer_key_name    | customer_key_type | cust_pub_key_s3_path
-- --------+-------------+--------------------+---------------+-----------------+---------------+----------------------+-------------------+-------------------------------------
--    1001 | Y           | BANK_KEY_2026_Q1   | RSA-4096      | 2026-01-01      | 2026-12-31    | CUST1001_PUB_2026    | RSA-4096          | PGP_KEYS/CUSTOMERS/1001/customer_1001_pub_2026.asc
-- ==============================================================================

\echo ''
\echo '✓ Sample data inserted successfully!'
\echo ''
\echo 'NEXT STEPS:'
\echo '1. Replace ''REPLACE_WITH_ENCRYPTED_BLOB_BASE64'' in Step 1 with actual encrypted key blob'
\echo '2. Upload the customer public key (.asc file) to S3 at: PGP_KEYS/CUSTOMERS/1001/customer_1001_pub_2026.asc'
\echo '3. Test decryption by sending a message to SECURITY.DECRYPTION.REQUEST.QUEUE with:'
\echo '   {"customerId": "1001", "encryptedFilePath": "...", "pgpSigningEnabled": true}'
\echo ''
