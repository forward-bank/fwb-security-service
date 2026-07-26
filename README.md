# FWB Security Service

A Spring Boot microservice responsible for **PGP decryption** and **signature verification** of customer payment files in the Forward Bank Direct Debit pipeline.

## Localstack aws commands for setup
```bash

aws s3 mb s3://forward-bank-payments --endpoint-url=http://localhost:4566

aws s3 cp Forward_Bank_0x7C56E1A820421C1D_SECRET.asc s3://forward-bank-payments/DEV/PGP_KEYS/BANK/PRIVATE/Forward_Bank_0x7C56E1A820421C1D_SECRET.asc --endpoint-url=http://localhost:4566

aws s3 cp Hexa_Consulting_0x3497C5F5C5F1D494_public.asc s3://forward-bank-payments/DEV/PGP_KEYS/CUSTOMERS/1001/Hexa_Consulting_0x3497C5F5C5F1D494_public.asc --endpoint-url=http://localhost:4566

aws s3 cp  pain.008.001.08.PM.pgp  s3://forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/I1234567890123.FWB.pain00800108.ABCD123.PM.pgp_12345145 --endpoint-url=http://localhost:4566

aws s3 cp  pain.008.001.08.PM.signed.pgp  s3://forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/03/03/INCOMING/S1234567890123.FWB.pain00800108.SBCD123.PM.signed.pgp_12345145 --endpoint-url=http://localhost:4566

```

This service uses a **three-table schema** to manage PGP keys:
- `FWB_MST_BANK_PGP_PRIVATE_KEY` — Bank's **encrypted** private keys
- `FWB_MST_PUBLIC_KEY` — Customer public keys (stored in S3)
- `FWB_MST_BANK_CUST_PGP_KEY_LINK` — Links bank keys to customers

## SQL statements for data setup
```sql
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
    'BANK_KEY_2026_Q1',
    null,
    '2026-01-01',
    '2029-01-01',
    'Y',
    'PGP',
    'SU5JVElBTElaQVRJT04gVuBY0dcv93FtbJxAqzP3dRQ=',
    'forward-bank-payments/DEV/PGP_KEYS/BANK/PRIVATE/Forward_Bank_0x7C56E1A820421C1D_SECRET.asc'
);




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
    1001,                                            
    'Y',                                              
    'CUST1001_PUB_2026',                             
    'PGP',                                       
     NULL,                                             
    '2026-01-01',                                     
    '2029-01-01',                                     
    'forward-bank-payments/DEV/PGP_KEYS/CUSTOMERS/1001/Hexa_Consulting_0x3497C5F5C5F1D494_public.asc'
);




INSERT INTO FWB_MST_BANK_CUST_PGP_KEY_LINK (
    BANK_KEY_SEQ,
    CUST_PUBLIC_KEY_SEQ,
    CUST_ID,
    KEY_ACTIVE_FLAG
) VALUES (
    2,          
    1,
    1001,
    'Y'
);
```

---

## How It Fits in the System

```
fwb-direct-debit-workflow-service  (Camunda BPMN engine)
        │
        │  decryption_request_task (Service Task)
        │  sends JSON to ────────────────────────────────────────────────────┐
        │                                                                     │
        │                                               SECURITY.DECRYPTION
        │                                               .REQUEST.QUEUE
        │                                                      │
        │                                         fwb-security-service
        │                                         DecryptionRequestListener
        │                                           1. parse request
        │                                           2. load key config from DB
        │                                           3. download bank private key (S3)
        │                                           4. download customer public key (S3, if signed)
        │                                           5. open encrypted file stream (S3)
        │                                           6. PGP decrypt + verify signature
        │                                           7. upload decrypted file (S3)
        │                                           8. write result ─────────┐
        │                                                                     │
        │                                               SECURITY.DECRYPTION
        │                                               .RESPONSE.QUEUE
        │                                                      │
        │  decryption_response_task (Receive Task)             │
        │  correlates back to waiting Camunda process ◄────────┘
        ▼
  [is_decryption_successful?] gateway → ...
```

---

## Processing Flow

### 1 — Receive request from IBM MQ

`DecryptionRequestListener.onMessage()` reads a JSON `TextMessage` from `SECURITY.DECRYPTION.REQUEST.QUEUE`:

```json
{
  "customerId": "CUST-001",
  "encryptedFilePath": "FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/payment.xml.pgp",
  "pgpSigningEnabled": true
}
```

### 2 — Load key configuration from DB (three-table lookup)

The orchestrator queries `FWB_MST_BANK_CUST_PGP_KEY_LINK` to find the active key link for the customer:

```sql
SELECT * FROM FWB_MST_BANK_CUST_PGP_KEY_LINK
WHERE CUST_ID = ? AND KEY_ACTIVE_FLAG = 'Y'
LIMIT 1
```

Then loads:
1. `BankPgpPrivateKey` using `BANK_KEY_SEQ` from the link
2. `CustomerPublicKey` using `CUST_ID` (when signing enabled)

### 3 — Decrypt the bank's PGP private key

The `KEY` column in `FWB_MST_BANK_PGP_PRIVATE_KEY` holds an **encrypted** blob. `PGPPrivateKeyEncryptionService.decrypt()` unwraps it using AES-256-GCM with PBKDF2 key derivation, yielding the armored PGP private key bytes.

### 4 — Download customer's public key from S3

`CustomerPublicKey.getCustPubKeyS3Path()` points to the S3 location of the customer's armored `.asc` public key. `S3StreamDownloader.downloadBytes()` fetches it.

### 5 — Decode the PGP passphrase

The `PASSPHRASE` column is Base64-encoded. Decode it to `char[]` at runtime, use it to unlock the PGP private key, then zero it out immediately in a `finally` block.

### 6 — Open encrypted file as a stream

`S3StreamDownloader.openStream()` opens a **streaming** `InputStream` directly backed by the S3 response body. The encrypted file is never fully loaded into memory — the Bouncy Castle PGP API reads it on-demand.

### 7 — PGP decryption and signature verification

`PgpDecryptionService.decrypt()` handles both modes:

| `pgpSigningEnabled` | Decryption mode | Signature verification |
|---|---|---|
| `false` | Encryption only — unwrap to literal data | None |
| `true` | Encryption + signing — one-pass signature + literal data | Customer public key |

After decryption, PGP message integrity (MDC) is verified when present.

### 8 — Upload decrypted file to S3

The plaintext bytes are written to S3 at a computed path derived from the encrypted path:
- `INCOMING` → `DECRYPTED`
- `.pgp` / `.gpg` / `.asc` suffix stripped

Example:
```
encrypted : FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/payment.xml.pgp
decrypted : FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/DECRYPTED/payment.xml
```

### 9 — Send response

```json
// Success
{
  "encryptedFilePath": "FWB_DIRECT_DEBIT/.../payment.xml.pgp",
  "decryptedFilePath": "FWB_DIRECT_DEBIT/.../DECRYPTED/payment.xml",
  "decryptionSuccessful": true,
  "errorCode": "",
  "errorMessage": ""
}

// Failure
{
  "encryptedFilePath": "FWB_DIRECT_DEBIT/.../payment.xml.pgp",
  "decryptedFilePath": "",
  "decryptionSuccessful": false,
  "errorCode": "SSE_005",
  "errorMessage": "PGP signature verification failed — file may have been tampered with"
}
```

---

## Project Structure

```
src/main/java/com/forward/security/
│
├── SecurityServiceApplication.java          # @SpringBootApplication entry point
│
├── config/
│   ├── S3Config.java                         # S3Client bean (LocalStack or real AWS)
│   └── MQListenerConfig.java                 # Wires MQ listener with init/destroy lifecycle
│
├── mq/
│   ├── MQConfig.java                         # Connection POJO + queue name constants
│   └── listener/
│       └── DecryptionRequestListener.java    # Core MQ message handler
│
├── service/
│   ├── FileDecryptionOrchestrator.java       # End-to-end decryption flow coordinator
│   └── PGPPrivateKeyEncryptionService.java   # AES-256-GCM encryption for bank private key blobs
│
├── pgp/
│   ├── PgpDecryptionService.java             # Bouncy Castle PGP decrypt + verify
│   └── PgpDecryptionResult.java              # Immutable result value object
│
├── s3/
│   ├── S3StreamDownloader.java               # S3 streaming InputStream + byte[] download
│   └── S3Uploader.java                       # S3 upload for decrypted output
│
├── model/
│   ├── DecryptionRequest.java                # Inbound MQ message model
│   └── DecryptionResponse.java               # Outbound MQ message model
│
├── entity/
│   ├── BankPgpPrivateKey.java                # JPA entity → FWB_MST_BANK_PGP_PRIVATE_KEY
│   ├── CustomerPublicKey.java                # JPA entity → FWB_MST_PUBLIC_KEY
│   └── BankCustPgpKeyLink.java               # JPA entity → FWB_MST_BANK_CUST_PGP_KEY_LINK
│
└── repository/
    ├── BankPgpPrivateKeyRepository.java      # JPA repo for bank private keys
    ├── CustomerPublicKeyRepository.java      # JPA repo for customer public keys
    └── BankCustPgpKeyLinkRepository.java     # JPA repo for bank-customer key links

database/
└── create_tables.sql                         # DDL for all three tables in APP_DB_1967
```

---

## Error Codes

| Code | Meaning |
|---|---|
| `SSE_001` | Input validation failure (null/blank field, bad JSON) |
| `SSE_002` | No matching bank private key found in the secret key ring |
| `SSE_003` | Wrong passphrase — unable to extract bank private key |
| `SSE_004` | PGP message integrity (MDC) check failed — possible tampering |
| `SSE_005` | Signature verification failed — bad signature or wrong public key |
| `SSE_006` | Signature packet missing in a signed message |
| `SSE_007` | IO error reading encrypted stream |
| `SSE_008` | Unexpected PGP packet structure |
| `SSE_009` | No key configuration found in DB for this customer ID |
| `SSE_010` | S3 download error (key file or encrypted payment file) |
| `SSE_011` | Bank key passphrase is not valid Base64 |
| `SSE_012` | S3 upload error for decrypted output file |
| `SSE_INTERNAL_ERROR` | Unexpected runtime exception |

---

## IBM MQ Queues

| Queue | Direction | Purpose |
|---|---|---|
| `SECURITY.DECRYPTION.REQUEST.QUEUE` | Inbound | Receives decryption requests |
| `SECURITY.DECRYPTION.RESPONSE.QUEUE` | Outbound | Sends decryption results |

---

## application.properties Reference

```properties
server.port=8085

mq.host=localhost
mq.port=1414
mq.channel=SYSTEM.DEF.SVRCONN
mq.queueManager=MY.TEST.QMNGR

aws.localstack.enabled=true
aws.localstack.endpoint=http://localhost:4566
aws.region=us-east-1
aws.s3.bucket=fwb-payments-dev

spring.datasource.url=jdbc:postgresql://localhost:5432/fwb_security_db
spring.datasource.username=fwb_user
spring.datasource.password=fwb_pass
```

---

## Running Locally

```bash
mvn clean package -DskipTests
java -jar target/fwb-security-service-1.0-SNAPSHOT.jar
```
