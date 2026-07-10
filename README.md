# FWB Security Service

A Spring Boot microservice responsible for **PGP decryption** and **signature verification** of customer payment files in the Forward Bank Direct Debit pipeline.

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

### 2 — Load key configuration from DB

`CustomerKeyConfigRepository.findById(customerId)` retrieves the `CUSTOMER_KEY_CONFIG` row which contains:
- `bankPrivateKeyPath` — S3 key of the bank's armored PGP private key
- `bankKeyPassphraseBase64` — Base64-encoded passphrase for the bank's private key
- `customerPublicKeyPath` — S3 key of the customer's armored PGP public key

### 3 — Download PGP keys from S3

`S3StreamDownloader.downloadBytes()` fetches the bank private key and (when signing is enabled) the customer public key. These are typically small armored text files.

### 4 — Decode the passphrase

The Base64-encoded passphrase is decoded to `char[]` at runtime. The array is zeroed out in a `finally` block immediately after use.

### 5 — Open encrypted file as a stream

`S3StreamDownloader.openStream()` opens a **streaming** `InputStream` directly backed by the S3 response body. The encrypted file is never fully loaded into memory — the Bouncy Castle PGP API reads it on-demand.

### 6 — PGP decryption and signature verification

`PgpDecryptionService.decrypt()` handles both modes:

| `pgpSigningEnabled` | Decryption mode | Signature verification |
|---|---|---|
| `false` | Encryption only — unwrap to literal data | None |
| `true` | Encryption + signing — one-pass signature + literal data | Customer public key |

After decryption, PGP message integrity (MDC) is verified when present.

### 7 — Upload decrypted file to S3

The plaintext bytes are written to S3 at a computed path derived from the encrypted path:
- `INCOMING` → `DECRYPTED`
- `.pgp` / `.gpg` / `.asc` suffix stripped

Example:
```
encrypted : FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/payment.xml.pgp
decrypted : FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/DECRYPTED/payment.xml
```

### 8 — Send response

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
│   └── FileDecryptionOrchestrator.java       # End-to-end decryption flow coordinator
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
│   └── CustomerKeyConfig.java                # JPA entity for CUSTOMER_KEY_CONFIG table
│
└── repository/
    └── CustomerKeyConfigRepository.java      # Spring Data JPA repository
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
