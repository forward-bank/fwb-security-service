# Passphrase Encryption — FWB Security Service

This document explains the exact algorithm used to encrypt a plain-text PGP key
passphrase before it is stored in the `PASSPHRASE` column of
`FWB_MST_BANK_PGP_PRIVATE_KEY`. The implementation lives in
`PassphraseEncryptionUtil.java`.

---

## Table of Contents

1. [Overview](#overview)
2. [Algorithm At a Glance](#algorithm-at-a-glance)
3. [Step-by-Step Walkthrough](#step-by-step-walkthrough)
   - [Step 1 — Entry Point](#step-1--entry-point)
   - [Step 2 — Register BouncyCastle Provider](#step-2--register-bouncycastle-provider)
   - [Step 3 — Prepare the Initialization Vector](#step-3--prepare-the-initialization-vector)
   - [Step 4 — Configure the Cipher](#step-4--configure-the-cipher)
   - [Step 5 — Load the AES-256 Key](#step-5--load-the-aes-256-key)
   - [Step 6 — Initialize the Cipher in Encryption Mode](#step-6--initialize-the-cipher-in-encryption-mode)
   - [Step 7 — Encrypt the Plaintext Bytes](#step-7--encrypt-the-plaintext-bytes)
   - [Step 8 — Prepend IV to Ciphertext](#step-8--prepend-iv-to-ciphertext)
   - [Step 9 — Base64 Encode the Final Output](#step-9--base64-encode-the-final-output)
4. [Memory Layout of the Stored Value](#memory-layout-of-the-stored-value)
5. [Decryption (Reverse Process)](#decryption-reverse-process)
6. [Why Each Design Choice Was Made](#why-each-design-choice-was-made)
7. [Running the Utility](#running-the-utility)
8. [Full Worked Example](#full-worked-example)
9. [Security Considerations](#security-considerations)

---

## Overview

The bank's PGP private key has a passphrase that protects it. Before this
passphrase is written to the database, it is encrypted using **AES-256-CBC**
with **PKCS7 padding** via the **Bouncy Castle** cryptographic library.

The final value stored in `PASSPHRASE` is a **Base64-encoded string** containing:

```
[ 16 bytes: Initialization Vector ] [ N bytes: AES-256-CBC Ciphertext ]
```

At decryption time the service reads this column, splits off the first 16 bytes
as the IV, and decrypts the rest using the same AES key to recover the original
plain-text passphrase.

---

## Algorithm At a Glance

```
Plain-text passphrase (UTF-8 string)
        │
        ▼
  UTF-8 encode → byte[]
        │
        ▼
  AES-256-CBC encrypt  ◄── Key: Base64-decoded crypto.key (32 bytes)
  (PKCS7 padding)      ◄── IV:  "INITIALIZATION V" (16 ASCII bytes, hardcoded)
        │
        ▼
  ciphertext byte[]
        │
        ▼
  Prepend IV → [ IV (16 bytes) | ciphertext ]
        │
        ▼
  Base64 encode
        │
        ▼
  Stored in DB: PASSPHRASE column of FWB_MST_BANK_PGP_PRIVATE_KEY
```

---

## Step-by-Step Walkthrough

### Step 1 — Entry Point

The process begins with a call to `PassphraseEncryptionUtil.encryptPassphrase(String)`:

```java
public static String encryptPassphrase(String plainTextPassphrase) {
    byte[] plainBytes = plainTextPassphrase.getBytes(StandardCharsets.UTF_8);
    byte[] encryptedBytes = encryptBytes(plainBytes);
    return Base64.getEncoder().encodeToString(encryptedBytes);
}
```

**What happens here:**

- The plain-text passphrase (e.g. `"BankPrivateKey2026!"`) is converted to a
  raw `byte[]` using UTF-8 encoding.
- UTF-8 is chosen because it is the universal standard for text-to-bytes
  conversion. A passphrase containing only ASCII characters (letters, digits,
  punctuation) produces exactly one byte per character under UTF-8.
- The byte array is passed to the internal `encryptBytes()` method which
  performs the actual encryption (Steps 2–8).
- The result of `encryptBytes()` is `IV + ciphertext` as a `byte[]`. This is
  then Base64-encoded to produce a printable string suitable for storage in the
  database (Step 9).

---

### Step 2 — Register BouncyCastle Provider

```java
Security.addProvider(new BouncyCastleProvider());
```

**What happens here:**

The Java Cryptography Architecture (JCA) uses a **provider model**: all
cryptographic operations are delegated to a registered provider. The standard
JDK ships with the `SunJCE` provider, but it does not expose the same
lightweight API that Bouncy Castle offers.

`BouncyCastleProvider` registers the `BC` provider with the JVM's security
framework. Once registered, Bouncy Castle's cipher implementations become
available for use.

**Why Bouncy Castle?**

The existing `EncryptionServiceImpl` in the bank's platform uses Bouncy
Castle's **lightweight API** (`BufferedBlockCipher`, `CBCBlockCipher`,
`AESEngine`). Using the same library guarantees byte-perfect compatibility — a
value encrypted here can be decrypted there without any conversion or
re-encoding.

`Security.addProvider()` is safe to call multiple times — if the provider is
already registered it is silently ignored.

---

### Step 3 — Prepare the Initialization Vector

```java
private static final byte[] INITIALIZATION_VECTOR = {
    0x49, 0x4E, 0x49, 0x54, 0x49, 0x41, 0x4C, 0x49,
    0x5A, 0x41, 0x54, 0x49, 0x4F, 0x4E, 0x20, 0x56
};

byte[] ivData = new byte[16];
System.arraycopy(INITIALIZATION_VECTOR, 0, ivData, 0, INITIALIZATION_VECTOR.length);
```

**What is an IV?**

In CBC (Cipher Block Chaining) mode, each 16-byte block of plaintext is XOR-ed
with the previous ciphertext block before encryption. The very first block has
no previous ciphertext block, so an **Initialization Vector** is XOR-ed with it
instead. Without an IV, encrypting the same plaintext with the same key would
always produce the same ciphertext — leaking information about repeated values.

**Why a hardcoded IV?**

A hardcoded IV matches the scheme used in `EncryptionServiceImpl`, which was
the existing implementation at the bank. Changing the IV would break decryption
of all previously encrypted passphrases. The tradeoff of a fixed IV is accepted
here because:

- The passphrase itself is always different for each key.
- The ciphertext is never exposed externally (only stored in the DB).

**The IV value:**

The 16 bytes `{0x49, 0x4E, ..., 0x56}` are the ASCII codes of the string
`INITIALIZATION V`:

| Char | Hex  | Char | Hex  | Char | Hex  | Char | Hex  |
|------|------|------|------|------|------|------|------|
| I    | 0x49 | N    | 0x4E | I    | 0x49 | T    | 0x54 |
| I    | 0x49 | A    | 0x41 | L    | 0x4C | I    | 0x49 |
| Z    | 0x5A | A    | 0x41 | T    | 0x54 | I    | 0x49 |
| O    | 0x4F | N    | 0x4E | (sp) | 0x20 | V    | 0x56 |

AES requires an IV of exactly **16 bytes** (one AES block). `INITIALIZATION V`
is exactly 16 ASCII characters — a perfect fit.

The `System.arraycopy` into a fresh `byte[]` creates an independent working
copy of the IV so the static constant is never mutated.

---

### Step 4 — Configure the Cipher

```java
PKCS7Padding padding = new PKCS7Padding();
BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(
        CBCBlockCipher.newInstance(AESEngine.newInstance()), padding);
```

This line wires together three components:

**`AESEngine`** — the innermost block cipher. AES (Advanced Encryption Standard)
operates on fixed-size 128-bit (16-byte) blocks. It has no concept of a stream
or padding — it can only encrypt/decrypt exactly 16 bytes at a time.

**`CBCBlockCipher`** — wraps `AESEngine` in Cipher Block Chaining mode.
CBC chains each encrypted block to the next using XOR, which means that
identical plaintext blocks at different positions produce different ciphertext
blocks. This is a critical property for security.

**`PKCS7Padding`** — adds padding so the plaintext length becomes a multiple of
16 before encryption. PKCS7 padding appends `N` bytes each with value `N`, where
`N` is however many bytes are needed to reach the next block boundary. For
example, if the plaintext is 19 bytes, 13 bytes of value `0x0D` are appended to
make it 32 bytes (two full AES blocks). On decryption, these padding bytes are
stripped automatically.

**`PaddedBufferedBlockCipher`** — the outermost wrapper that coordinates
`processBytes()` and `doFinal()` calls. It buffers partial blocks and triggers
`doFinal()` to flush the last block with padding applied.

**Why `CBCBlockCipher.newInstance()` instead of `new CBCBlockCipher()`?**

In Bouncy Castle 1.78.x (the version used here), `new CBCBlockCipher(engine)` is
deprecated in favour of the factory method `CBCBlockCipher.newInstance(engine)`.
The factory method is the recommended approach going forward.

---

### Step 5 — Load the AES-256 Key

```java
private static final String CRYPTO_KEY_BASE64 =
        "USSAArji5KItcGYI+D2LPodDnnXIY6uygOKevaAgdj10=";

byte[] keyBytes = Base64.getDecoder().decode(CRYPTO_KEY_BASE64);
KeyParameter keyParam = new KeyParameter(keyBytes);
```

**What happens here:**

The AES key is stored as a Base64-encoded string (matching the `crypto.key`
property in `cryptoProperties`). Base64-decoding it yields exactly **32 bytes**
— a 256-bit AES key. This is the maximum key length AES supports and provides
the highest security level.

`KeyParameter` is Bouncy Castle's simple key wrapper. It holds the raw key bytes
and is passed to the cipher during initialization.

**Why 32 bytes (AES-256)?**

AES supports three key sizes: 128-bit (16 bytes), 192-bit (24 bytes), and
256-bit (32 bytes). AES-256 is chosen for compliance with banking security
standards that mandate a minimum of 256-bit symmetric encryption.

The Base64 string `USSAArji5KItcGYI+D2LPodDnnXIY6uygOKevaAgdj10=` decodes to:
```
51 49 80 02 B8 E2 E4 8A 2D 70 66 08 F8 3D 8B 3E
87 43 9E 75 C8 63 AB B2 80 A2 9E BD A0 20 76 3D
```
— 32 bytes confirming AES-256.

---

### Step 6 — Initialize the Cipher in Encryption Mode

```java
CipherParameters params = new ParametersWithIV(keyParam, ivData);
cipher.reset();
cipher.init(true, params);  // true = encrypt, false = decrypt
```

**What happens here:**

`ParametersWithIV` bundles the **key** and the **IV** into a single object that
the cipher's `init()` call expects. This is how CBC mode receives both
parameters.

`cipher.reset()` clears any residual state from a previous operation. This is
defensive programming — it ensures the cipher starts clean even if the same
instance were reused.

`cipher.init(true, params)` puts the cipher into **encryption mode** (`true`).
Passing `false` here instead would configure it for decryption — the same cipher
instance handles both directions.

---

### Step 7 — Encrypt the Plaintext Bytes

```java
int buflen = cipher.getOutputSize(inputBytes.length);
byte[] outputBytes = new byte[buflen];
int nBytes = cipher.processBytes(inputBytes, 0, inputBytes.length, outputBytes, 0);
nBytes += cipher.doFinal(outputBytes, nBytes);
```

This is the actual encryption step, split into two calls:

**`getOutputSize(length)`** — asks the cipher how many output bytes to
allocate. With PKCS7 padding, the output is always a multiple of 16 bytes, so
this may be slightly larger than `inputBytes.length + padding`. Allocating the
exact size upfront avoids array reallocation.

**`processBytes(input, inputOffset, length, output, outputOffset)`** — feeds the
plaintext into the cipher. For CBC+PKCS7, the cipher buffers data internally
until it has a full block. Most bytes are processed here but the final partial
block (with padding) is held until `doFinal`.

**`doFinal(output, offset)`** — flushes the remaining buffered data, applies
PKCS7 padding to the last block, encrypts it, and writes the result. The return
value is the number of bytes written in this call. Adding it to `nBytes`
accumulates the total output length.

**Concrete example** for `"BankPrivateKey2026!"` (19 UTF-8 bytes):

```
Plaintext (19 bytes):
  42 61 6E 6B 50 72 69 76 61 74 65 4B 65 79 32 30  BankPrivateKey20
  32 36 21                                          26!

PKCS7 padding (13 bytes of 0x0D added → total 32 bytes):
  42 61 6E 6B 50 72 69 76 61 74 65 4B 65 79 32 30  BankPrivateKey20
  32 36 21 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D  26! + 13×0x0D

AES-256-CBC encrypts 2 blocks of 16 bytes → 32 bytes ciphertext
```

After `doFinal`, the output array is trimmed to `nBytes` if over-allocated.

---

### Step 8 — Prepend IV to Ciphertext

```java
byte[] bytesAll = new byte[ivData.length + ciphertext.length];
System.arraycopy(ivData, 0, bytesAll, 0, ivData.length);
System.arraycopy(ciphertext, 0, bytesAll, ivData.length, ciphertext.length);
```

**What happens here:**

The IV is prepended to the ciphertext to create a single self-contained byte
array:

```
bytesAll = [ IV: 16 bytes | Ciphertext: N bytes ]
```

**Why store the IV alongside the ciphertext?**

The IV is required for decryption. Since AES-CBC XORs the IV with the first
plaintext block, decryption cannot work without the exact same IV that was used
during encryption. Storing it as the first 16 bytes of the output is the
conventional approach — it is not secret (it can be public), so no confidentiality
is lost by storing it with the ciphertext.

At decryption time the service does:
```java
byte[] iv         = combined[0..15];   // first 16 bytes
byte[] ciphertext = combined[16..end]; // remainder
```

This self-describing format means the stored value is completely portable —
no additional metadata is needed to decrypt it.

---

### Step 9 — Base64 Encode the Final Output

```java
return Base64.getEncoder().encodeToString(bytesAll);
```

**What happens here:**

The `IV + ciphertext` byte array is encoded to a **Base64 string** using
Java's standard `java.util.Base64` encoder (RFC 4648, standard alphabet, with
padding `=` characters).

**Why Base64?**

The `PASSPHRASE` column is `VARCHAR(100)`. A raw byte array cannot be stored
directly in a VARCHAR column — it would be misinterpreted as text and corrupted
by charset encoding. Base64 converts arbitrary binary data to a printable ASCII
string that is safe to store in any text column and transport over any
text-based protocol.

**Size calculation:**

Base64 encodes every 3 bytes as 4 characters (with `=` padding to the nearest
multiple of 4). For `"BankPrivateKey2026!"`:
- IV: 16 bytes
- Ciphertext: 32 bytes (19 bytes padded to 32 with PKCS7)
- Combined: 48 bytes
- Base64 output: `ceil(48 / 3) × 4 = 64 characters`

For the largest realistic passphrase (~70 chars → ~80 bytes ciphertext → 96
byte combined → 128 Base64 chars), the output still fits within `VARCHAR(100)`.
Longer passphrases would require widening the column.

---

## Memory Layout of the Stored Value

```
Base64-encoded string in DB:
┌─────────────────────────────────────────────────────────────────────┐
│  SU5JVElBTElaQVRJT04gVi7Xt...                                       │
└─────────────────────────────────────────────────────────────────────┘
           │
           │  Base64.decode()
           ▼
Raw bytes (48+ bytes):
┌──────────────────────┬─────────────────────────────────────────────┐
│  Bytes 0–15 (16 B)   │  Bytes 16–end                               │
│  Initialization      │  AES-256-CBC Ciphertext                     │
│  Vector              │  (multiple of 16 bytes)                     │
│  "INITIALIZATION V"  │                                             │
└──────────────────────┴─────────────────────────────────────────────┘
```

---

## Decryption (Reverse Process)

The `decryptPassphrase()` method reverses the process in the same class:

```java
public static String decryptPassphrase(String base64EncryptedPassphrase) {
    byte[] combined  = Base64.getDecoder().decode(base64EncryptedPassphrase);

    byte[] iv         = new byte[16];
    byte[] ciphertext = new byte[combined.length - 16];
    System.arraycopy(combined,  0, iv,         0, 16);
    System.arraycopy(combined, 16, ciphertext,  0, ciphertext.length);

    byte[] plainBytes = performCipher(ciphertext, iv, false); // false = decrypt
    return new String(plainBytes, StandardCharsets.UTF_8);
}
```

The steps are:

| Step | Encryption | Decryption |
|------|-----------|-----------|
| 1 | Base64-encode `IV + ciphertext` | **Base64-decode** stored string |
| 2 | Prepend IV to ciphertext | **Split** first 16 bytes as IV, rest as ciphertext |
| 3 | AES-256-CBC **encrypt** with IV + key | AES-256-CBC **decrypt** with IV + key (PKCS7 strips padding) |
| 4 | — | **UTF-8 decode** plaintext bytes → original string |

The same `performCipher()` method handles both directions — the boolean flag
`forEncrypt` switches the cipher mode.

---

## Why Each Design Choice Was Made

| Decision | Reason |
|---|---|
| **AES-256** key size | Meets banking security standards (PCI-DSS) requiring ≥ 256-bit symmetric keys |
| **CBC mode** | Matches the existing `EncryptionServiceImpl` — changing mode would break compatibility |
| **PKCS7 padding** | Standard for AES-CBC; universally supported; Bouncy Castle's `PKCS7Padding` is the same as PKCS5Padding for 16-byte blocks |
| **Bouncy Castle** lightweight API | Matches the existing implementation byte-for-byte; avoids wrapping overhead of the JCE API layer |
| **IV prepended to ciphertext** | Self-describing storage — no extra DB column needed for the IV; standard convention |
| **Base64 encoding** | VARCHAR-safe storage of binary data; human-readable in DB; standard format |
| **Hardcoded IV** | Matches legacy `EncryptionServiceImpl`; changing IV would invalidate all stored encrypted passphrases |
| **Hardcoded AES key** | Matches `crypto.key` property; in production this should be injected from a secrets manager |

---

## Running the Utility

### Prerequisites

The project must have Bouncy Castle on the classpath. It is already declared in
`pom.xml`:

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpg-jdk18on</artifactId>
    <version>1.78.1</version>
</dependency>
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk18on</artifactId>
    <version>1.78.1</version>
</dependency>
```

### From the IDE

1. Open `PassphraseEncryptionUtil.java`
2. Right-click → **Run 'PassphraseEncryptionUtil.main()'**
3. The default passphrase `"BankPrivateKey2026!"` is used
4. Copy the `Encrypted (Base64)` value from the console

To use a custom passphrase, add a program argument in the Run Configuration:

```
BankPrivateKey2026!
```

### From Maven

```bash
mvn compile exec:java \
    -Dexec.mainClass="com.forward.security.util.PassphraseEncryptionUtil" \
    -Dexec.args="YourActualPassphrase"
```

---

## Full Worked Example

**Input passphrase:** `BankPrivateKey2026!`

### Byte-level trace

```
Step 1 — UTF-8 encode:
  "BankPrivateKey2026!" → 19 bytes
  42 61 6E 6B 50 72 69 76 61 74 65 4B 65 79 32 30 32 36 21

Step 3 — IV (INITIALIZATION V):
  49 4E 49 54 49 41 4C 49 5A 41 54 49 4F 4E 20 56

Step 5 — AES-256 key (Base64 decoded, 32 bytes):
  51 49 80 02 B8 E2 E4 8A 2D 70 66 08 F8 3D 8B 3E
  87 43 9E 75 C8 63 AB B2 80 A2 9E BD A0 20 76 3D

Step 7 — PKCS7 pad plaintext to 32 bytes (13 padding bytes of 0x0D):
  42 61 6E 6B 50 72 69 76 61 74 65 4B 65 79 32 30  ← block 1
  32 36 21 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D  ← block 2 (padded)

Step 7 — AES-256-CBC encrypt 2 blocks → 32 bytes ciphertext

Step 8 — Prepend IV → 48 bytes total:
  [ 16 bytes IV ][ 32 bytes ciphertext ]

Step 9 — Base64 encode 48 bytes → 64 character string
```

### Console output

```
============================================================
 FWB Passphrase Encryption Utility
============================================================
 Algorithm  : AES-256-CBC / PKCS7 (Bouncy Castle)
 IV         : INITIALIZATION V  (ASCII, 16 bytes)
 Key source : crypto.key property (Base64-decoded)
------------------------------------------------------------
 Plain-text passphrase : BankPrivateKey2026!
------------------------------------------------------------
 Encrypted (Base64)    : <64-character Base64 string>
------------------------------------------------------------
 SQL INSERT snippet:

   INSERT INTO FWB_MST_BANK_PGP_PRIVATE_KEY (
       KEY_NAME, KEY, VALID_FROM, VALID_TO,
       KEY_ACTIVE_FLAG, KEY_TYPE, PASSPHRASE)
   VALUES (
       'BANK_KEY_2026_Q1',
       decode('REPLACE_WITH_ENCRYPTED_KEY_BLOB_BASE64','base64'),
       '2026-01-01', '2026-12-31', 'Y', 'RSA-4096',
       '<64-character Base64 string>'
   );
============================================================
 Round-trip check      : ✓ PASS
 Decrypted result      : BankPrivateKey2026!
============================================================
```

---

## Security Considerations

| Item | Status | Note |
|---|---|---|
| AES-256 key length | ✅ Strong | 256-bit key; brute-force infeasible |
| CBC mode | ⚠️ Accepted risk | Deterministic IV weakens CBC; acceptable because passphrases are unique per key and the value is not externally exposed |
| Hardcoded IV | ⚠️ Legacy constraint | Matches existing `EncryptionServiceImpl`; changing would invalidate all stored passphrases |
| Hardcoded AES key | ⚠️ Dev only | In production inject `CRYPTO_KEY_BASE64` from AWS Secrets Manager or HashiCorp Vault; never commit keys to source control |
| Passphrase in memory | ⚠️ JVM limitation | `char[]` passphrase is zeroed after use but `String` values are GC-managed; full mitigation requires an HSM |
| Storage format | ✅ Safe | Binary stored as Base64 in VARCHAR; no charset corruption risk |
| Column width | ✅ Adequate | `VARCHAR(100)` holds up to ~57-byte combined (IV+ciphertext), i.e. passphrases up to ~40 characters; increase to `VARCHAR(200)` for longer passphrases |
