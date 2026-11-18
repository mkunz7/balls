<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Antigravity BALLS workflow and evidence rules. -->

# Cryptographic Vulnerability Detection Skill

## Overview

Cryptographic vulnerabilities represent some of the most severe security flaws in software. When
cryptography fails, the consequences are catastrophic: confidential data exposure, authentication
bypass, data tampering, and complete loss of trust guarantees. Unlike many vulnerability classes
where defense-in-depth can mitigate impact, broken cryptography often means **total compromise**
of the protected data — past, present, and future.

### The Cardinal Rule: Don't Roll Your Own Crypto

The single most important principle in applied cryptography is: **never implement your own
cryptographic primitives or protocols**. Cryptography is uniquely unforgiving — code that appears
to work correctly can be fundamentally broken in ways that are invisible without deep expertise.
Always use well-vetted libraries (libsodium/NaCl, OpenSSL, BoringSSL, the JCA/JCE, .NET
System.Security.Cryptography) and follow their recommended high-level APIs.

### Impact of Cryptographic Failures

- **Confidentiality breach**: Weak encryption allows decryption of sensitive data at rest or in transit.
- **Integrity compromise**: Weak hashing allows undetected tampering of messages, tokens, or files.
- **Authentication bypass**: Broken signature schemes allow token forgery and identity spoofing.
- **Regulatory violations**: PCI-DSS, HIPAA, GDPR, and SOC 2 all mandate specific crypto standards.
- **Retroactive decryption**: If keys or algorithms are compromised, all previously captured ciphertext can be decrypted.

---

## Vulnerability Patterns

### 1. Weak/Deprecated Encryption Algorithms

Algorithms like DES (56-bit key), 3DES (effective 112-bit, with known attacks), RC4 (biased
keystream), and Blowfish (64-bit block size vulnerable to birthday attacks) are no longer
considered secure for any purpose.

#### Vulnerable Code Examples

**Java — DES:**
```java
// VULNERABLE: DES uses a 56-bit key, brute-forceable in hours
import javax.crypto.Cipher;
Cipher cipher = Cipher.getInstance("DES");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
byte[] encrypted = cipher.doFinal(plaintext);

// ALSO VULNERABLE: 3DES / DESede
Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
```

**Python — DES / Blowfish:**
```python
# VULNERABLE: DES via pycryptodome
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(data, DES.block_size))

# VULNERABLE: Blowfish 64-bit block
from Crypto.Cipher import Blowfish
cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)

# VULNERABLE: RC4 (ARC4)
from Crypto.Cipher import ARC4
cipher = ARC4.new(key)
```

**JavaScript/Node.js — DES / RC4:**
```javascript
// VULNERABLE: DES-ECB
const crypto = require('crypto');
const cipher = crypto.createCipheriv('des-ecb', key, null);

// VULNERABLE: RC4
const cipher = crypto.createCipheriv('rc4', key, null);

// VULNERABLE: DES-CBC
const cipher = crypto.createCipheriv('des-cbc', key, iv);
```

**C# — DES:**
```csharp
// VULNERABLE: DES
using System.Security.Cryptography;
var des = new DESCryptoServiceProvider();
des.Key = keyBytes;
des.IV = ivBytes;
ICryptoTransform encryptor = des.CreateEncryptor();

// VULNERABLE: 3DES
var tripleDes = new TripleDESCryptoServiceProvider();

// VULNERABLE: RC2
var rc2 = new RC2CryptoServiceProvider();
```

**Go — DES:**
```go
// VULNERABLE: DES
import "crypto/des"
block, err := des.NewCipher(key)

// VULNERABLE: 3DES
block, err := des.NewTripleDESCipher(key)
```

**PHP — DES / Blowfish:**
```php
// VULNERABLE: DES
$encrypted = openssl_encrypt($data, 'des-cbc', $key, 0, $iv);

// VULNERABLE: RC4
$encrypted = openssl_encrypt($data, 'rc4', $key);

// VULNERABLE: Blowfish
$encrypted = openssl_encrypt($data, 'bf-cbc', $key, 0, $iv);
```

**Ruby — DES:**
```ruby
# VULNERABLE: DES
cipher = OpenSSL::Cipher::DES.new('CBC')
cipher.encrypt
cipher.key = key
```

#### Detection Patterns (grep)
```
# Java
Cipher\.getInstance\(\s*"DES"
Cipher\.getInstance\(\s*"DESede
Cipher\.getInstance\(\s*"RC4"
Cipher\.getInstance\(\s*"Blowfish"

# Python
DES\.new\(
Blowfish\.new\(
ARC4\.new\(
from Crypto\.Cipher import DES
from Crypto\.Cipher import Blowfish
from Crypto\.Cipher import ARC4

# JavaScript/Node.js
createCipheriv\(\s*['"]des
createCipheriv\(\s*['"]rc4
createCipheriv\(\s*['"]bf-
createDecipheriv\(\s*['"]des
createDecipheriv\(\s*['"]rc4

# C#
DESCryptoServiceProvider
TripleDESCryptoServiceProvider
RC2CryptoServiceProvider

# Go
des\.NewCipher
des\.NewTripleDESCipher

# PHP
openssl_encrypt\(.*, *['"]des-
openssl_encrypt\(.*, *['"]bf-
openssl_encrypt\(.*, *['"]rc4
mcrypt_encrypt\(

# Ruby
Cipher::DES
Cipher::RC4
Cipher::Blowfish
```

---

### 2. Weak/Deprecated Hash Algorithms

MD5 and SHA-1 are **cryptographically broken** for integrity, digital signatures, and
certificate validation. Collision attacks against MD5 are trivial; SHA-1 collisions have been
publicly demonstrated (SHAttered, 2017).

> **Important distinction**: MD5/SHA-1 used purely for non-security checksums (file deduplication,
> cache keys, ETags) are **not** vulnerabilities. Password hashing is covered separately under
> authentication skills.

#### Vulnerable Code Examples

**Python:**
```python
# VULNERABLE when used for integrity/signatures
import hashlib
digest = hashlib.md5(data).hexdigest()
signature = hashlib.sha1(message).hexdigest()
```

**Java:**
```java
// VULNERABLE: MD5 for integrity
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(data);

// VULNERABLE: SHA-1 for signatures
MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
```

**JavaScript/Node.js:**
```javascript
// VULNERABLE: MD5
const hash = crypto.createHash('md5').update(data).digest('hex');

// VULNERABLE: SHA-1 for HMAC on security-critical data
const hmac = crypto.createHmac('sha1', secret).update(data).digest('hex');
```

**C#:**
```csharp
// VULNERABLE: MD5
using var md5 = MD5.Create();
byte[] hash = md5.ComputeHash(data);

// VULNERABLE: SHA-1
using var sha1 = SHA1.Create();
```

**Go:**
```go
// VULNERABLE: MD5 for integrity
import "crypto/md5"
h := md5.New()
h.Write(data)
digest := h.Sum(nil)

// VULNERABLE: SHA-1
import "crypto/sha1"
h := sha1.New()
```

**PHP:**
```php
// VULNERABLE: MD5 for integrity
$hash = md5($data);
$hash = hash('md5', $data);

// VULNERABLE: SHA-1
$hash = sha1($data);
```

#### Detection Patterns (grep)
```
# Python
hashlib\.md5\(
hashlib\.sha1\(

# Java
MessageDigest\.getInstance\(\s*"MD5"
MessageDigest\.getInstance\(\s*"SHA-1"

# JavaScript/Node.js
createHash\(\s*['"]md5
createHash\(\s*['"]sha1

# C#
MD5\.Create\(
SHA1\.Create\(
MD5CryptoServiceProvider
SHA1CryptoServiceProvider
SHA1Managed

# Go
md5\.New\(
md5\.Sum\(
sha1\.New\(
sha1\.Sum\(

# PHP
\bmd5\(
\bsha1\(
hash\(\s*['"]md5
hash\(\s*['"]sha1
```

---

### 3. Insecure Random Number Generation

Using non-cryptographic PRNGs for security-sensitive operations (token generation, key
generation, nonce creation, password resets, session IDs) allows attackers to predict generated
values and compromise security controls.

#### Vulnerable Code Examples

**JavaScript:**
```javascript
// VULNERABLE: Math.random() is NOT cryptographically secure
const token = Math.random().toString(36).substring(2);
const sessionId = Math.floor(Math.random() * 1000000);
const otp = Math.floor(Math.random() * 999999);
```

**Python:**
```python
# VULNERABLE: random module uses Mersenne Twister (predictable)
import random
token = random.randint(100000, 999999)
key = ''.join(random.choices(string.ascii_letters, k=32))
nonce = random.getrandbits(128)
```

**Java:**
```java
// VULNERABLE: java.util.Random is predictable given 2 consecutive outputs
import java.util.Random;
Random rand = new Random();
String token = String.valueOf(rand.nextLong());
byte[] key = new byte[32];
rand.nextBytes(key);  // NOT secure
```

**C/C++:**
```c
// VULNERABLE: rand() / srand() are trivially predictable
srand(time(NULL));
int token = rand();
```

**PHP:**
```php
// VULNERABLE: rand() and mt_rand() are predictable
$token = rand(100000, 999999);
$resetCode = mt_rand();
```

**Ruby:**
```ruby
# VULNERABLE: Kernel#rand uses non-crypto PRNG
token = rand(999999)
```

#### Secure Alternatives

| Language   | Insecure                      | Secure                                      |
|------------|-------------------------------|---------------------------------------------|
| JavaScript | `Math.random()`              | `crypto.randomBytes(32)`, `crypto.randomUUID()`, `crypto.getRandomValues()` |
| Python     | `random.random()`            | `secrets.token_hex()`, `secrets.token_urlsafe()`, `os.urandom()` |
| Java       | `java.util.Random`           | `java.security.SecureRandom`                |
| C#         | `System.Random`              | `RandomNumberGenerator.GetBytes()`, `RandomNumberGenerator.GetInt32()` |
| Go         | `math/rand`                  | `crypto/rand.Read()`, `crypto/rand.Int()`   |
| PHP        | `rand()`, `mt_rand()`        | `random_bytes()`, `random_int()`            |
| Ruby       | `rand()`                     | `SecureRandom.hex()`, `SecureRandom.random_bytes()` |
| C/C++      | `rand()`, `srand()`          | `/dev/urandom`, `getrandom()`, `BCryptGenRandom()` |

#### Detection Patterns (grep)
```
# JavaScript
Math\.random\(\)

# Python
import random
random\.random\(
random\.randint\(
random\.choice\(
random\.choices\(
random\.getrandbits\(

# Java
java\.util\.Random
new Random\(

# C#
new System\.Random\(
new Random\(

# Go
math/rand
rand\.Intn\(
rand\.Int\(

# PHP
\brand\(
\bmt_rand\(
\barray_rand\(

# Ruby
\brand\(
Kernel\.rand

# C/C++
\bsrand\(
\brand\(\)
```

> **Analysis note**: After finding matches, check the context. If `Math.random()` is used for
> shuffling a UI animation or `random.random()` generates test data, it is NOT a vulnerability.
> Flag only when the output feeds into security-sensitive operations (tokens, keys, nonces, OTPs,
> session IDs, password resets, CSRF tokens).

---

### 4. Hardcoded Cryptographic Keys and Secrets

Embedding encryption keys, API secrets, passwords, or initialization vectors directly in source
code means anyone with access to the code (including public repos, decompiled binaries, or
insider threats) can decrypt all protected data.

#### Vulnerable Code Examples

**Python:**
```python
# VULNERABLE: Hardcoded AES key
SECRET_KEY = "mysecretkey12345"
AES_KEY = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
ENCRYPTION_PASSWORD = "SuperSecretPassword123!"
```

**Java:**
```java
// VULNERABLE: Hardcoded keys
private static final String SECRET = "MyHardcodedSecret";
private static final byte[] KEY = "0123456789abcdef".getBytes();
private static final String API_KEY = "sk-proj-abc123xyz";
```

**JavaScript/Node.js:**
```javascript
// VULNERABLE: Hardcoded keys
const SECRET_KEY = 'my-secret-encryption-key';
const JWT_SECRET = 'super-secret-jwt-key-dont-share';
const encryptionKey = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
```

**C#:**
```csharp
// VULNERABLE: Hardcoded keys
private const string EncryptionKey = "MySecretKey12345";
private static readonly byte[] IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
```

**Go:**
```go
// VULNERABLE: Hardcoded keys
var encryptionKey = []byte("my-secret-key-32-bytes-long!!!!!")
var hmacSecret = []byte("hardcoded-hmac-secret")
```

#### Detection Patterns (grep)
```
# Variable name patterns with string literal assignments
(SECRET_KEY|ENCRYPTION_KEY|AES_KEY|HMAC_KEY|API_KEY|PRIVATE_KEY)\s*=\s*["'`]
(secret|password|token|api_key|apikey)\s*[:=]\s*["'`][^"'`]{8,}
(key|secret|password)\s*=\s*["'`b][^"'`]{8,}

# Hardcoded IVs (all-zero or static)
iv\s*=\s*(b['"]\\x00|bytes\(\[0|new byte\[\]\s*\{(\s*0\s*,?)+)
IV\s*=\s*["'`]
nonce\s*=\s*["'`]

# Base64-encoded keys in source
["'][A-Za-z0-9+/=]{20,}["']

# Hex-encoded keys
["'][0-9a-fA-F]{32,}["']
```

---

### 5. ECB Mode Usage

ECB (Electronic Codebook) mode encrypts each block independently with the same key. Identical
plaintext blocks produce identical ciphertext blocks, **leaking patterns** in the data. This is
the classic "ECB penguin" problem. ECB mode should never be used for encrypting data longer
than a single block.

#### Vulnerable Code Examples

**Java:**
```java
// VULNERABLE: ECB mode
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
Cipher cipher = Cipher.getInstance("AES");  // WARNING: default is ECB in many providers
```

**Python:**
```python
# VULNERABLE: ECB mode
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
```

**JavaScript/Node.js:**
```javascript
// VULNERABLE: ECB mode
const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
```

**C#:**
```csharp
// VULNERABLE: ECB mode
aes.Mode = CipherMode.ECB;
```

**Go:**
```go
// VULNERABLE: Using block cipher directly without a mode (effectively ECB)
block, _ := aes.NewCipher(key)
block.Encrypt(ciphertext, plaintext) // Single-block ECB
```

**PHP:**
```php
// VULNERABLE: ECB mode
$encrypted = openssl_encrypt($data, 'aes-256-ecb', $key);
```

#### Detection Patterns (grep)
```
# Java
Cipher\.getInstance\(\s*"AES"\s*\)        # Default is often ECB
Cipher\.getInstance\(\s*"AES/ECB
Cipher\.getInstance\(\s*"[^"]*ECB

# Python
MODE_ECB
AES\.MODE_ECB

# JavaScript/Node.js
aes-\d+-ecb
aes-128-ecb|aes-192-ecb|aes-256-ecb

# C#
CipherMode\.ECB

# PHP
aes-\d+-ecb
```

---

### 6. CBC Without Authentication (Padding Oracle Attacks)

AES-CBC provides confidentiality but **not integrity**. Without a separate MAC (HMAC), an
attacker can manipulate ciphertext and use padding error responses to decrypt data one byte at
a time (Padding Oracle attack). This was exploited in real-world attacks against ASP.NET,
JavaServer Faces, and many custom protocols.

#### Vulnerable Pattern

```python
# VULNERABLE: CBC without authentication
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(data, AES.block_size))
# No HMAC computed over ciphertext — padding oracle possible
```

```java
// VULNERABLE: CBC without HMAC
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
byte[] ciphertext = cipher.doFinal(plaintext);
// Ciphertext sent without authentication tag
```

#### Secure Alternatives

```python
# SECURE: AES-GCM (authenticated encryption)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(data)
# tag provides authentication — tampering is detected

# SECURE: CBC + HMAC (Encrypt-then-MAC)
from Crypto.Cipher import AES
import hmac, hashlib
cipher = AES.new(key_enc, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(data, AES.block_size))
mac = hmac.new(key_mac, iv + ciphertext, hashlib.sha256).digest()
```

```java
// SECURE: AES-GCM
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
byte[] ciphertext = cipher.doFinal(plaintext);
```

#### Detection Strategy

1. Search for CBC usage without a nearby HMAC/MAC computation.
2. Look for `AES/CBC/PKCS5Padding` in Java, `MODE_CBC` in Python, `aes-*-cbc` in Node.js.
3. Trace the ciphertext — is an HMAC computed over it before storage/transmission?
4. If the application returns different errors for "bad padding" vs "bad MAC," a padding oracle exists.

---

### 7. IV/Nonce Reuse

Reusing an initialization vector (IV) or nonce with the same key is catastrophic for most
cipher modes. For **AES-GCM**, nonce reuse allows an attacker to recover the authentication key
and forge messages. For **CBC**, IV reuse leaks whether two plaintexts share a common prefix.
For **CTR/stream ciphers**, nonce reuse enables XOR of plaintexts (complete break).

#### Vulnerable Code Examples

```python
# VULNERABLE: Static IV
iv = b'\x00' * 16  # All-zero IV reused for every encryption
cipher = AES.new(key, AES.MODE_CBC, iv)

# VULNERABLE: Predictable counter nonce
nonce = struct.pack('>Q', message_count)  # If counter resets, nonce repeats
```

```java
// VULNERABLE: Hardcoded IV
byte[] iv = new byte[16]; // All zeros
IvParameterSpec ivSpec = new IvParameterSpec(iv);
cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

// VULNERABLE: Same IV reused
private static final byte[] STATIC_IV = "1234567890abcdef".getBytes();
```

```javascript
// VULNERABLE: Static IV
const iv = Buffer.alloc(16, 0); // All zeros
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

// VULNERABLE: Hardcoded nonce for GCM
const nonce = Buffer.from('000000000000000000000000', 'hex');
```

```go
// VULNERABLE: Static nonce for GCM — catastrophic
nonce := make([]byte, 12) // All zeros, reused
aead.Seal(nil, nonce, plaintext, nil)
```

#### Secure Pattern
```python
# SECURE: Random IV for each encryption
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)

# SECURE: Random nonce for GCM
cipher = AES.new(key, AES.MODE_GCM)  # Generates random nonce automatically
```

#### Detection Patterns (grep)
```
# Static/all-zero IVs
iv\s*=\s*(b['"]\\x00|bytes\(\d+\)|Buffer\.alloc\(|new byte\[|make\(\[\]byte)
IV\s*=\s*["'][0-9a-fA-F]+["']
nonce\s*=\s*(make\(\[\]byte|new byte\[|Buffer\.(alloc|from))

# Hardcoded IV as constant
(static|final|const)\s+.*[Ii][Vv]\s*=
(STATIC_IV|DEFAULT_IV|FIXED_IV|CONSTANT_IV)
```

---

### 8. RSA Without Proper Padding

Raw RSA (textbook RSA) and PKCS#1 v1.5 padding are vulnerable. Textbook RSA is deterministic
and malleable. PKCS#1 v1.5 is vulnerable to the Bleichenbacher attack, which allows decryption
through an adaptive chosen-ciphertext attack against the padding validation oracle.

#### Vulnerable Code Examples

**Java:**
```java
// VULNERABLE: RSA with PKCS1 v1.5 padding
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

// VULNERABLE: No padding specified (defaults may vary)
Cipher cipher = Cipher.getInstance("RSA");

// VULNERABLE: NoPadding (textbook RSA)
Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
```

**Python:**
```python
# VULNERABLE: PKCS1 v1.5
from Crypto.Cipher import PKCS1_v1_5
cipher = PKCS1_v1_5.new(key)
ciphertext = cipher.encrypt(message)
```

**C#:**
```csharp
// VULNERABLE: PKCS1 v1.5 (default for RSA.Encrypt with false parameter)
byte[] encrypted = rsa.Encrypt(data, false); // false = PKCS1v1.5
```

#### Secure Alternatives

```java
// SECURE: RSA-OAEP with SHA-256
Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
```

```python
# SECURE: OAEP padding
from Crypto.Cipher import PKCS1_OAEP
cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(message)
```

```csharp
// SECURE: OAEP
byte[] encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
// or
byte[] encrypted = rsa.Encrypt(data, true); // true = OAEP
```

#### Detection Patterns (grep)
```
# Java
Cipher\.getInstance\(\s*"RSA"\s*\)
Cipher\.getInstance\(\s*"RSA/ECB/PKCS1Padding"
Cipher\.getInstance\(\s*"RSA/ECB/NoPadding"

# Python
PKCS1_v1_5\.new

# C#
\.Encrypt\([^,]+,\s*false\s*\)
RSAEncryptionPadding\.Pkcs1
```

---

### 9. Weak RSA Key Sizes

RSA keys below 2048 bits are considered weak. Keys of 1024 bits or less are practically
breakable. NIST recommends a minimum of 2048 bits, with 3072+ bits for data needing
protection beyond 2030.

#### Vulnerable Code Examples

```java
// VULNERABLE: 1024-bit RSA key
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(1024);

// VULNERABLE: 512-bit key (trivially factorable)
keyGen.initialize(512);
```

```python
# VULNERABLE: Small RSA key
from Crypto.PublicKey import RSA
key = RSA.generate(1024)
```

```go
// VULNERABLE: 1024-bit RSA
key, err := rsa.GenerateKey(rand.Reader, 1024)
```

```csharp
// VULNERABLE: Small key size
using var rsa = new RSACryptoServiceProvider(1024);
```

#### Detection Patterns (grep)
```
# Key size in RSA generation
keyGen\.initialize\(\s*(512|768|1024)\s*\)
RSA\.generate\(\s*(512|768|1024)\s*\)
rsa\.GenerateKey\(\s*[^,]+,\s*(512|768|1024)\s*\)
RSACryptoServiceProvider\(\s*(512|768|1024)\s*\)
KeySize\s*=\s*(512|768|1024)
```

---

### 10. Custom / Homebrew Cryptography

Any attempt to build cryptographic primitives from scratch — XOR "encryption," custom hash
functions, hand-rolled key exchange, proprietary ciphers — is almost certainly broken. These
implementations lack the rigorous analysis, peer review, and constant-time guarantees of
established libraries.

#### Vulnerable Code Examples

```python
# VULNERABLE: XOR "encryption"
def encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# VULNERABLE: Custom "hash"
def my_hash(data):
    h = 0
    for byte in data:
        h = (h * 31 + byte) & 0xFFFFFFFF
    return hex(h)
```

```javascript
// VULNERABLE: XOR cipher
function xorEncrypt(text, key) {
  return text.split('').map((c, i) =>
    String.fromCharCode(c.charCodeAt(0) ^ key.charCodeAt(i % key.length))
  ).join('');
}

// VULNERABLE: Base64 as "encryption"
const encrypted = Buffer.from(secret).toString('base64');
```

```java
// VULNERABLE: Custom XOR
public static byte[] encrypt(byte[] data, byte[] key) {
    byte[] result = new byte[data.length];
    for (int i = 0; i < data.length; i++) {
        result[i] = (byte) (data[i] ^ key[i % key.length]);
    }
    return result;
}
```

```go
// VULNERABLE: XOR "encryption"
func xorEncrypt(data, key []byte) []byte {
    result := make([]byte, len(data))
    for i := range data {
        result[i] = data[i] ^ key[i%len(key)]
    }
    return result
}
```

#### Detection Patterns (grep)
```
# XOR encryption patterns
\^\s*key\[
\bxor\s*(encrypt|cipher|crypt)
charCodeAt.*\^
data\[i\]\s*\^\s*key\[

# Base64 as "encryption"
(encrypt|encode).*base64
base64.*(encrypt|secret|password|key)

# Custom hash function names
def\s+(my_hash|custom_hash|simple_hash|hash_password)
function\s+(myHash|customHash|simpleHash)
```

---

### 11. Certificate Validation Bypass

Disabling TLS certificate verification allows man-in-the-middle attacks. Attackers on the
network path can intercept, read, and modify all "encrypted" traffic. This completely negates
the security of TLS.

#### Vulnerable Code Examples

**Python (requests):**
```python
# VULNERABLE: Disables certificate verification
import requests
response = requests.get('https://api.example.com', verify=False)

# VULNERABLE: Custom session with verify disabled
session = requests.Session()
session.verify = False

# VULNERABLE: urllib3 warnings suppressed to hide the insecurity
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

**Go:**
```go
// VULNERABLE: Skip certificate verification
tr := &http.Transport{
    TLSClientConfig: &tls.Config{
        InsecureSkipVerify: true,
    },
}
client := &http.Client{Transport: tr}
```

**JavaScript/Node.js:**
```javascript
// VULNERABLE: Disable TLS verification globally
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// VULNERABLE: Per-request
const agent = new https.Agent({ rejectUnauthorized: false });

// VULNERABLE: Ignoring TLS errors
tls.connect({ rejectUnauthorized: false });
```

**C#:**
```csharp
// VULNERABLE: Accept all certificates
ServicePointManager.ServerCertificateValidationCallback =
    (sender, cert, chain, errors) => true;

// VULNERABLE: HttpClientHandler
handler.ServerCertificateCustomValidationCallback =
    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

// VULNERABLE: Lambda always returning true
handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
```

**Java:**
```java
// VULNERABLE: TrustManager that accepts everything
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};
SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAllCerts, new SecureRandom());

// VULNERABLE: HostnameVerifier bypass
HostnameVerifier allHostsValid = (hostname, session) -> true;
```

**Ruby:**
```ruby
# VULNERABLE: Disable SSL verification
http = Net::HTTP.new(uri.host, uri.port)
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
```

**PHP:**
```php
// VULNERABLE: Disable SSL verification in cURL
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

// VULNERABLE: Guzzle
$client = new \GuzzleHttp\Client(['verify' => false]);
```

#### Detection Patterns (grep)
```
# Python
verify\s*=\s*False
\.verify\s*=\s*False
disable_warnings.*InsecureRequestWarning

# Go
InsecureSkipVerify\s*:\s*true

# JavaScript/Node.js
NODE_TLS_REJECT_UNAUTHORIZED.*['"]0['"]
rejectUnauthorized\s*:\s*false

# C#
ServerCertificateValidationCallback\s*=.*=>\s*true
DangerousAcceptAnyServerCertificateValidator
ServerCertificateCustomValidationCallback.*true

# Java
TrustAllCerts
checkServerTrusted.*\{\s*\}
HostnameVerifier.*->\s*true
ALLOW_ALL_HOSTNAME_VERIFIER

# Ruby
VERIFY_NONE

# PHP
CURLOPT_SSL_VERIFYPEER\s*,\s*false
CURLOPT_SSL_VERIFYHOST\s*,\s*(false|0)
['"]verify['"]\s*=>\s*false
```

---

### 12. Weak TLS Configuration

Allowing TLS 1.0, TLS 1.1, or SSL 3.0 exposes connections to known protocol-level attacks
(BEAST, POODLE, Lucky13). Weak cipher suites (RC4, DES, export-grade) further reduce security.
Missing HSTS headers allow SSL-stripping attacks.

#### Vulnerable Code Examples

```python
# VULNERABLE: Allowing old TLS versions
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)   # TLS 1.0 only
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1) # TLS 1.1 only
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)   # Allows SSL 3.0
```

```java
// VULNERABLE: Enabling old TLS
SSLContext ctx = SSLContext.getInstance("TLSv1");
SSLContext ctx = SSLContext.getInstance("TLSv1.1");

// VULNERABLE: Enabling weak cipher suites
socket.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_RC4_128_SHA"});
```

```go
// VULNERABLE: Allowing TLS 1.0
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS10,
}
```

```csharp
// VULNERABLE: Enabling old protocols
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls; // TLS 1.0
ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls;
```

#### Detection Patterns (grep)
```
# Python
PROTOCOL_TLSv1[^_2]
PROTOCOL_TLSv1_1
PROTOCOL_SSLv2
PROTOCOL_SSLv3
PROTOCOL_SSLv23

# Java
SSLContext\.getInstance\(\s*"TLSv1"[^.]
SSLContext\.getInstance\(\s*"TLSv1\.1"
SSLContext\.getInstance\(\s*"SSL"

# Go
VersionTLS10
VersionTLS11
VersionSSL30

# C#
SecurityProtocolType\.Ssl3
SecurityProtocolType\.Tls[^1]
SslProtocols\.Tls11
SslProtocols\.Ssl3

# Config files
ssl_protocols.*TLSv1[^.2]
MinProtocol.*TLSv1[^.2]
```

---

## Detection Methodology

### Phase 1: Automated Pattern Scanning

Run grep scans for each vulnerability category. Start broad, then triage:

```bash
# Step 1: Find all crypto-related files
grep -r --include="*.py" --include="*.java" --include="*.js" --include="*.ts" \
  --include="*.cs" --include="*.go" --include="*.php" --include="*.rb" \
  -l "(Cipher|cipher|crypto|Crypto|hashlib|MessageDigest|AES|RSA|DES)" .

# Step 2: Scan for weak algorithms
grep -rn "DES\b|RC4|Blowfish|MD5|SHA-?1" --include="*.{py,java,js,ts,cs,go,php,rb}" .

# Step 3: Scan for insecure random
grep -rn "Math\.random\(\)|java\.util\.Random|random\.rand|srand\(|mt_rand" .

# Step 4: Scan for hardcoded keys
grep -rn "(SECRET_KEY|ENCRYPTION_KEY|API_KEY|PRIVATE_KEY)\s*=\s*[\"']" .

# Step 5: Scan for ECB mode
grep -rn "ECB|MODE_ECB|aes-.*-ecb" .

# Step 6: Scan for certificate bypass
grep -rn "verify.*False|InsecureSkipVerify|VERIFY_NONE|rejectUnauthorized.*false" .

# Step 7: Scan for weak TLS
grep -rn "TLSv1[^.2]|SSLv[23]|PROTOCOL_TLS\b" .
```

### Phase 2: Contextual Analysis

For each finding from Phase 1:

1. **Read the surrounding code** (20-30 lines of context) to understand the purpose.
2. **Trace data flow**: Where does the output go? Is it security-sensitive?
3. **Check for mitigating controls**: Is CBC paired with HMAC? Is the weak hash used only for caching?
4. **Verify file context**: Is this test code? Development-only configuration? Dead code?
5. **Check for configuration guards**: Is `InsecureSkipVerify` behind an `if env == "dev"` check?

### Phase 3: Cross-Reference

- Check if hardcoded keys also appear in configuration files, environment variable loaders, or secret managers.
- Verify that weak algorithm usage isn't already flagged in the project's TODO/FIXME comments.
- Look for crypto utility/helper modules that centralize cryptographic operations — a single fix there may resolve multiple findings.

---

## Common Sinks and Sources

### Sources (where crypto inputs originate)
- User-supplied passwords → key derivation functions
- Configuration files → encryption keys, TLS settings
- Environment variables → secrets, API keys
- Key management services (KMS) → encryption keys
- Certificate stores → TLS certificates
- Random number generators → IVs, nonces, tokens

### Sinks (where crypto is consumed)
- `Cipher.getInstance()` / `crypto.createCipheriv()` — encryption operations
- `MessageDigest` / `hashlib` / `crypto.createHash()` — hashing operations
- `SSLContext` / `tls.Config` — TLS configuration
- `requests.get()` / `http.Client` — HTTP clients with TLS
- `jwt.encode()` / `JWT.create()` — token signing
- `Signature.getInstance()` — digital signatures
- Database connection strings — TLS configuration for data in transit
- File I/O with encrypted data — encryption at rest

---

## False Positive Indicators

### MD5/SHA-1 for Non-Security Purposes (NOT vulnerabilities)
```python
# FALSE POSITIVE: MD5 for cache key generation (no security implication)
cache_key = hashlib.md5(url.encode()).hexdigest()

# FALSE POSITIVE: MD5 for file deduplication/checksum
file_hash = hashlib.md5(open(path, 'rb').read()).hexdigest()

# FALSE POSITIVE: SHA-1 as Git object identifier (by design)
```

### Math.random() for Non-Security Purposes
```javascript
// FALSE POSITIVE: UI randomization
const randomColor = `hsl(${Math.random() * 360}, 70%, 50%)`;

// FALSE POSITIVE: Shuffling display order
array.sort(() => Math.random() - 0.5);

// FALSE POSITIVE: Random delay for jitter
const delay = Math.random() * 1000;
```

### Test-Only Code
- Hardcoded keys in files matching `*_test.go`, `*Test.java`, `*.test.js`, `*.spec.ts`, `test_*.py`, `tests/`, `__tests__/`
- `InsecureSkipVerify` in test setup with clear test-only scope
- Weak algorithms used in test assertions or test data generation

### Development-Only Configuration
```go
// FALSE POSITIVE if properly guarded
if os.Getenv("ENV") == "development" {
    tlsConfig.InsecureSkipVerify = true
}
```
> **Caution**: Even development-only bypasses can be false positives, but verify the guard
> is robust. Environment variable checks can be spoofed or misconfigured in production.

### Legacy Compatibility Wrappers
- Code that explicitly documents backward compatibility with a tracked migration plan
- Deprecated functions wrapped with logging/alerting for sunset tracking

---

## Severity Assessment

### Critical (CVSS 9.0+)
- **Hardcoded private keys** for production encryption or signing
- **Nonce reuse with AES-GCM** (enables key recovery and forgery)
- **Certificate validation completely disabled** in production HTTP clients
- **Custom XOR encryption** protecting sensitive data (passwords, PII, financial)
- **Textbook RSA** (no padding) on production data

### High (CVSS 7.0-8.9)
- **ECB mode** encrypting structured or repetitive data (user records, API payloads)
- **DES/RC4** used for production encryption
- **RSA with 1024-bit keys** in production
- **PKCS#1 v1.5** encryption padding (Bleichenbacher-vulnerable)
- **CBC without MAC** in a network protocol (padding oracle)
- **Static IV** with AES-CBC across multiple messages

### Medium (CVSS 4.0-6.9)
- **Math.random()/java.util.Random** generating session tokens or CSRF tokens
- **MD5/SHA-1** used for integrity verification of security-relevant data
- **TLS 1.0/1.1** enabled but TLS 1.2+ also supported
- **Weak RSA key** (< 2048 bits) for non-critical signing

### Low (CVSS 1.0-3.9)
- **MD5** used for checksums where collision resistance is not required
- **InsecureSkipVerify** in test code with proper environment guards
- **3DES** in legacy code with documented migration plan
- **Weak TLS** in internal-only services with network-level controls

---

## Remediation Patterns

### Replace Weak Algorithms with Strong Alternatives

| Weak                        | Secure Replacement                          |
|-----------------------------|---------------------------------------------|
| DES, 3DES, RC4, Blowfish   | AES-256-GCM, ChaCha20-Poly1305             |
| MD5, SHA-1 (security use)  | SHA-256, SHA-3, BLAKE2b                     |
| RSA-1024                    | RSA-2048+ or Ed25519/ECDSA P-256            |
| RSA PKCS#1 v1.5             | RSA-OAEP with SHA-256                       |
| ECB mode                    | GCM, CCM, or CBC + HMAC (Encrypt-then-MAC) |
| CBC without MAC             | AES-GCM, ChaCha20-Poly1305                 |
| Math.random()               | crypto.randomBytes() / secrets module       |
| Custom XOR cipher           | libsodium secretbox / AES-GCM              |

### Move Secrets to Proper Key Management

```python
# BEFORE (vulnerable):
SECRET_KEY = "hardcoded-secret-key-123"

# AFTER (secure):
import os
SECRET_KEY = os.environ["SECRET_KEY"]

# BEST: Use a secrets manager
from azure.keyvault.secrets import SecretClient
client = SecretClient(vault_url="https://myvault.vault.azure.net/", credential=credential)
SECRET_KEY = client.get_secret("encryption-key").value
```

### Use High-Level Crypto Libraries

```python
# BEST: Use libsodium (PyNaCl) — misuse-resistant API
from nacl.secret import SecretBox
box = SecretBox(key)
encrypted = box.encrypt(plaintext)  # Handles nonce generation, authentication

# GOOD: Use Fernet (symmetric, authenticated)
from cryptography.fernet import Fernet
key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(plaintext)
```

```javascript
// GOOD: Use libsodium
const sodium = require('libsodium-wrappers');
await sodium.ready;
const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
const ciphertext = sodium.crypto_secretbox_easy(message, nonce, key);
```

### Fix TLS Configuration

```python
# SECURE: Enforce TLS 1.2+
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
# Optionally enforce 1.3
context.minimum_version = ssl.TLSVersion.TLSv1_3
```

```go
// SECURE: Enforce TLS 1.2+
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
}
```

```csharp
// SECURE: Enforce TLS 1.2+
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
```

---

## CWE References

| CWE      | Name                                                    | Patterns Covered                           |
|----------|---------------------------------------------------------|--------------------------------------------|
| CWE-326  | Inadequate Encryption Strength                          | Weak RSA key sizes, short keys             |
| CWE-327  | Use of a Broken or Risky Cryptographic Algorithm        | DES, RC4, MD5, SHA-1, ECB mode             |
| CWE-328  | Use of Weak Hash                                        | MD5, SHA-1 for integrity/signatures        |
| CWE-329  | Generation of Predictable IV with CBC Mode              | Static IV, hardcoded IV, IV reuse          |
| CWE-330  | Use of Insufficiently Random Values                     | Math.random(), java.util.Random            |
| CWE-321  | Use of Hard-coded Cryptographic Key                     | Hardcoded keys, secrets in source          |
| CWE-295  | Improper Certificate Validation                         | verify=False, InsecureSkipVerify           |
| CWE-338  | Use of Cryptographically Weak PRNG                      | Non-crypto PRNGs for security operations   |
| CWE-757  | Selection of Less-Secure Algorithm During Negotiation   | Weak TLS versions, downgrade attacks       |
| CWE-916  | Use of Password Hash With Insufficient Computational Effort | Weak hashing (when applied to passwords) |

### Additional Relevant CWEs
- **CWE-261**: Weak Encoding for Password
- **CWE-780**: Use of RSA Algorithm without OAEP
- **CWE-323**: Reusing a Nonce, Key Pair in Encryption
- **CWE-325**: Missing Cryptographic Step (e.g., missing MAC on CBC)
- **CWE-347**: Improper Verification of Cryptographic Signature
