<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Antigravity BALLS workflow and evidence rules. -->

## Overview

Sensitive data exposure occurs when applications fail to adequately protect confidential information throughout its lifecycle — in transit, at rest, and during processing. This includes leaking PII through API responses, storing tokens in client-side storage accessible to JavaScript, transmitting credentials over unencrypted channels, exposing internal system details through error messages, and leaving backup files, source maps, or version control directories accessible. Unlike targeted injection attacks, data exposure often results from design oversights that inadvertently make sensitive information available to unauthorized parties.

## Vulnerability Patterns

### PII in API Responses

```python
# Python/Django — VULNERABLE: Serializer exposes all fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # VULNERABLE: Includes SSN, password hash, internal notes

# API response:
# {
#   "id": 42,
#   "email": "user@example.com",
#   "password_hash": "$2b$12$LJ3m4ys...",
#   "ssn": "123-45-6789",
#   "date_of_birth": "1990-01-15",
#   "phone": "+1-555-0123",
#   "internal_notes": "High-value customer",
#   "credit_score": 780,
#   "bank_account": "1234567890"
# }
```

```javascript
// Node.js — VULNERABLE: Database record returned directly
app.get('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    // VULNERABLE: Returns entire MongoDB/SQL document
    // Including: passwordHash, resetToken, mfaSecret, stripeCustomerId
    res.json(user);
});

// VULNERABLE: List endpoint leaks other users' PII
app.get('/api/users/search', async (req, res) => {
    const users = await User.find({ name: { $regex: req.query.q } });
    // Returns full user objects for all matches — PII of other users exposed
    res.json(users);
});
```

```java
// Java — VULNERABLE: Entity with sensitive fields
@Entity
public class Employee {
    @Id private Long id;
    private String name;
    private String email;
    private String socialSecurityNumber;  // VULNERABLE: Exposed via JSON
    private BigDecimal salary;            // VULNERABLE: Exposed
    private String bankAccountNumber;     // VULNERABLE: Exposed

    // JPA entity serialized directly to JSON response
}

@GetMapping("/api/employees/{id}")
public Employee getEmployee(@PathVariable Long id) {
    return employeeRepository.findById(id).orElseThrow();
    // All fields serialized — SSN, salary, bank account exposed
}
```

```go
// Go — VULNERABLE: Struct with all fields exported
type User struct {
    ID           int    `json:"id"`
    Name         string `json:"name"`
    Email        string `json:"email"`
    PasswordHash string `json:"password_hash"` // VULNERABLE
    SSN          string `json:"ssn"`           // VULNERABLE
    CreditCard   string `json:"credit_card"`   // VULNERABLE
    MFASecret    string `json:"mfa_secret"`    // VULNERABLE
}

func getUser(w http.ResponseWriter, r *http.Request) {
    user, _ := db.GetUser(userID)
    json.NewEncoder(w).Encode(user) // All fields serialized
}
```

### Sensitive Data in URL Parameters

```python
# Python — VULNERABLE: Token in URL
@app.route('/api/data')
def get_data():
    # VULNERABLE: API key in URL — logged in server logs, proxy logs, referer headers
    api_key = request.args.get('api_key')
    # URL: /api/data?api_key=STRIPE_SECRET_KEY_PLACEHOLDER
```

```javascript
// JavaScript — VULNERABLE: Auth token in URL
// VULNERABLE: Token visible in browser history, server logs, referrer header
window.location.href = `/dashboard?token=${authToken}`;

// VULNERABLE: Password reset link with token in URL (acceptable)
// but token doesn't expire quickly enough or is reusable
fetch(`/api/reset-password?token=${resetToken}&new_password=${newPassword}`);
// Password in URL — logged everywhere
```

```html
<!-- VULNERABLE: Sensitive data in GET form -->
<form action="/login" method="GET">
    <!-- VULNERABLE: GET method puts credentials in URL -->
    <input name="username" type="text">
    <input name="password" type="password">
    <button type="submit">Login</button>
</form>
```

### Client-Side Storage Vulnerabilities

```javascript
// JavaScript — VULNERABLE: Tokens in localStorage
// localStorage is accessible to any JavaScript on the same origin
// XSS can steal all tokens
localStorage.setItem('auth_token', 'eyJhbGciOiJIUzI1NiIs...');
localStorage.setItem('refresh_token', 'dGhpcyBpcyBhIHJlZnJlc2g...');
localStorage.setItem('user_data', JSON.stringify({
    email: 'user@example.com',
    ssn: '123-45-6789',       // VULNERABLE: PII in localStorage
    role: 'admin'
}));

// VULNERABLE: sessionStorage (same XSS risk)
sessionStorage.setItem('api_key', 'STRIPE_SECRET_KEY_PLACEHOLDER');

// VULNERABLE: Sensitive data in cookies without flags
document.cookie = "session_id=abc123";
// Missing: Secure, HttpOnly, SameSite flags
```

```javascript
// VULNERABLE: IndexedDB with sensitive data
const request = indexedDB.open('UserData');
request.onsuccess = (event) => {
    const db = event.target.result;
    const tx = db.transaction('users', 'readwrite');
    const store = tx.objectStore('users');
    // VULNERABLE: PII stored client-side in IndexedDB
    store.put({ id: 1, ssn: '123-45-6789', creditCard: '4111111111111111' });
};
```

### Cookie Misconfiguration

```python
# Python/Flask — VULNERABLE: Insecure cookie settings
response.set_cookie('session_id', value=session_id)
# VULNERABLE: Missing Secure flag — sent over HTTP
# VULNERABLE: Missing HttpOnly flag — accessible via JavaScript
# VULNERABLE: Missing SameSite flag — sent on cross-site requests

# VULNERABLE: Sensitive data in cookie value
response.set_cookie('user_data',
    value=json.dumps({'email': email, 'role': 'admin', 'internal_id': 12345}))
```

```javascript
// Express — VULNERABLE: Session cookie configuration
app.use(session({
    secret: 'keyboard cat',
    cookie: {
        secure: false,        // VULNERABLE: Not HTTPS-only
        httpOnly: false,      // VULNERABLE: JS-accessible
        sameSite: false,      // VULNERABLE: No SameSite
        maxAge: 365 * 24 * 60 * 60 * 1000  // VULNERABLE: 1 year session
    }
}));
```

```java
// Java — VULNERABLE: Cookie without security flags
Cookie cookie = new Cookie("session", sessionId);
// VULNERABLE: Missing setSecure(true)
// VULNERABLE: Missing setHttpOnly(true)
cookie.setMaxAge(60 * 60 * 24 * 365); // VULNERABLE: 1 year
response.addCookie(cookie);
```

### Unencrypted Database Connections

```python
# Python — VULNERABLE: No TLS on database connection
import psycopg2
conn = psycopg2.connect(
    host='database.internal',
    dbname='production',
    user='app',
    password='secret',
    sslmode='disable'  # VULNERABLE: No encryption in transit
)

# VULNERABLE: Redis without TLS
import redis
r = redis.Redis(host='redis.internal', port=6379)  # No ssl=True
```

```javascript
// Node.js — VULNERABLE: MongoDB without TLS
const mongoose = require('mongoose');
mongoose.connect('mongodb://db.internal:27017/production');
// VULNERABLE: No TLS — should use mongodb+srv:// or ssl=true option

// VULNERABLE: MySQL without encryption
const mysql = require('mysql2');
const connection = mysql.createConnection({
    host: 'db.internal',
    user: 'root',
    password: 'secret',
    database: 'production',
    // Missing: ssl: { ca: fs.readFileSync('/path/to/ca.pem') }
});
```

### Exposed Backup and Source Files

```
# Files that should NOT be accessible via web server:
/.git/                          # Git repository — full source code
/.git/config                    # May contain credentials
/.svn/                          # SVN metadata
/.env                           # Environment variables with secrets
/backup.sql                     # Database backup
/database.sql.gz                # Compressed database dump
/db_backup_2024.sql             # Database backup
/*.bak                          # Backup files
/*.old                          # Old files
/*.swp                          # Vim swap files
/*.dump                         # Memory/database dumps
/config.yml.bak                 # Config backups
/web.config.old                 # ASP.NET config backup
/phpinfo.php                    # PHP configuration exposure
/.DS_Store                      # macOS directory metadata
/Thumbs.db                      # Windows thumbnail cache
```

### Source Map Exposure

```javascript
// VULNERABLE: Source maps deployed to production
// Build output:
// dist/app.js
// dist/app.js.map          ← VULNERABLE: Exposes original source code

// webpack.config.js — VULNERABLE in production
module.exports = {
    devtool: 'source-map',  // Generates .map files
    // Should be: false (for production)
};

// next.config.js — VULNERABLE
module.exports = {
    productionBrowserSourceMaps: true,  // VULNERABLE: Source maps in production
};
```

### Error Message Information Disclosure

```python
# Python — VULNERABLE: Detailed error responses
@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': str(error),
        'traceback': traceback.format_exc(),       # VULNERABLE: Stack trace
        'database': app.config['DATABASE_URI'],     # VULNERABLE: DB connection
        'hostname': socket.gethostname(),           # VULNERABLE: Internal hostname
        'python_version': sys.version,              # VULNERABLE: Runtime version
        'environment': dict(os.environ),            # VULNERABLE: All env vars!
    }), 500
```

```javascript
// Node.js — VULNERABLE: SQL error details
app.get('/api/users/:id', async (req, res) => {
    try {
        const user = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
        res.json(user);
    } catch (err) {
        // VULNERABLE: Exposes database schema, table names, query details
        res.status(500).json({
            error: err.message,
            // "relation \"users\" does not exist" or
            // "column \"password_hash\" of relation \"users\" ..."
            query: err.query,     // VULNERABLE: SQL query exposed
            detail: err.detail,   // VULNERABLE: DB error details
        });
    }
});
```

```csharp
// C# — VULNERABLE: Exception details in response
[HttpGet("{id}")]
public IActionResult Get(int id)
{
    try {
        return Ok(_repository.Get(id));
    } catch (Exception ex) {
        // VULNERABLE: Full exception with stack trace, inner exceptions
        return StatusCode(500, new {
            Message = ex.Message,
            StackTrace = ex.StackTrace,
            InnerException = ex.InnerException?.Message,
            Source = ex.Source  // VULNERABLE: Assembly/namespace info
        });
    }
}
```

### Response Header Information Leakage

```
# VULNERABLE: Server headers reveal technology stack
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
X-Powered-By: PHP/8.1.2
X-AspNet-Version: 4.0.30319
X-AspNetMvc-Version: 5.2
X-Generator: Drupal 9
Via: 1.1 internal-proxy-01.company.com   # VULNERABLE: Internal hostname
X-Request-Id: includes-internal-data
```

### PDF/Image Metadata Exposure

```python
# Python — VULNERABLE: EXIF data not stripped from uploaded images
from PIL import Image

def save_profile_photo(uploaded_file, output_path):
    img = Image.open(uploaded_file)
    img.save(output_path)
    # VULNERABLE: EXIF metadata preserved
    # May contain: GPS coordinates, camera model, timestamp, creator name

# VULNERABLE: PDF metadata not stripped
# PDF files can contain: Author, Creator, Company, creation tool, revision history
```

```javascript
// Node.js — VULNERABLE: Serving images without stripping metadata
app.post('/upload/photo', upload.single('photo'), (req, res) => {
    // VULNERABLE: Saving file directly without metadata removal
    fs.renameSync(req.file.path, `./uploads/${req.file.filename}`);
    // EXIF GPS data, device info, timestamps all preserved
});
```

## Detection Methodology

1. **API Response Audit**: Examine all API serializers, response builders, and database queries for field-level filtering
2. **URL Parameter Scan**: Search for sensitive values (tokens, passwords, keys) passed as query parameters
3. **Client-Side Storage Audit**: Check JavaScript code for localStorage, sessionStorage, IndexedDB usage with sensitive data
4. **Cookie Configuration**: Verify all cookies have Secure, HttpOnly, and SameSite flags as appropriate
5. **Database Connection Audit**: Check all database connection strings for TLS/SSL configuration
6. **File Exposure Scan**: Check web server configuration for accessible backup files, .git directory, source maps
7. **Error Handler Review**: Examine all error handlers for stack trace, internal path, and configuration exposure
8. **Response Header Check**: Audit server response headers for technology disclosure
9. **Metadata Analysis**: Check if uploaded files have metadata stripped before serving
10. **Encryption at Rest**: Verify database encryption, file encryption, and backup encryption configurations

## Common Sinks and Sources

### Data Serialization
- **Django**: `ModelSerializer`, `fields`, `exclude`, `SerializerMethodField`
- **Express**: `res.json()`, `toJSON()`, `lean()` (Mongoose)
- **Spring**: `@JsonIgnore`, `@JsonView`, `@JsonProperty`
- **ASP.NET**: `JsonResult`, `[JsonIgnore]`, DTO classes
- **Go**: `json:"field"` tags, `json:"-"` to exclude
- **Rails**: `as_json`, `to_json`, `render json:`

### Client-Side Storage APIs
- `localStorage.setItem()`, `localStorage.getItem()`
- `sessionStorage.setItem()`, `sessionStorage.getItem()`
- `document.cookie`
- `indexedDB.open()`, `IDBObjectStore.put()`
- `window.name` (cross-page data leakage)
- `postMessage()` (cross-origin data sharing)

### Web Server Configuration
- `nginx.conf`, `apache2.conf`, `httpd.conf`
- `.htaccess`
- `web.config` (IIS)
- CDN configuration (CloudFront, Cloudflare)

### Error Handling
- `try/catch` blocks with error responses
- Global error handlers and middleware
- Framework error pages (404, 500)
- Logging configuration (what gets sent to client vs. logs)

## False Positive Indicators

- **Public data endpoints**: APIs that intentionally serve public information (product listings, public profiles)
- **User's own data**: An API returning the authenticated user's own PII in their profile endpoint (if properly scoped)
- **Admin interfaces**: Admin APIs that expose detailed data — verify admin auth is enforced
- **Development environments**: Source maps and debug errors in development mode
- **Field projections present**: MongoDB `select()` or SQL `SELECT field1, field2` limiting returned fields
- **DTO/ViewModel patterns**: Separate response classes that already filter sensitive fields
- **`@JsonIgnore` annotations**: Fields explicitly excluded from serialization
- **Encrypted cookies**: Cookie values that are encrypted (not just encoded)
- **Intentional public files**: robots.txt, sitemap.xml, public assets

## Severity Assessment

| Finding | Severity |
|---------|----------|
| Passwords/password hashes in API responses | **Critical** |
| Credit card numbers in API responses | **Critical** |
| SSN/government IDs in unprotected API responses | **Critical** |
| .git directory accessible (full source code) | **Critical** |
| Database backups accessible via web | **Critical** |
| Auth tokens stored in localStorage (XSS exploitable) | **High** |
| Sensitive data in URL query parameters | **High** |
| Cookies missing Secure + HttpOnly flags | **High** |
| Database connections without TLS | **High** |
| Stack traces with internal paths in production | **High** |
| PII in API responses to unauthorized users | **High** |
| Source maps deployed to production | **Medium** |
| Server version headers | **Medium** |
| EXIF/GPS data in user-uploaded images | **Medium** |
| Internal hostnames in error messages | **Medium** |
| Sensitive data in client-side IndexedDB | **Medium** |
| Missing Referrer-Policy header | **Low** |
| Technology fingerprinting via headers | **Low** |

## Remediation Patterns

### API Response Filtering

```python
# SECURE: Explicit field allowlist in serializer
class UserPublicSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'avatar_url']  # Only public fields

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'phone', 'avatar_url']
        # Excludes: password_hash, ssn, internal_notes, credit_score
```

```javascript
// SECURE: MongoDB projection / Mongoose select
app.get('/api/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id)
        .select('name email avatar -_id');  // Only selected fields
    res.json(user);
});
```

```java
// SECURE: Response DTO pattern
public record UserResponse(Long id, String name, String email) {
    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getName(), user.getEmail());
    }
}

@GetMapping("/api/users/{id}")
public UserResponse getUser(@PathVariable Long id) {
    User user = userRepository.findById(id).orElseThrow();
    return UserResponse.from(user);
}
```

```go
// SECURE: Separate response struct with json:"-" for sensitive fields
type User struct {
    ID           int    `json:"id"`
    Name         string `json:"name"`
    Email        string `json:"email"`
    PasswordHash string `json:"-"` // Never serialized
    SSN          string `json:"-"` // Never serialized
    MFASecret    string `json:"-"` // Never serialized
}
```

### Secure Cookie Configuration

```javascript
// SECURE: Cookie with all security flags
res.cookie('session_id', sessionId, {
    secure: true,           // HTTPS only
    httpOnly: true,         // No JavaScript access
    sameSite: 'strict',     // No cross-site sending
    maxAge: 3600000,        // 1 hour
    path: '/',
    domain: '.company.com',
});
```

### Encrypted Database Connections

```python
# SECURE: PostgreSQL with TLS
conn = psycopg2.connect(
    host='database.internal',
    dbname='production',
    user='app',
    password=os.environ['DB_PASSWORD'],
    sslmode='verify-full',
    sslrootcert='/path/to/ca.pem'
)
```

### Error Handling with Correlation IDs

```python
# SECURE: Generic error response with correlation ID
import uuid

@app.errorhandler(Exception)
def handle_error(error):
    correlation_id = str(uuid.uuid4())
    app.logger.error(f"[{correlation_id}] Unhandled error: {error}", exc_info=True)
    return jsonify({
        'error': 'An unexpected error occurred',
        'reference_id': correlation_id
    }), 500
```

### Strip Image Metadata

```python
# SECURE: Strip EXIF data from uploaded images
from PIL import Image

def strip_metadata(input_path, output_path):
    img = Image.open(input_path)
    data = list(img.getdata())
    clean_img = Image.new(img.mode, img.size)
    clean_img.putdata(data)
    clean_img.save(output_path)  # No EXIF metadata
```

### Web Server Hardening

```nginx
# SECURE: nginx configuration
server {
    server_tokens off;  # Hide version

    # Block sensitive files
    location ~ /\.git { deny all; return 404; }
    location ~ /\.env { deny all; return 404; }
    location ~ \.(bak|sql|dump|old|swp|map)$ { deny all; return 404; }
    location ~ /\.DS_Store { deny all; return 404; }

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}
```

## CWE References

- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **CWE-201**: Insertion of Sensitive Information Into Sent Data
- **CWE-209**: Generation of Error Message Containing Sensitive Information
- **CWE-215**: Insertion of Sensitive Information Into Debugging Code
- **CWE-312**: Cleartext Storage of Sensitive Information
- **CWE-319**: Cleartext Transmission of Sensitive Information
- **CWE-359**: Exposure of Private Personal Information to an Unauthorized Actor
- **CWE-497**: Exposure of Sensitive System Information to an Unauthorized Control Sphere
- **CWE-532**: Insertion of Sensitive Information into Log File
- **CWE-538**: Insertion of Sensitive Information into Externally-Accessible File or Directory
- **CWE-548**: Exposure of Information Through Directory Listing
- **CWE-614**: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **CWE-1004**: Sensitive Cookie Without 'HttpOnly' Flag
