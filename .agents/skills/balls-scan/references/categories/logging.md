<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

## Overview

Logging and monitoring vulnerabilities undermine an organization's ability to detect, investigate, and respond to security incidents. Log injection allows attackers to forge entries and evade detection, while sensitive data in logs creates secondary exposure vectors. Insufficient logging means attacks go unnoticed, and poor log access control can turn log files into targets. The OWASP Top 10 identifies "Security Logging and Monitoring Failures" as a critical risk because it enables all other attacks to succeed undetected.

## Vulnerability Patterns

### Log Injection — Newline / CRLF Injection

```python
# Python — VULNERABLE: User input in log messages
import logging

logger = logging.getLogger(__name__)

def login(request):
    username = request.POST['username']
    # VULNERABLE: Attacker sends username = "admin\nINFO Login successful for user admin"
    # This creates a fake log entry that looks like admin logged in
    logger.info(f"Login attempt for user {username}")

    # VULNERABLE: Multiline injection
    # username = "admin\n2024-01-15 10:00:00 INFO Payment processed: $0.00\nDEBUG "
    logger.warning(f"Failed login for {username} from {request.META['REMOTE_ADDR']}")
```

```javascript
// Node.js — VULNERABLE: Log injection via user input
const winston = require('winston');
const logger = winston.createLogger({ /* ... */ });

app.post('/login', (req, res) => {
    const { username } = req.body;
    // VULNERABLE: username = "admin\n[INFO] Transfer $10000 to attacker - SUCCESS"
    logger.info(`Login attempt: ${username}`);

    // VULNERABLE: HTTP header injection into logs
    const userAgent = req.headers['user-agent'];
    // userAgent = "Mozilla/5.0\n[ERROR] System compromised - ignore previous alerts"
    logger.info(`Request from UA: ${userAgent}`);
});
```

```java
// Java — VULNERABLE: Log forging
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    public void login(HttpServletRequest request) {
        String username = request.getParameter("username");
        // VULNERABLE: Unescaped user input
        logger.info("Login attempt for user: " + username);
        // Attacker: username = "admin%0d%0aINFO Login successful for user admin"
    }
}
```

```go
// Go — VULNERABLE: Log injection
func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    // VULNERABLE: Newlines in username create fake log entries
    log.Printf("Login attempt for user: %s from IP: %s", username, r.RemoteAddr)
}
```

### Sensitive Data in Logs

```python
# Python — VULNERABLE: Logging passwords and tokens
def authenticate(username, password):
    logger.debug(f"Auth attempt: user={username}, password={password}")  # VULNERABLE
    user = User.objects.get(username=username)
    if check_password(password, user.password_hash):
        token = generate_token(user)
        logger.info(f"Token generated: {token}")  # VULNERABLE: Token in logs
        return token

def process_payment(card_number, cvv, amount):
    logger.info(f"Processing payment: card={card_number}, cvv={cvv}, amount={amount}")
    # VULNERABLE: Full credit card and CVV logged
```

```javascript
// Node.js — VULNERABLE: PII and credentials in logs
app.post('/api/user/register', (req, res) => {
    const { email, password, ssn, phone } = req.body;
    // VULNERABLE: Logging entire request body with sensitive data
    console.log('Registration request:', JSON.stringify(req.body));
    // Logs: {"email":"user@example.com","password":"secret123","ssn":"123-45-6789",...}

    logger.info('Registration', { body: req.body });  // VULNERABLE: Same issue
});

// VULNERABLE: Logging auth headers
app.use((req, res, next) => {
    logger.debug('Request headers:', req.headers);
    // Logs Authorization: Bearer eyJhbGc..., Cookie: session=abc123
    next();
});
```

```java
// Java — VULNERABLE: Logging sensitive objects
@PostMapping("/api/auth/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    // VULNERABLE: toString() on request object includes password
    logger.info("Login request: {}", request);
    // Logs: LoginRequest{username='john', password='secret123'}

    try {
        User user = authService.authenticate(request);
        // VULNERABLE: Logging full user object with sensitive fields
        logger.info("Authenticated user: {}", user);
        // Logs: User{id=1, email='john@example.com', passwordHash='$2b$...', ssn='123-45-6789'}
    } catch (AuthException e) {
        // VULNERABLE: Stack trace may contain sensitive data
        logger.error("Auth failed", e);
    }
    return ResponseEntity.ok().build();
}
```

```csharp
// C# — VULNERABLE: Connection strings and secrets in logs
public void ConfigureDatabase(IConfiguration config)
{
    var connectionString = config.GetConnectionString("DefaultConnection");
    // VULNERABLE: Connection string contains password
    _logger.LogInformation("Connecting to database: {ConnectionString}", connectionString);
    // Logs: "Connecting to database: Server=prod-db;Password=SuperSecret;..."

    var apiKey = config["ExternalApi:Key"];
    _logger.LogDebug("Using API key: {ApiKey}", apiKey);  // VULNERABLE
}
```

### Missing Security Event Logging

```python
# Python — VULNERABLE: No logging of security events
def login(request):
    user = authenticate(request.POST['username'], request.POST['password'])
    if user:
        login_user(request, user)
        return redirect('/dashboard')
    else:
        # VULNERABLE: Failed login not logged — can't detect brute force
        return render(request, 'login.html', {'error': 'Invalid credentials'})

def change_role(request, user_id, new_role):
    # VULNERABLE: Privilege change not logged — no audit trail
    user = User.objects.get(id=user_id)
    user.role = new_role
    user.save()
    return redirect('/admin/users')

def delete_records(request, record_ids):
    # VULNERABLE: Bulk data deletion not logged
    Record.objects.filter(id__in=record_ids).delete()
    return JsonResponse({'status': 'deleted'})

def export_data(request):
    # VULNERABLE: Data export not logged — can't detect exfiltration
    data = User.objects.all().values('name', 'email', 'ssn', 'phone')
    return JsonResponse(list(data), safe=False)
```

```javascript
// Node.js — VULNERABLE: Insufficient security logging
app.post('/api/auth/reset-password', async (req, res) => {
    // VULNERABLE: Password reset not logged
    const user = await User.findOne({ email: req.body.email });
    await sendResetEmail(user);
    res.json({ success: true });
});

app.put('/api/admin/settings', adminAuth, async (req, res) => {
    // VULNERABLE: Security setting changes not logged
    await Settings.update(req.body);
    res.json({ success: true });
});
```

### Log Level Misconfiguration

```python
# Python/Django — VULNERABLE: DEBUG in production
# settings.py
DEBUG = True                    # VULNERABLE in production
LOGGING = {
    'handlers': {
        'console': {
            'level': 'DEBUG',   # VULNERABLE: Verbose logging in production
        },
    },
}
```

```javascript
// Node.js — VULNERABLE: Debug logging in production
const logger = winston.createLogger({
    level: 'debug',  // VULNERABLE: Should be 'info' or 'warn' in production
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: '/var/log/app/debug.log' }),
    ],
});

// VULNERABLE: Morgan logging request bodies
app.use(morgan(':method :url :status :req[body]')); // Logs request bodies
```

```yaml
# application.yml — VULNERABLE: Debug logging in production
logging:
  level:
    root: DEBUG                    # VULNERABLE
    org.springframework: DEBUG     # VULNERABLE: Framework internals exposed
    org.hibernate.SQL: DEBUG       # VULNERABLE: SQL queries logged
    org.hibernate.type: TRACE      # VULNERABLE: SQL parameter values logged
```

### Error Message Information Disclosure

```python
# Python/Flask — VULNERABLE: Stack traces in production
@app.errorhandler(Exception)
def handle_error(e):
    # VULNERABLE: Full stack trace returned to client
    return jsonify({
        'error': str(e),
        'traceback': traceback.format_exc(),  # VULNERABLE
        'debug_info': {
            'database': app.config['SQLALCHEMY_DATABASE_URI'],  # VULNERABLE
            'server': socket.gethostname(),                      # VULNERABLE
        }
    }), 500
```

```javascript
// Node.js — VULNERABLE: Detailed errors in production
app.use((err, req, res, next) => {
    // VULNERABLE: Sends full error with stack trace
    res.status(500).json({
        message: err.message,
        stack: err.stack,           // VULNERABLE: Internal paths exposed
        query: err.sql,             // VULNERABLE: SQL query exposed
        config: err.config,         // VULNERABLE: Config details exposed
    });
});
```

```java
// Java — VULNERABLE: Exception details in response
@ExceptionHandler(Exception.class)
public ResponseEntity<Map<String, Object>> handleException(Exception ex) {
    Map<String, Object> error = new HashMap<>();
    error.put("message", ex.getMessage());
    error.put("stackTrace", Arrays.toString(ex.getStackTrace())); // VULNERABLE
    error.put("cause", ex.getCause() != null ? ex.getCause().getMessage() : null);
    return ResponseEntity.status(500).body(error);
}
```

### Log File Access Control

```bash
# VULNERABLE: World-readable log files
-rw-r--r-- 1 www-data www-data  /var/log/app/application.log  # Others can read
-rw-rw-rw- 1 root     root      /var/log/app/audit.log        # World-writable!

# VULNERABLE: Logs in webroot
/var/www/html/logs/application.log    # Accessible via HTTP
/var/www/html/debug.log               # Accessible via HTTP
```

```yaml
# VULNERABLE: Log viewing endpoint without auth
# nginx config
location /logs/ {
    alias /var/log/app/;
    # VULNERABLE: No authentication required to read logs
    autoindex on;
}
```

## Detection Methodology

1. **Log Statement Scan**: Find all logging calls and check for user-controlled input without sanitization
2. **Sensitive Data Patterns**: Search log statements for variables named password, token, secret, key, ssn, credit_card, cvv
3. **Security Event Coverage**: Map critical operations (auth, authz changes, data access, admin actions) to logging statements
4. **Log Level Audit**: Check production configuration for DEBUG/TRACE levels
5. **Error Handler Review**: Examine global error handlers for information disclosure
6. **Log File Permissions**: Check file system permissions on log files and directories
7. **Log Endpoint Security**: Find any log viewing/streaming endpoints and verify authentication
8. **Request Logging**: Check HTTP request logging middleware for header/body logging that captures secrets
9. **Structured Logging**: Verify structured logging frameworks are configured to exclude sensitive fields
10. **Audit Trail Completeness**: Verify all CRUD operations on sensitive data have audit logging

## Common Sinks and Sources

### Logging Frameworks
- **Python**: `logging`, `loguru`, `structlog`
- **JavaScript**: `console.log`, `winston`, `pino`, `bunyan`, `morgan`, `debug`
- **Java**: `slf4j`, `log4j`, `logback`, `java.util.logging`
- **C#**: `ILogger`, `Serilog`, `NLog`, `log4net`
- **Go**: `log`, `logrus`, `zap`, `zerolog`
- **Ruby**: `Logger`, `Rails.logger`, `Lograge`

### User Input Sources in Logs
- Request parameters: `username`, `email`, `user-agent`, `referer`
- Headers: `Authorization`, `Cookie`, `X-Forwarded-For`
- Request bodies: form data, JSON payloads
- URL paths: dynamic segments, query parameters
- Error messages: exception details with user context

### Security Events to Log
- Authentication: login success/failure, logout, password changes, MFA events
- Authorization: access denied, privilege escalation, role changes
- Data: creation, modification, deletion, bulk export of sensitive data
- Admin: configuration changes, user management, system settings
- Security: rate limit triggers, input validation failures, CSRF failures

## False Positive Indicators

- **Debug logging disabled in production**: If log level is `INFO` or above in production, DEBUG-level sensitive logging may not execute
- **Structured logging with redaction**: Frameworks like Serilog with destructuring policies that exclude sensitive fields
- **Log masking middleware**: Middleware that masks passwords, tokens, and PII before writing to logs
- **Test logging**: Verbose logging in test code that doesn't run in production
- **Audit logging services**: Dedicated audit log services with proper access control, separate from application logs
- **Sanitized user input**: User input that is explicitly sanitized before logging (newlines stripped, length limited)

## Severity Assessment

| Finding | Severity |
|---------|----------|
| Credentials/tokens logged in production | **Critical** |
| Credit card numbers/CVV in logs | **Critical** |
| Log files accessible via web without auth | **High** |
| Log injection allowing log forging | **High** |
| Stack traces with sensitive info in responses | **High** |
| PII (SSN, email, phone) in logs | **High** |
| Missing logging for authentication events | **High** |
| World-writable log files | **High** |
| DEBUG level in production | **Medium** |
| Missing logging for authorization changes | **Medium** |
| Missing logging for data export operations | **Medium** |
| SQL queries with parameters logged | **Medium** |
| Insufficient log retention | **Low** |
| Missing structured logging | **Low** |
| Log format inconsistencies | **Low** |

## Remediation Patterns

### Log Injection Prevention

```python
# SECURE: Sanitize user input before logging
import re

def sanitize_for_log(value):
    """Remove newlines and control characters from log input."""
    if isinstance(value, str):
        return re.sub(r'[\r\n\t]', '', value)[:200]  # Also limit length
    return str(value)

def login(request):
    username = sanitize_for_log(request.POST.get('username', ''))
    logger.info("Login attempt for user %s", username)
```

```javascript
// SECURE: Structured logging prevents injection
const logger = pino();

app.post('/login', (req, res) => {
    // Structured logging — username is a field value, not interpolated into message
    logger.info({ username: req.body.username, ip: req.ip }, 'Login attempt');
});
```

```java
// SECURE: SLF4J parameterized logging
logger.info("Login attempt for user: {}", username.replaceAll("[\\r\\n]", ""));
```

### Sensitive Data Redaction

```python
# SECURE: Redact sensitive fields before logging
import copy

SENSITIVE_FIELDS = {'password', 'token', 'secret', 'ssn', 'credit_card', 'cvv',
                    'authorization', 'cookie', 'api_key'}

def redact_sensitive(data, fields=SENSITIVE_FIELDS):
    if isinstance(data, dict):
        redacted = {}
        for key, value in data.items():
            if key.lower() in fields:
                redacted[key] = '***REDACTED***'
            else:
                redacted[key] = redact_sensitive(value, fields)
        return redacted
    return data

logger.info("Request data: %s", redact_sensitive(request_data))
```

```javascript
// SECURE: Pino redaction
const logger = pino({
    redact: {
        paths: ['password', 'req.headers.authorization', 'req.headers.cookie',
                '*.token', '*.secret', '*.ssn', '*.creditCard'],
        censor: '***REDACTED***'
    }
});
```

```csharp
// SECURE: Serilog destructuring with exclusions
Log.Logger = new LoggerConfiguration()
    .Destructure.ByTransforming<LoginRequest>(r =>
        new { r.Username, Password = "***REDACTED***" })
    .CreateLogger();
```

### Security Event Logging

```python
# SECURE: Comprehensive security event logging
import structlog

security_logger = structlog.get_logger("security")

def login(request):
    user = authenticate(request.POST['username'], request.POST['password'])
    if user:
        security_logger.info("authentication.success",
            username=request.POST['username'],
            ip=request.META['REMOTE_ADDR'],
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:200])
        login_user(request, user)
    else:
        security_logger.warning("authentication.failure",
            username=sanitize_for_log(request.POST['username']),
            ip=request.META['REMOTE_ADDR'],
            reason="invalid_credentials")

def change_role(request, user_id, new_role):
    target_user = User.objects.get(id=user_id)
    old_role = target_user.role
    target_user.role = new_role
    target_user.save()
    security_logger.info("authorization.role_change",
        actor=request.user.id,
        target_user=user_id,
        old_role=old_role,
        new_role=new_role,
        ip=request.META['REMOTE_ADDR'])
```

### Secure Error Handling

```python
# SECURE: Generic error messages in production
@app.errorhandler(Exception)
def handle_error(e):
    error_id = uuid.uuid4().hex
    # Log full error internally
    logger.error("Unhandled exception [%s]: %s", error_id, e, exc_info=True)
    # Return generic message to client
    return jsonify({
        'error': 'An internal error occurred',
        'reference': error_id  # For support tickets
    }), 500
```

```javascript
// SECURE: Error handler with correlation ID
app.use((err, req, res, next) => {
    const errorId = crypto.randomUUID();
    logger.error({ errorId, err, path: req.path }, 'Unhandled error');
    res.status(500).json({
        error: 'Internal server error',
        referenceId: errorId
    });
});
```

## CWE References

- **CWE-117**: Improper Output Neutralization for Logs (Log Injection)
- **CWE-532**: Insertion of Sensitive Information into Log File
- **CWE-778**: Insufficient Logging
- **CWE-223**: Omission of Security-relevant Information
- **CWE-209**: Generation of Error Message Containing Sensitive Information
- **CWE-215**: Insertion of Sensitive Information Into Debugging Code
- **CWE-538**: Insertion of Sensitive Information into Externally-Accessible File or Directory
- **CWE-497**: Exposure of Sensitive System Information to an Unauthorized Control Sphere
- **CWE-779**: Logging of Excessive Data
- **CWE-276**: Incorrect Default Permissions (Log files)
