<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Antigravity BALLS workflow and evidence rules. -->

## Overview

## ⚠️ Mandatory: Concrete Data Flow Proof Required

**DO NOT report a finding based on pattern-matching alone.** For every potential vulnerability you identify:

1. **Find the SINK** (dangerous function/API call)
2. **Trace all callers** — use `codegraph callers <symbol>` or `codegraph explore "<flow question>"` to identify call sites and execution paths.
3. **For each caller, trace the argument origin**:
   - Hardcoded/constant value → **Skip** (not a vulnerability, just bad practice)
   - Config file / admin-only source → **Skip** (not exploitable from internet)
   - User-controlled input (HTTP request, RPC, file upload, etc.) → **Investigate further**
   - Another service / database → **Trace upstream** to find the ultimate source
4. **Document the complete path**: SOURCE (file:line) → INTERMEDIATES (file:line each) → SINK (file:line)
5. **Verify no sanitization** between source and sink that would prevent exploitation

**"If an attacker controls X" is NOT a valid finding. You must prove X is user-controlled by tracing the actual code.**

Cross-Origin Resource Sharing (CORS) and Cross-Site Request Forgery (CSRF) vulnerabilities exploit the trust relationships between web origins. CORS misconfigurations allow unauthorized origins to read sensitive API responses, while CSRF flaws enable attackers to trick authenticated users into performing unintended actions. Combined with clickjacking and SameSite cookie issues, these vulnerabilities form a critical attack surface for web applications that rely on cookie-based or session-based authentication.

### Route-by-route CSRF coverage

Build a list of every route and method that changes server or browser authentication state, account state, or other protected data. Check each independently for token middleware, token validation, origin checks, accepted content types, and the effective cookie policy from source and framework defaults. Include signup and signin (which can create a browser session for a different account), logout (usually lower impact, but still a state change), and password/account mutations where present. Do not treat a token field in a template as proof the handler validates it, or treat one protected route as evidence that all routes are protected. State the affected user action and impact precisely; login/session confusion is not equivalent to account takeover.

## Vulnerability Patterns

### CORS — Wildcard with Credentials

```javascript
// Node.js/Express — VULNERABLE: Wildcard + credentials
const cors = require('cors');
app.use(cors({
    origin: '*',                    // VULNERABLE: Any origin
    credentials: true,              // With cookies — browsers block this,
                                    // but the misconfiguration signals intent issues
}));

// Even worse — reflecting the Origin header:
app.use((req, res, next) => {
    // VULNERABLE: Echoes any origin, effectively bypassing same-origin policy
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});
```

```python
# Python/Django — VULNERABLE: CORS misconfiguration
# settings.py
CORS_ALLOW_ALL_ORIGINS = True          # VULNERABLE: allows any origin
CORS_ALLOW_CREDENTIALS = True           # With credentials

# Or using django-cors-headers:
CORS_ORIGIN_WHITELIST = []
CORS_ORIGIN_ALLOW_ALL = True            # VULNERABLE
CORS_ALLOW_CREDENTIALS = True
```

```java
// Java/Spring — VULNERABLE: Wildcard CORS
@CrossOrigin(origins = "*", allowCredentials = "true")
@RestController
public class UserController {
    @GetMapping("/api/user/profile")
    public UserProfile getProfile() { /* ... */ }
}

// Or global config:
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("*")          // VULNERABLE
            .allowCredentials(true)
            .allowedMethods("*");
    }
}
```

```csharp
// C# ASP.NET — VULNERABLE: Overly permissive CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()        // VULNERABLE
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();      // With credentials
    });
});
```

### CORS — Origin Reflection / Regex Flaws

```javascript
// Node.js — VULNERABLE: Origin reflection
app.use((req, res, next) => {
    const origin = req.headers.origin;
    // VULNERABLE: Reflects any origin — attacker site gets full access
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});
```

```python
# Python — VULNERABLE: Regex matching flaw
ALLOWED_ORIGINS_REGEX = r'https://.*\.company\.com'

def check_origin(origin):
    # VULNERABLE: "https://evil.company.com" matches
    # VULNERABLE: "https://evilcompany.com" also matches (missing anchor)
    # VULNERABLE: "https://company.com.evil.com" matches
    if re.match(ALLOWED_ORIGINS_REGEX, origin):
        return True
    return False
```

```java
// Java — VULNERABLE: Subdomain matching without anchor
@Bean
public CorsFilter corsFilter() {
    CorsConfiguration config = new CorsConfiguration();
    // VULNERABLE: endsWith check allows "attacker-company.com"
    config.addAllowedOriginPattern("*.company.com");
    // Should be: https://*.company.com (with protocol and proper pattern)
    return new CorsFilter(source);
}
```

### CSRF — Missing Protection on State-Changing Operations

```python
# Python/Django — VULNERABLE: CSRF exemption
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # VULNERABLE: Disables CSRF protection
@login_required
def transfer_funds(request):
    if request.method == 'POST':
        to_account = request.POST['to_account']
        amount = request.POST['amount']
        perform_transfer(request.user, to_account, amount)
        return HttpResponse('Transfer complete')
```

```javascript
// Node.js/Express — VULNERABLE: No CSRF middleware
app.post('/api/user/change-email', authMiddleware, (req, res) => {
    // VULNERABLE: No CSRF token validation
    // Attacker's page can submit form to this endpoint
    const newEmail = req.body.email;
    updateUserEmail(req.user.id, newEmail);
    res.json({ success: true });
});

// VULNERABLE: GET request changes state
app.get('/api/user/delete-account', authMiddleware, (req, res) => {
    // VULNERABLE: GET requests should never change state
    // <img src="https://app.com/api/user/delete-account"> triggers this
    deleteAccount(req.user.id);
    res.json({ success: true });
});
```

```java
// Java/Spring — VULNERABLE: CSRF disabled globally
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()  // VULNERABLE: CSRF disabled for all endpoints
            .authorizeRequests()
            .anyRequest().authenticated();
    }
}
```

```csharp
// C# — VULNERABLE: Missing ValidateAntiForgeryToken
[HttpPost]
// Missing [ValidateAntiForgeryToken]
public IActionResult ChangePassword(ChangePasswordModel model)
{
    // VULNERABLE: No CSRF validation
    var user = GetCurrentUser();
    user.Password = HashPassword(model.NewPassword);
    _context.SaveChanges();
    return Ok();
}
```

### CSRF Token Validation Bypass

```python
# Python — VULNERABLE: Token not tied to session
def validate_csrf_token(request):
    token = request.POST.get('csrf_token')
    # VULNERABLE: Only checks if token exists, not if it matches session
    if token:
        return True
    # VULNERABLE: Accepts any valid token from any session
    if CsrfToken.objects.filter(token=token).exists():
        return True
    return False
```

```javascript
// Node.js — VULNERABLE: Predictable CSRF token
function generateCsrfToken(sessionId) {
    // VULNERABLE: Predictable — attacker who knows sessionId can compute token
    return crypto.createHash('md5').update(sessionId).digest('hex');
}

// VULNERABLE: Token in cookie without double-submit validation
app.use((req, res, next) => {
    // Sets CSRF token in cookie but never validates it in requests
    res.cookie('csrf_token', generateToken());
    next();
});
```

### SameSite Cookie Issues

```python
# Python/Flask — VULNERABLE: SameSite=None without Secure
response.set_cookie(
    'session_id',
    value=session_id,
    samesite='None',    # Sent on cross-site requests
    secure=False,       # VULNERABLE: Must be Secure with SameSite=None
    httponly=True
)

# VULNERABLE: No SameSite attribute (defaults vary by browser)
response.set_cookie('session_id', value=session_id, httponly=True)
```

```javascript
// Node.js/Express — VULNERABLE: Cookie configuration
app.use(session({
    secret: 'keyboard cat',
    cookie: {
        secure: false,          // VULNERABLE: Sent over HTTP
        httpOnly: false,        // VULNERABLE: Accessible via JavaScript
        sameSite: 'none',       // VULNERABLE: Sent cross-site without Secure
    }
}));
```

```java
// Java/Spring — VULNERABLE: Cookie config
@Bean
public CookieSerializer cookieSerializer() {
    DefaultCookieSerializer serializer = new DefaultCookieSerializer();
    serializer.setSameSite("None");   // Cross-site
    serializer.setUseSecureCookie(false);  // VULNERABLE: Must be secure
    return serializer;
}
```

### Clickjacking — Missing Frame Protection

```python
# Python/Django — VULNERABLE: No X-Frame-Options
# Missing django.middleware.clickjacking.XFrameOptionsMiddleware in MIDDLEWARE

# Or explicitly allowing framing:
X_FRAME_OPTIONS = 'ALLOWALL'  # VULNERABLE
```

```javascript
// Node.js — VULNERABLE: No frame protection headers
app.get('/account/settings', (req, res) => {
    // VULNERABLE: No X-Frame-Options or CSP frame-ancestors
    // Page can be framed by attacker and overlaid with transparent UI
    res.render('settings');
});
```

```html
<!-- Attacker's page — Clickjacking attack -->
<html>
<body>
<h1>Click to win a prize!</h1>
<iframe src="https://bank.com/transfer?to=attacker&amount=10000"
        style="opacity: 0; position: absolute; top: 0; left: 0;
               width: 100%; height: 100%; z-index: 999;">
</iframe>
<button style="position: absolute; top: 200px; left: 200px; z-index: 1;">
    Click Here!
</button>
</body>
</html>
```

### Pre-flight Request Handling Issues

```javascript
// Node.js — VULNERABLE: OPTIONS handler leaks info or bypasses auth
app.options('*', (req, res) => {
    // VULNERABLE: Responds to all pre-flight with permissive headers
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400'); // Cache for 24 hours
    res.sendStatus(204);
});
```

## Detection Methodology

1. **CORS Header Analysis**: Search for `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials` in response headers and middleware configuration
2. **Origin Validation**: Check how origin is validated — reflection, regex, allowlist, or wildcard
3. **CSRF Protection Audit**: Verify every state-changing endpoint (POST, PUT, DELETE, PATCH) has CSRF protection
4. **CSRF Token Validation**: Ensure tokens are tied to sessions, unpredictable, and validated server-side
5. **GET State Changes**: Find GET handlers that modify data (should be POST/PUT/DELETE)
6. **Cookie Configuration**: Check all `Set-Cookie` headers for Secure, HttpOnly, SameSite attributes
7. **Frame Protection**: Verify X-Frame-Options or CSP frame-ancestors on sensitive pages
8. **CSRF Exemptions**: Search for `@csrf_exempt`, `csrf().disable()`, `IgnoreAntiforgeryToken`, `[ValidateAntiForgeryToken]` missing
9. **Pre-flight Handling**: Check OPTIONS handlers for overly permissive responses
10. **Framework Configuration**: Audit CORS middleware settings in Express, Django, Spring, ASP.NET

## Common Sinks and Sources

### CORS Configuration Points
- **Express**: `cors()`, `res.setHeader('Access-Control-*')`, `app.options()`
- **Django**: `django-cors-headers`, `CORS_ALLOW_ALL_ORIGINS`, `CORS_ORIGIN_WHITELIST`
- **Spring**: `@CrossOrigin`, `CorsRegistry`, `CorsConfiguration`, `CorsFilter`
- **ASP.NET**: `AddCors()`, `UseCors()`, `[EnableCors]`, `CorsPolicyBuilder`
- **Rails**: `rack-cors`, `config.action_controller.allow_forgery_protection`
- **Flask**: `flask-cors`, `CORS()`, `@cross_origin()`
- **nginx**: `add_header Access-Control-Allow-Origin`
- **Apache**: `Header set Access-Control-Allow-Origin`

### CSRF Configuration Points
- **Django**: `CsrfViewMiddleware`, `@csrf_exempt`, `{% csrf_token %}`
- **Express**: `csurf`, `csrf()` middleware, `lusca`
- **Spring**: `csrf().disable()`, `CsrfFilter`, `@EnableWebSecurity`
- **ASP.NET**: `[ValidateAntiForgeryToken]`, `@Html.AntiForgeryToken()`
- **Rails**: `protect_from_forgery`, `skip_before_action :verify_authenticity_token`
- **Laravel**: `@csrf`, `VerifyCsrfToken` middleware, `$except`

### Cookie Configuration
- `Set-Cookie` headers, `res.cookie()`, `response.set_cookie()`
- Session middleware configuration
- Authentication cookie settings

## False Positive Indicators

- **Public APIs**: APIs that intentionally serve public data with `Access-Control-Allow-Origin: *` without credentials are not vulnerable
- **CORS on static assets**: CDN resources, fonts, and public static files commonly use wildcard CORS
- **Token-based auth (no cookies)**: APIs using Bearer tokens in headers are not vulnerable to CSRF (tokens aren't auto-sent)
- **SameSite=Lax default**: Modern browsers default to SameSite=Lax, providing some CSRF protection even without explicit setting
- **Internal/localhost origins**: CORS configured for localhost during development — verify production config differs
- **API Gateway CORS**: CORS handled at API gateway/reverse proxy level, not visible in application code
- **CSRF for login forms**: Login CSRF is lower risk in some contexts (no authenticated session to hijack)
- **GraphQL mutations over POST**: GraphQL typically requires `Content-Type: application/json` which triggers pre-flight, providing some CSRF protection

## Severity Assessment

| Finding | Severity |
|---------|----------|
| Origin reflection + credentials on sensitive API | **Critical** |
| CSRF on financial operations (transfers, purchases) | **Critical** |
| CSRF on password change without current password | **Critical** |
| Missing CSRF on account deletion | **High** |
| Wildcard CORS + credentials on authenticated endpoints | **High** |
| GET-based state changes on sensitive operations | **High** |
| SameSite=None without Secure flag | **High** |
| Missing clickjacking protection on sensitive pages | **High** |
| CSRF token not tied to session | **High** |
| Regex-based origin validation with bypass | **High** |
| Missing CSRF on non-sensitive state changes | **Medium** |
| Overly permissive CORS on non-sensitive endpoints | **Medium** |
| Missing X-Frame-Options on non-sensitive pages | **Medium** |
| Pre-flight caching too long (Max-Age) | **Low** |
| CORS on static/public assets | **Informational** |

## Remediation Patterns

### Secure CORS Configuration

```javascript
// SECURE: Express CORS with explicit allowlist
const cors = require('cors');

const allowedOrigins = [
    'https://app.company.com',
    'https://admin.company.com',
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
    maxAge: 600,  // 10 minutes
}));
```

```python
# SECURE: Django CORS configuration
CORS_ALLOWED_ORIGINS = [
    "https://app.company.com",
    "https://admin.company.com",
]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
```

```java
// SECURE: Spring CORS with explicit origins
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("https://app.company.com")
            .allowedMethods("GET", "POST", "PUT", "DELETE")
            .allowCredentials(true)
            .maxAge(600);
    }
}
```

### CSRF Protection

```python
# SECURE: Django — ensure middleware is active
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',  # Must be present
    # ...
]
# Template: {% csrf_token %} in every form
```

```javascript
// SECURE: Express CSRF with csurf
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: { httpOnly: true, secure: true, sameSite: 'strict' } });

app.use(csrfProtection);

app.get('/form', (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
});
```

```java
// SECURE: Spring — CSRF enabled (default)
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .authorizeRequests()
                .anyRequest().authenticated();
    }
}
```

### Secure Cookie Configuration

```javascript
// SECURE: Cookie settings
app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: {
        secure: true,           // HTTPS only
        httpOnly: true,         // No JavaScript access
        sameSite: 'strict',     // No cross-site sending
        maxAge: 3600000,        // 1 hour
        domain: '.company.com',
        path: '/',
    }
}));
```

### Clickjacking Protection

```python
# SECURE: Django — X-Frame-Options + CSP
X_FRAME_OPTIONS = 'DENY'

# Or in middleware/CSP header:
SECURE_CONTENT_TYPE_NOSNIFF = True
CSP_FRAME_ANCESTORS = ["'none'"]
```

```javascript
// SECURE: Express — Helmet for security headers
const helmet = require('helmet');

app.use(helmet({
    frameguard: { action: 'deny' },
    contentSecurityPolicy: {
        directives: {
            frameAncestors: ["'none'"],
        },
    },
}));
```

## CWE References

- **CWE-942**: Permissive Cross-domain Policy with Untrusted Domains
- **CWE-346**: Origin Validation Error
- **CWE-352**: Cross-Site Request Forgery (CSRF)
- **CWE-1275**: Sensitive Cookie with Improper SameSite Attribute
- **CWE-614**: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **CWE-1004**: Sensitive Cookie Without 'HttpOnly' Flag
- **CWE-1021**: Improper Restriction of Rendered UI Layers or Frames (Clickjacking)
- **CWE-16**: Configuration
- **CWE-693**: Protection Mechanism Failure
- **CWE-284**: Improper Access Control
