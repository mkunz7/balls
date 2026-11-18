<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Antigravity BALLS workflow and evidence rules. -->

## Overview

Security misconfiguration is consistently one of the most common vulnerability categories. It encompasses any security-relevant setting that is missing, improperly configured, or left at an insecure default. This includes debug modes enabled by repository defaults, default credentials, missing security headers, unnecessary features enabled, overly permissive cloud IAM policies, insecure container configurations, and exposed administrative interfaces. These issues are particularly dangerous because they often require no sophisticated exploitation — the vulnerability is the configuration itself.

## Required source-as-provided assessment

Review the application in the configuration state represented by the repository. Trace the actual entry point through app factories, config selection, launch scripts, containers, and checked-in deployment manifests. A committed `DEBUG = True`, disabled cookie flag, or absent header policy is assessed as configured when no repository-defined override changes it. Do not dismiss a finding because an operator might set an environment variable or a hosting platform might add protection. When runtime values are absent, report the source-defined/default behavior and state that the external runtime value is unknown. Do not claim the app is deployed to production unless the repository establishes that fact; report concrete behavior such as debugger-enabled exception handling, not a hypothetical deployment label.

## Vulnerability Patterns

### Debug Modes Enabled by Repository Configuration

```python
# Python/Django — VULNERABLE: repository default enables debug behavior
# settings.py
DEBUG = True                    # VULNERABLE: Exposes stack traces, SQL queries, settings
TEMPLATE_DEBUG = True           # VULNERABLE: Template error details

# VULNERABLE: Debug toolbar in production
INSTALLED_APPS = [
    'debug_toolbar',            # VULNERABLE: Should only be in dev
    'silk',                     # VULNERABLE: Profiler in production
]

# VULNERABLE: Secret key that is clearly a default/placeholder
SECRET_KEY = 'django-insecure-change-me-in-production'
```

```javascript
// Node.js — VULNERABLE: Development mode in production
// VULNERABLE: NODE_ENV not set to production
// process.env.NODE_ENV === undefined or 'development'

const app = express();
// VULNERABLE: Error handler exposes stack traces
app.use((err, req, res, next) => {
    res.status(500).json({
        error: err.message,
        stack: err.stack  // VULNERABLE: exposes stack details to the caller
    });
});

// VULNERABLE: Source maps in production build
// webpack.config.js
module.exports = {
    mode: 'development',      // VULNERABLE: Should be 'production'
    devtool: 'source-map',    // VULNERABLE: Exposes source code
};
```

```java
// Java/Spring — VULNERABLE: Dev profile in production
// application.yml
spring:
  profiles:
    active: dev               # VULNERABLE: Dev profile in production

# VULNERABLE: Actuator endpoints exposed
management:
  endpoints:
    web:
      exposure:
        include: '*'           # VULNERABLE: All actuator endpoints exposed
  endpoint:
    env:
      enabled: true            # VULNERABLE: Exposes environment variables
    heapdump:
      enabled: true            # VULNERABLE: Memory dump accessible
    shutdown:
      enabled: true            # VULNERABLE: Remote shutdown

# VULNERABLE: H2 console enabled
spring:
  h2:
    console:
      enabled: true            # VULNERABLE: Database console accessible
      settings:
        web-allow-others: true
```

```csharp
// C# ASP.NET — VULNERABLE: Development exception page in production
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // VULNERABLE: Should only be in Development
    app.UseDeveloperExceptionPage();  // Shows stack traces, source code

    // VULNERABLE: Swagger in production
    app.UseSwagger();
    app.UseSwaggerUI();
}
```

### Default Credentials

```yaml
# docker-compose.yml — VULNERABLE: Default/weak passwords
services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres    # VULNERABLE: Default password
      POSTGRES_DB: app

  redis:
    image: redis:7
    # VULNERABLE: No password set — open access

  mongodb:
    image: mongo:6
    # VULNERABLE: No authentication enabled by default

  rabbitmq:
    image: rabbitmq:3-management
    environment:
      RABBITMQ_DEFAULT_USER: guest    # VULNERABLE: Default credentials
      RABBITMQ_DEFAULT_PASS: guest

  elasticsearch:
    image: elasticsearch:8.0.0
    environment:
      xpack.security.enabled: "false"  # VULNERABLE: Security disabled
```

```python
# Python — VULNERABLE: Hardcoded default credentials
DATABASE_CONFIG = {
    'host': 'localhost',
    'user': 'root',          # VULNERABLE: Root user
    'password': '',           # VULNERABLE: Empty password
    'database': 'production'
}

ADMIN_USER = 'admin'
ADMIN_PASSWORD = 'admin123'   # VULNERABLE: Default admin password
```

```java
// Java — VULNERABLE: Default credentials in config
// application.properties
spring.datasource.username=sa            // VULNERABLE: SA user
spring.datasource.password=              // VULNERABLE: Empty password
spring.jpa.properties.hibernate.show_sql=true  // VULNERABLE: SQL logging
```

### Missing Security Headers

```python
# Python/Django — VULNERABLE: Missing security headers
# settings.py — these should all be True/set:
SECURE_HSTS_SECONDS = 0              # VULNERABLE: No HSTS
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_CONTENT_TYPE_NOSNIFF = False   # VULNERABLE: MIME sniffing allowed
SECURE_BROWSER_XSS_FILTER = False
X_FRAME_OPTIONS = None                # VULNERABLE: Clickjacking possible
SECURE_SSL_REDIRECT = False           # VULNERABLE: No HTTPS redirect
SESSION_COOKIE_SECURE = False         # VULNERABLE: Cookie over HTTP
CSRF_COOKIE_SECURE = False
```

```javascript
// Node.js — VULNERABLE: No security headers
const app = express();
// Missing: helmet() middleware
// Missing: Content-Security-Policy
// Missing: Strict-Transport-Security
// Missing: X-Content-Type-Options
// Missing: X-Frame-Options
// Missing: Referrer-Policy
// Missing: Permissions-Policy

// VULNERABLE: Powered-by header reveals framework
// Express sends "X-Powered-By: Express" by default
```

```xml
<!-- web.config — VULNERABLE: Missing headers -->
<system.webServer>
  <httpProtocol>
    <customHeaders>
      <!-- VULNERABLE: No security headers configured -->
      <!-- Should include: -->
      <!-- X-Content-Type-Options: nosniff -->
      <!-- X-Frame-Options: DENY -->
      <!-- Strict-Transport-Security -->
      <!-- Content-Security-Policy -->
    </customHeaders>
  </httpProtocol>
</system.webServer>
```

### Directory Listing and Exposed Files

```nginx
# nginx — VULNERABLE: Directory listing enabled
server {
    location /uploads/ {
        autoindex on;          # VULNERABLE: Lists all files
        alias /data/uploads/;
    }

    # VULNERABLE: Backup files accessible
    # No rule blocking .bak, .sql, .dump, .old files

    # VULNERABLE: .git directory exposed
    # No rule blocking /.git/
}
```

```apache
# Apache — VULNERABLE: Directory listing
<Directory /var/www/html>
    Options +Indexes          # VULNERABLE: Directory listing enabled
    AllowOverride None
</Directory>

# VULNERABLE: No .git protection
# <DirectoryMatch "^/.*/\.git/">
#     Deny from all
# </DirectoryMatch>
```

### Docker/Container Misconfiguration

```dockerfile
# Dockerfile — VULNERABLE: Multiple issues
FROM ubuntu:latest              # VULNERABLE: Unpinned base image

# VULNERABLE: Running as root (no USER directive)

# VULNERABLE: Installing unnecessary tools
RUN apt-get update && apt-get install -y \
    curl wget netcat telnet nmap vim

# VULNERABLE: Secrets in build
ENV API_KEY=STRIPE_SECRET_KEY_PLACEHOLDER
ARG DB_PASSWORD=supersecret

# VULNERABLE: Exposing all ports
EXPOSE 22 80 443 3306 5432 6379 9200

# VULNERABLE: Running as root (default)
CMD ["node", "server.js"]
```

```yaml
# docker-compose.yml — VULNERABLE
services:
  app:
    privileged: true             # VULNERABLE: Full host access
    cap_add:
      - ALL                      # VULNERABLE: All Linux capabilities
    network_mode: host           # VULNERABLE: Host network access
    pid: host                    # VULNERABLE: Host PID namespace
    volumes:
      - /:/host                  # VULNERABLE: Entire host filesystem mounted
      - /var/run/docker.sock:/var/run/docker.sock  # VULNERABLE: Docker socket
    security_opt:
      - seccomp:unconfined       # VULNERABLE: No seccomp filtering
```

### Kubernetes Misconfiguration

```yaml
# Kubernetes — VULNERABLE: Pod running as root
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
  - name: app
    image: myapp:latest          # VULNERABLE: Unpinned tag
    securityContext:
      runAsUser: 0               # VULNERABLE: Running as root
      privileged: true           # VULNERABLE: Privileged container
      allowPrivilegeEscalation: true  # VULNERABLE
    resources: {}                # VULNERABLE: No resource limits

---
# VULNERABLE: Overly permissive RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: default-admin
roleRef:
  kind: ClusterRole
  name: cluster-admin            # VULNERABLE: Admin access
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: default                  # VULNERABLE: Default service account
  namespace: default

---
# VULNERABLE: Dashboard exposed without auth
apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard
spec:
  type: NodePort                 # VULNERABLE: Dashboard accessible externally
```

### Cloud Misconfiguration (AWS)

```json
// AWS S3 — VULNERABLE: Public access
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::sensitive-data-bucket/*"
  }]
}
```

```json
// AWS IAM — VULNERABLE: Overly permissive policy
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
```

```hcl
# Terraform — VULNERABLE: Multiple cloud misconfigs
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"         # VULNERABLE: Public S3 bucket
}

resource "aws_db_instance" "main" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  publicly_accessible = true     # VULNERABLE: Database publicly accessible
  storage_encrypted   = false    # VULNERABLE: Unencrypted storage
  username       = "admin"
  password       = "password123" # VULNERABLE: Weak password in IaC
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # VULNERABLE: All ports open to internet
  }
}
```

### TLS Misconfiguration

```nginx
# nginx — VULNERABLE: Weak TLS config
server {
    listen 443 ssl;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;  # VULNERABLE: TLS 1.0/1.1 enabled
    ssl_ciphers ALL:!aNULL;                 # VULNERABLE: Weak ciphers allowed
    ssl_prefer_server_ciphers off;          # VULNERABLE: Client cipher preference
    # VULNERABLE: Missing HSTS header
    # VULNERABLE: Missing OCSP stapling
}
```

## Detection Methodology

1. **Configuration File Scan**: Parse all application config files for debug flags, dev modes, and insecure defaults
2. **Default Credential Check**: Search for common default usernames/passwords in configs and docker-compose files
3. **Security Header Audit**: Check web server and application configs for missing security headers
4. **Exposed Service Scan**: Identify admin panels, debug endpoints, monitoring tools, and documentation (Swagger, GraphQL playground)
5. **Docker/Container Audit**: Review Dockerfiles for root user, privileged mode, exposed ports, and secrets
6. **Kubernetes RBAC Review**: Check for overly permissive roles, default service accounts with elevated privileges
7. **Cloud IAM Audit**: Review IAM policies for wildcard permissions, public access grants
8. **TLS Configuration**: Check for weak protocols, ciphers, and missing HSTS
9. **Directory/File Exposure**: Check web server configs for directory listing, .git exposure, backup file access
10. **Environment Separation**: Verify that development configs, test credentials, and debug tools are absent from production

## Common Sinks and Sources

### Configuration Files
- `settings.py`, `config.py` (Django, Flask)
- `application.yml`, `application.properties` (Spring)
- `appsettings.json`, `web.config` (ASP.NET)
- `webpack.config.js`, `next.config.js`, `vite.config.js`
- `nginx.conf`, `apache2.conf`, `httpd.conf`
- `docker-compose.yml`, `Dockerfile`
- `*.tf`, `*.tfvars` (Terraform)
- `k8s/*.yml`, `helm/values.yml`
- `.env`, `.env.production`

### Debug/Admin Endpoints
- `/debug/`, `/admin/`, `/_debug_toolbar/`
- `/actuator/*` (Spring Boot)
- `/swagger*`, `/api-docs`, `/graphql` (playground)
- `/__debug__/`, `/silk/` (Django)
- `/phpinfo.php`, `/server-status`, `/server-info`
- `/elmah.axd`, `/trace.axd` (ASP.NET)
- `/h2-console` (H2 database)
- `/metrics`, `/health` (with sensitive data)

## Context That Does Not Cancel a Source Finding

- An environment variable or infrastructure override that is not assigned by repository content is unknown runtime context, not proof the secure value is used.
- A development-only label in a comment does not alter executable configuration or an entry point that loads it.
- State debug behavior and its demonstrated impact separately: debug may expose tracebacks; interactive code execution requires its own reachable, evidenced path.

## False Positive Indicators

- **Explicitly local-only configuration**: The repository enforces a local-only binding or launch path and the setting has no reachable effect outside that environment
- **Test configurations**: Default credentials in test fixtures or CI environments
- **Repository-defined safe override**: A checked-in launcher/configuration path demonstrably selects a secure setting for the assessed entry point
- **Infrastructure as Code templates**: Template files with placeholder values
- **Internal tools**: Admin panels on separate networks with VPN-only access
- **Intentionally public endpoints**: Health checks, status pages designed to be public
- **Documentation examples**: Sample configs in README or docs/ directories

## Severity Assessment

| Finding | Severity |
|---------|----------|
| Default credentials on production databases | **Critical** |
| Public S3 bucket with sensitive data | **Critical** |
| Privileged container with host filesystem access | **Critical** |
| Kubernetes cluster-admin on default service account | **Critical** |
| Debug-enabled exception handling reachable by an untrusted caller, with sensitive trace disclosure | **Assess demonstrated impact; commonly High** |
| Spring Actuator endpoints fully exposed | **High** |
| Database publicly accessible | **High** |
| Docker socket mounted in container | **High** |
| IAM policy with Action: * Resource: * | **High** |
| Missing HSTS header | **High** |
| TLS 1.0/1.1 enabled | **High** |
| Swagger/API docs in production | **Medium** |
| Missing X-Content-Type-Options | **Medium** |
| Directory listing enabled | **Medium** |
| Container running as root (no host access) | **Medium** |
| Source maps deployed to production | **Medium** |
| .git directory exposed | **High** |
| Server version headers exposed | **Low** |
| Missing Referrer-Policy header | **Low** |

## Remediation Patterns

### Secure Django Configuration
```python
# settings.py — Production
DEBUG = False
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']
ALLOWED_HOSTS = ['app.company.com']
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
X_FRAME_OPTIONS = 'DENY'
```

### Secure Express Configuration
```javascript
const helmet = require('helmet');

app.use(helmet());  // Sets all security headers
app.disable('x-powered-by');

if (process.env.NODE_ENV !== 'production') {
    app.use(require('morgan')('dev'));
}

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
});
```

### Secure Docker Configuration
```dockerfile
FROM node:18-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .

FROM node:18-slim
RUN groupadd -r appuser && useradd -r -g appuser appuser
WORKDIR /app
COPY --from=build /app .
USER appuser
EXPOSE 3000
HEALTHCHECK CMD curl -f http://localhost:3000/health || exit 1
CMD ["node", "server.js"]
```

### Secure Kubernetes Pod
```yaml
apiVersion: v1
kind: Pod
spec:
  automountServiceAccountToken: false
  containers:
  - name: app
    image: myapp:1.2.3@sha256:abc123...
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        cpu: "500m"
        memory: "256Mi"
      requests:
        cpu: "250m"
        memory: "128Mi"
```

### Security Headers (nginx)
```nginx
server {
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "default-src 'self'" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

    # Hide server version
    server_tokens off;

    # Block .git and sensitive files
    location ~ /\.git { deny all; }
    location ~ /\. { deny all; }
    location ~ \.(bak|sql|dump|old|swp)$ { deny all; }
}
```

## CWE References

- **CWE-16**: Configuration
- **CWE-2**: 7PK - Environment
- **CWE-215**: Insertion of Sensitive Information Into Debugging Code
- **CWE-489**: Active Debug Code
- **CWE-521**: Weak Password Requirements
- **CWE-798**: Use of Hard-coded Credentials
- **CWE-693**: Protection Mechanism Failure
- **CWE-1004**: Sensitive Cookie Without 'HttpOnly' Flag
- **CWE-614**: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **CWE-525**: Use of Web Browser Cache Containing Sensitive Information
- **CWE-756**: Missing Custom Error Page
- **CWE-942**: Permissive Cross-domain Policy with Untrusted Domains
- **CWE-250**: Execution with Unnecessary Privileges
