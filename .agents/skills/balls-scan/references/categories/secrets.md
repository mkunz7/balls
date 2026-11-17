<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

## Overview

Hardcoded secrets in source code are one of the most common and dangerous security vulnerabilities. When secrets are committed to version control, they persist in Git history even after removal, can be discovered through repository leaks, and provide attackers with direct access to infrastructure, APIs, and data stores. This skill systematically scans for credentials, tokens, keys, and other sensitive values embedded in code, configuration, and infrastructure-as-code files.

## Vulnerability Patterns

### AWS Credentials

```python
# Python — Hardcoded AWS keys
import boto3

# VULNERABLE: Access key hardcoded
client = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7_PLACEHOLDER',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCY_PLACEHOLDER',
    region_name='us-east-1'
)
```

```javascript
// JavaScript — AWS credentials in config
const AWS = require('aws-sdk');

// VULNERABLE
AWS.config.update({
  accessKeyId: 'AKIAIOSFODNN7_PLACEHOLDER',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCY_PLACEHOLDER',
  region: 'us-west-2'
});
```

```java
// Java — AWS credentials hardcoded
BasicAWSCredentials credentials = new BasicAWSCredentials(
    "AKIAIOSFODNN7_PLACEHOLDER",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCY_PLACEHOLDER"
);
AmazonS3 s3 = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(credentials))
    .build();
```

### Database Connection Strings

```python
# Python — Database credentials
import psycopg2

# VULNERABLE: Password in connection string
conn = psycopg2.connect(
    "host=db.company.com dbname=production user=admin password=SuperSecret123!"
)

# VULNERABLE: SQLAlchemy URI
engine = create_engine('postgresql://admin:SuperSecret123!@db.company.com:5432/production')
```

```csharp
// C# — Connection strings
// VULNERABLE: In appsettings.json or code
string connectionString = "Server=prod-db.company.com;Database=MainDB;User Id=sa;Password=Pr0dP@ss_Placeholder!";

// VULNERABLE: In web.config
// <connectionStrings>
//   <add name="MainDB" connectionString="Server=...;Password=secret;" />
// </connectionStrings>
```

```go
// Go — Database credentials
import "database/sql"

// VULNERABLE
db, err := sql.Open("postgres",
    "host=production-db.internal port=5432 user=admin password=s3cr3t dbname=app sslmode=disable")
```

```yaml
# docker-compose.yml — Database passwords
services:
  db:
    image: postgres:14
    environment:
      POSTGRES_PASSWORD: SuperSecretPassword123!  # VULNERABLE
      POSTGRES_USER: admin
    ports:
      - "5432:5432"
```

### API Keys and Tokens

```javascript
// JavaScript — Various API keys
const config = {
  // VULNERABLE: Stripe secret key
  stripeKey: 'STRIPE_SECRET_KEY_PLACEHOLDER',

  // VULNERABLE: SendGrid API key
  sendgridKey: 'SG.xxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',

  // VULNERABLE: Twilio auth token
  twilioToken: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4',

  // VULNERABLE: Firebase API key
  firebaseKey: 'AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',

  // VULNERABLE: Mailgun API key
  mailgunKey: 'key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
};
```

```python
# Python — GitHub and Slack tokens
# VULNERABLE: GitHub personal access token
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"

# VULNERABLE: GitHub fine-grained PAT
GITHUB_PAT = "github_pat_11ABCDEFG0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# VULNERABLE: Slack tokens
SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-Placeholder_AbCdEfGhIjKl"
SLACK_USER_TOKEN = "xoxp-123456789012-123456789012-123456789012-placeholder1234567890ab"
```

### Private Keys and Certificates

```
# VULNERABLE: RSA private key in source
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/yGaXmKqHpEGJMF...
-----END RSA PRIVATE KEY-----

# VULNERABLE: EC private key
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIODrfaBYLWVx...
-----END EC PRIVATE KEY-----

# VULNERABLE: Generic private key
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBg...
-----END PRIVATE KEY-----
```

```yaml
# Kubernetes secret in plain text — VULNERABLE
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
data:
  # These are just base64 encoded, NOT encrypted
  username: YWRtaW4=          # admin
  password: cDRzc3cwcmQh     # p4ssw0rd!
```

### JWT Secrets and Encryption Keys

```python
# Python — JWT secret
import jwt

# VULNERABLE: Hardcoded JWT secret
SECRET_KEY = "my-super-secret-jwt-key-that-should-not-be-here"
token = jwt.encode({"user_id": 123}, SECRET_KEY, algorithm="HS256")
```

```javascript
// Node.js — Encryption keys
const crypto = require('crypto');

// VULNERABLE: Hardcoded encryption key
const ENCRYPTION_KEY = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6';
const IV = '1234567890abcdef';

const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
```

```java
// Java — Hardcoded signing key
// VULNERABLE
private static final String JWT_SECRET = "myJwtSecretKeyThatIsLongEnoughForHS256Algorithm";
private static final byte[] ENCRYPTION_KEY = "0123456789abcdef".getBytes();
```

### Configuration and Environment Files

```bash
# .env — Secrets in environment file (should not be committed)
DATABASE_URL=postgres://admin:realpassword@prod-db:5432/app
SECRET_KEY=django-insecure-k8s9d7f6g5h4j3k2l1
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7_PLACEHOLDER
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY_PLACEHOLDER
STRIPE_SECRET_KEY=STRIPE_SECRET_KEY_PLACEHOLDER
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxx
REDIS_PASSWORD=r3d1s_p@ss!
```

```yaml
# CI/CD config with hardcoded secrets — VULNERABLE
# .github/workflows/deploy.yml
env:
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7_PLACEHOLDER
  AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCY_PLACEHOLDER
  DEPLOY_TOKEN: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

```dockerfile
# Dockerfile — Secrets in build args or ENV
# VULNERABLE
ENV DATABASE_PASSWORD=SuperSecret123!
ENV API_KEY=STRIPE_SECRET_KEY_PLACEHOLDER

# VULNERABLE: Secret in build arg (persists in image layers)
ARG GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
RUN git clone https://${GITHUB_TOKEN}@github.com/company/private-repo.git
```

## Detection Methodology

1. **Regex Pattern Scanning**: Apply provider-specific regex patterns against all source files
2. **Entropy Analysis**: Flag strings with Shannon entropy > 4.5 bits/char that appear in assignment contexts
3. **File Discovery**: Locate sensitive file types (`.env`, `.pem`, `.key`, `credentials`, `secrets`)
4. **Git History Scanning**: Check for secrets in previous commits that may have been "removed"
5. **Configuration Audit**: Examine all config files, environment files, and IaC templates
6. **Variable Name Analysis**: Flag variables named `password`, `secret`, `key`, `token`, `credential` with literal string values
7. **Base64 Decode Check**: Decode base64 strings in configs to check for plaintext secrets
8. **Certificate/Key File Check**: Identify private key files committed to the repository
9. **Docker Layer Analysis**: Check Dockerfiles for secrets in ENV, ARG, COPY, and RUN instructions
10. **CI/CD Pipeline Review**: Audit workflow files for inline secrets vs. secret references

## Common Sinks and Sources

### High-Priority File Patterns
- `.env`, `.env.*` (`.env.production`, `.env.local`)
- `config.*`, `settings.*`, `credentials.*`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`
- `docker-compose*.yml`, `Dockerfile*`
- `.github/workflows/*.yml`, `.gitlab-ci.yml`
- `appsettings*.json`, `web.config`, `app.config`
- `application*.yml`, `application*.properties`
- `terraform.tfvars`, `*.auto.tfvars`
- `secrets.yml`, `vault.*`
- `id_rsa`, `id_ed25519`, `*.keystore`
- `serviceAccountKey.json`, `credentials.json`
- `kubeconfig`, `.kube/config`

### Regex Detection Patterns

| Secret Type | Regex Pattern |
|-------------|---------------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | `(?i)aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}` |
| GitHub PAT (classic) | `ghp_[a-zA-Z0-9]{36}` |
| GitHub PAT (fine-grained) | `github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}` |
| GitHub OAuth | `gho_[a-zA-Z0-9]{36}` |
| GitHub App Token | `ghu_[a-zA-Z0-9]{36}` or `ghs_[a-zA-Z0-9]{36}` |
| Slack Bot Token | `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}` |
| Slack User Token | `xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}` |
| Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+` |
| Google API Key | `AIza[0-9A-Za-z_-]{35}` |
| Stripe Live Key | `sk_live_[0-9a-zA-Z]{24,}` |
| Stripe Publishable | `pk_live_[0-9a-zA-Z]{24,}` |
| Twilio API Key | `SK[0-9a-fA-F]{32}` |
| SendGrid API Key | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` |
| Mailgun API Key | `key-[0-9a-zA-Z]{32}` |
| JWT Token | `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*` |
| RSA Private Key | `-----BEGIN (RSA )?PRIVATE KEY-----` |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| Generic Password | `(?i)(password\|passwd\|pwd)\s*[=:]\s*['"][^'"]{8,}['"]` |
| Generic Secret | `(?i)(secret\|token\|api_key\|apikey)\s*[=:]\s*['"][^'"]{8,}['"]` |
| Generic Connection String | `(?i)(mongodb\|postgres\|mysql\|redis\|amqp)://[^:]+:[^@]+@` |
| Azure Storage Key | `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};` |
| Heroku API Key | `[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}` |

## False Positive Indicators

- **Placeholder values**: `YOUR_API_KEY_HERE`, `REPLACE_ME`, `xxx`, `changeme`, `TODO`, `<token>`, `${VAR}`
- **Environment variable references**: `process.env.SECRET`, `os.environ['KEY']`, `ENV['TOKEN']`
- **Example/documentation strings**: Values in README, docs/, examples/ directories
- **Test fixtures**: Strings in test files clearly labeled as test data (e.g., `test_api_key`)
- **Configuration templates**: Files ending in `.example`, `.template`, `.sample`, `.dist`
- **AWS example keys**: `AKIAIOSFODNN7_PLACEHOLDER` is the official AWS example key (with `_PLACEHOLDER` appended to bypass secret scanning)
- **Known dummy values**: `sk_test_*` (Stripe test keys), `xoxb-not-a-real-token`
- **Base64 encoded non-secrets**: Short base64 strings that decode to non-sensitive data
- **Hash values**: SHA256/MD5 hashes used for checksums, not as secrets
- **Public keys**: `-----BEGIN PUBLIC KEY-----` (public keys are not secrets)
- **Encrypted values**: Values wrapped in vault references, KMS encryption, or SOPS

## Severity Assessment

| Finding | Severity |
|---------|----------|
| Production AWS/GCP/Azure credentials in code | **Critical** |
| Production database credentials in code | **Critical** |
| Private keys (RSA, EC, PGP) committed | **Critical** |
| Production API keys (Stripe live, SendGrid, etc.) | **Critical** |
| JWT signing secrets hardcoded | **High** |
| `.env` file with production secrets committed | **High** |
| Secrets in CI/CD config (not using secret refs) | **High** |
| Secrets in Docker images (ENV, ARG) | **High** |
| Encryption keys hardcoded | **High** |
| OAuth client secrets in source code | **High** |
| Internal service tokens | **Medium** |
| Test/staging credentials in non-test code | **Medium** |
| Base64-encoded secrets in Kubernetes manifests | **Medium** |
| API keys in client-side JavaScript (if restricted) | **Medium** |
| Default passwords in configuration templates | **Low** |
| Secrets in Git history (already rotated) | **Low** |

## Remediation Patterns

### Use Environment Variables
```python
# Python — Read from environment
import os

DATABASE_URL = os.environ['DATABASE_URL']
API_KEY = os.environ.get('API_KEY')
```

```javascript
// Node.js — Read from environment
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;
```

```go
// Go — Read from environment
apiKey := os.Getenv("API_KEY")
dbURL := os.Getenv("DATABASE_URL")
```

### Use Secret Management Services
```python
# Python — AWS Secrets Manager
import boto3
import json

client = boto3.client('secretsmanager')
response = client.get_secret_value(SecretId='prod/db/credentials')
secrets = json.loads(response['SecretString'])
db_password = secrets['password']
```

```csharp
// C# — Azure Key Vault
var client = new SecretClient(
    new Uri("https://my-vault.vault.azure.net/"),
    new DefaultAzureCredential()
);
KeyVaultSecret secret = await client.GetSecretAsync("DatabasePassword");
string password = secret.Value;
```

### CI/CD Secret References
```yaml
# GitHub Actions — Use secrets
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

### Docker — Multi-stage Builds for Secrets
```dockerfile
# SAFE: Use build secrets (Docker BuildKit)
# syntax=docker/dockerfile:1
FROM node:18 AS build
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm install

FROM node:18-slim
COPY --from=build /app/node_modules ./node_modules
# Secret never persists in final image
```

### .gitignore for Sensitive Files
```gitignore
# Environment files
.env
.env.*
!.env.example

# Key files
*.pem
*.key
*.p12
*.pfx
*.jks

# Credential files
credentials.json
serviceAccountKey.json
**/secrets.*
```

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

## CWE References

- **CWE-798**: Use of Hard-coded Credentials
- **CWE-259**: Use of Hard-coded Password
- **CWE-321**: Use of Hard-coded Cryptographic Key
- **CWE-312**: Cleartext Storage of Sensitive Information
- **CWE-319**: Cleartext Transmission of Sensitive Information
- **CWE-522**: Insufficiently Protected Credentials
- **CWE-256**: Plaintext Storage of a Password
- **CWE-260**: Password in Configuration File
- **CWE-538**: Insertion of Sensitive Information into Externally-Accessible File or Directory
- **CWE-540**: Inclusion of Sensitive Information in Source Code
- **CWE-615**: Inclusion of Sensitive Information in Source Code Comments
