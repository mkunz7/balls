# BALLS Scanner Report Comparison — VulnApp

Comparison of findings across three independent security scan runs against the same target repository:
- **Codex Full Scan** (`CODEX-REPORT.md`): Full multi-agent scan orchestrated under OpenAI Codex CLI.
- **Codex Quick Scan** (`CODEX-QUICK-REPORT.md`): Quick triage scan orchestrated under OpenAI Codex CLI.
- **Google Antigravity** (`ANTIGRAVITY-REPORT.MD`): Comprehensive call-graph and multi-agent audit orchestrated under Google Antigravity.

---

## Legend

- 🟩 **Green**: Individually called out as a dedicated, verified finding with an assigned `BALLS-xxx` finding identifier.
- 🟨 **Yellow**: Mentioned or analyzed in the report (e.g., in Scope, Architecture, Coverage Matrix, Technical Evidence, or grouped within another finding), but **not** promoted as an individual standalone finding.
- 🟥 **Red**: Missing from the report (not covered, skipped during triage, or omitted).

---

## High-Level Metrics

| Metric | Codex Full | Codex Quick | Google Antigravity |
|---|:---:|:---:|:---:|
| **Total Dedicated Findings** | 13 | 9 | **22** |
| **High Severity Findings** | 3 | 3 | **8** |
| **Medium Severity Findings** | 4 | 4 | **10** |
| **Low Severity Findings** | 6 | 2 | **4** |
| **Exploit Chains Documented** | 3 | 1 | **4** |
| **Coverage Units Evaluated** | 27 (16 with findings/reviews) | 10 (Quick triage) | **27 (All 27 evaluated)** |

---

## Detailed Comparison Table

| Finding / Vulnerability | Codex | Codex Quick | Antigravity |
|---|:---:|:---:|:---:|
| **Path Traversal & Arbitrary File Read** (`catch_all send_file(path)`) | 🟩 `BALLS-001` | 🟩 `BALLS-001` | 🟩 `BALLS-003` |
| **Hardcoded Secret Key & Session Forgery** (`SECRET_KEY`) | 🟩 `BALLS-002` | 🟩 `BALLS-002` | 🟩 `BALLS-004` |
| **Server-Side Request Forgery (SSRF)** (`download_picture(url)`) | 🟩 `BALLS-003` | 🟩 `BALLS-003` | 🟩 `BALLS-006` |
| **Reflected XSS in Sign-In Flash** (`signin.jinja2`) | 🟩 `BALLS-004` | 🟩 `BALLS-004` | 🟩 `BALLS-008` |
| **Stored XSS in Directory Profiles** (`directory.jinja2`) | 🟩 `BALLS-005` | 🟩 `BALLS-005` | 🟩 `BALLS-005` |
| **Fail-Open Authorization Bypass** (`signup limited=None`) | 🟩 `BALLS-006` | 🟩 `BALLS-006` | 🟩 `BALLS-002` |
| **Unbounded Picture Download / Resource Exhaustion (DoS)** | 🟩 `BALLS-007` | 🟩 `BALLS-007` | 🟩 `BALLS-007` |
| **Account Enumeration via Error Messages & Timing** | 🟩 `BALLS-008` | 🟩 `BALLS-008` | 🟩 `BALLS-012` |
| **Missing Sign-In Rate Limiting / Brute-Force Throttling** | 🟩 `BALLS-012` | 🟩 `BALLS-009` | 🟩 `BALLS-011` |
| **Hardcoded Shared Password Hash Salt** (`BCRYPT_SALT`) | 🟩 `BALLS-009` | 🟨 Mentioned in scope/code | 🟩 `BALLS-016` |
| **Pre-Auth Full-Table Directory Load & Memory DoS** | 🟩 `BALLS-010` | 🟥 Missing (Skipped in quick) | 🟩 `BALLS-001` |
| **Login Cross-Site Request Forgery (Login CSRF)** | 🟩 `BALLS-011` | 🟨 Mentioned (Marked unreviewed) | 🟩 `BALLS-010` *(Part 1)* |
| **Logout CSRF / Forced Signout on GET** (`GET /signout`) | 🟩 `BALLS-013` | 🟨 Mentioned (Entry point listed) | 🟩 `BALLS-010` *(Part 2)* |
| **Open Self-Registration / Internal Directory Disclosure** | 🟨 Mentioned in narrative/chains | 🟨 Mentioned in data flow | 🟩 `BALLS-009` |
| **Plaintext Credentials & Request Params Logged in `after_request`** | 🟨 Mentioned (Discarded in matrix) | 🟨 Mentioned (Logging skipped) | 🟩 `BALLS-013` |
| **Password Policy Deficiencies & 72-Byte Bcrypt Truncation** | 🟨 Mentioned in code evidence | 🟨 Mentioned in code snippet | 🟩 `BALLS-014` |
| **Missing Session Cookie Security Flags & Invalidation** | 🟨 Mentioned in scope/analysis | 🟨 Mentioned in scope controls | 🟩 `BALLS-015` |
| **Outdated/EOL Dependencies & Missing Lockfile** | 🟨 Mentioned in scope review | 🟨 Mentioned in scope | 🟩 `BALLS-017` |
| **Internal API Query/Path Injection & Cleartext HTTP** | 🟨 Mentioned in matrix (discarded) | 🟨 Mentioned in architecture | 🟩 `BALLS-018` |
| **Insufficient Security Audit Logging for Auth Events** | 🟥 Missing | 🟥 Missing | 🟩 `BALLS-019` |
| **Missing HTTP Security Headers (Nosniff, Framing, HSTS)** | 🟨 Mentioned in scope controls | 🟨 Mentioned in scope controls | 🟩 `BALLS-020` |
| **Missing Subresource Integrity (SRI) on jQuery CDN** | 🟥 Missing | 🟥 Missing | 🟩 `BALLS-021` |
| **Active Debug Mode Flag Enabled by Default** | 🟨 Mentioned in matrix (discarded) | 🟨 Mentioned in scope review | 🟩 `BALLS-022` |

---

## Detailed Context & Explanations

### 1. Findings Identified Across All Three Engines (Core Vulns)
The following 9 core vulnerabilities were independently confirmed and assigned finding numbers in all three scans:
- **Path Traversal / File Read**: `send_file(path)` without traversal guards exposes `database.db` and source.
  - Codex: `BALLS-001` | Codex Quick: `BALLS-001` | Antigravity: `BALLS-003`
- **Hardcoded SECRET_KEY**: Enables unauthenticated signing of Flask cookie sessions.
  - Codex: `BALLS-002` | Codex Quick: `BALLS-002` | Antigravity: `BALLS-004`
- **SSRF**: Profile picture URL fetch via `requests.get` allows unauthenticated internal network requests.
  - Codex: `BALLS-003` | Codex Quick: `BALLS-003` | Antigravity: `BALLS-006`
- **Reflected XSS**: Unescaped flash message in `signin.jinja2` under Flask 0.12.2.
  - Codex: `BALLS-004` | Codex Quick: `BALLS-004` | Antigravity: `BALLS-008`
- **Stored XSS**: Unescaped user `name` and `bio` rendered in `directory.jinja2`.
  - Codex: `BALLS-005` | Codex Quick: `BALLS-005` | Antigravity: `BALLS-005`
- **Signup Privilege Bypass**: Non-atomic user creation commits `User.limited=None`, treating users as internal directory viewers.
  - Codex: `BALLS-006` | Codex Quick: `BALLS-006` | Antigravity: `BALLS-002`
- **Unbounded Picture Download (DoS)**: Lack of byte limits or timeout on remote image fetch.
  - Codex: `BALLS-007` | Codex Quick: `BALLS-007` | Antigravity: `BALLS-007`
- **Account Enumeration**: Distinct flash error messages and bcrypt timing differences between valid/invalid accounts.
  - Codex: `BALLS-008` | Codex Quick: `BALLS-008` | Antigravity: `BALLS-012`
- **Missing Sign-In Rate Limiting**: No throttling on `/signin` brute-force attempts.
  - Codex: `BALLS-012` | Codex Quick: `BALLS-009` | Antigravity: `BALLS-011`

### 2. Findings in Codex Full But Not in Codex Quick
- **Hardcoded Shared Salt (`BCRYPT_SALT`)**:
  - Codex: `BALLS-009` (Dedicated Finding).
  - Codex Quick: Mentioned in technical evidence/snippets of other findings, but not promoted as a standalone finding due to quick triage time constraints.
  - Antigravity: `BALLS-016` (Dedicated Finding).
- **Pre-Auth Full-Table Load (`User.query.all()`)**:
  - Codex: `BALLS-010` (Dedicated Finding).
  - Codex Quick: Skipped entirely in quick triage.
  - Antigravity: `BALLS-001` (Dedicated Finding — elevated to High severity due to memory exhaustion amplification).
- **Login & Logout CSRF**:
  - Codex: Split into two separate findings (`BALLS-011` for Login CSRF, `BALLS-013` for Forced Logout CSRF).
  - Codex Quick: CSRF category explicitly marked as `not-reviewed` in the quick triage scope.
  - Antigravity: `BALLS-010` (Consolidated dedicated finding covering both auth CSRF vectors).

### 3. Findings Exclusively Promoted by Antigravity
Antigravity promoted 9 additional security findings that Codex and Codex Quick either discarded during triage or omitted:
1. **Plaintext Credential Logging (`BALLS-013`)**: Codex noted debug logging in its coverage matrix but discarded it claiming runtime logger emission was unestablished; Antigravity verified that `@app.after_request` unconditionally logs `request.form` (including plaintext passwords) under default `DEBUG=True`.
2. **Password Policy & Bcrypt Truncation (`BALLS-014`)**: Codex quoted the vulnerable `bytes(plaintext, "ascii")` in evidence; Antigravity identified that non-ASCII input triggers an unhandled `UnicodeEncodeError` (DoS) and bcrypt silently truncates passwords at 72 bytes.
3. **Missing Cookie Attributes & Revocation (`BALLS-015`)**: Antigravity formally audited session cookie flags (`Secure`, `SameSite`) and verified that `/signout` merely drops client cookies without server-side revocation.
4. **EOL Dependencies & Known CVEs (`BALLS-017`)**: Antigravity identified reachable vulnerabilities in `requests` (CVE-2018-18074 redirect credential leak) and lack of lockfile pinning.
5. **Internal API Injection (`BALLS-018`)**: Codex marked `BaseConfig.LOOKUP` as unverified; Antigravity audited the employee lookup URL string concatenation and verified path/query parameter injection.
6. **Insufficient Audit Logging (`BALLS-019`)**: Antigravity validated absence of structured audit logs for failed logins, privilege assignments, and account creation.
7. **Missing Security Response Headers (`BALLS-020`)**: Antigravity verified absence of `X-Frame-Options`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store` on sensitive authenticated routes.
8. **Subresource Integrity (`BALLS-021`)**: Antigravity audited external asset loading in `base.jinja2` and identified unpinned, unsigned HTTP CDN inclusion of jQuery without SRI hashes.
9. **Active Default Debug Flag (`BALLS-022`)**: Codex discarded this candidate as not establishing an interactive debugger; Antigravity flagged `DEBUG=True` for enabling Werkzeug interactive tracebacks and verbose error leakage on unhandled exceptions.
