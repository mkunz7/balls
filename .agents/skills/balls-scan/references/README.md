# BALLS audit reference catalog

The scan skill loads these references on demand. The category guides retain the detailed vulnerability patterns; workflow guides retain reconnaissance, hunting, verification, reporting, chain analysis, fast-scan, and resumability practices. All execution uses Antigravity subagents, CodeGraph, and the BALLS SQLite CLI.

## Vulnerability categories

- [api-security](categories/api-security.md)
- [authn](categories/authn.md)
- [authentication abuse](categories/authentication-abuse.md)
- [authz](categories/authz.md)
- [business-logic](categories/business-logic.md)
- [config](categories/config.md)
- [cors-csrf](categories/cors-csrf.md)
- [crypto](categories/crypto.md)
- [data-exposure](categories/data-exposure.md)
- [exceptional conditions](categories/exceptional-conditions.md)
- [deserialization](categories/deserialization.md)
- [file-upload](categories/file-upload.md)
- [injection](categories/injection.md)
- [logging](categories/logging.md)
- [memory](categories/memory.md)
- [path-traversal](categories/path-traversal.md)
- [race-condition](categories/race-condition.md)
- [outbound HTTP trust](categories/outbound-http-trust.md)
- [resource-exhaustion](categories/resource-exhaustion.md)
- [secrets](categories/secrets.md)
- [ssrf](categories/ssrf.md)
- [supply-chain](categories/supply-chain.md)
- [xss](categories/xss.md)
- [xxe](categories/xxe.md)

## Workflow guidance

- [exploit chain analysis](workflows/exploit-chain-analysis.md)
- [context saving](workflows/context-saving.md)
- [finding verification](workflows/finding-verification.md)
- [vulnerability hunting](workflows/vulnerability-hunting.md)
- [scan resumption](workflows/scan-resumption.md)
- [quick scan](workflows/quick-scan.md)
- [deterministic reporting](workflows/deterministic-reporting.md)
- [evidence-led report writing](workflows/report-writing.md)
- [component review](workflows/component-review.md)
- [coverage critic](workflows/coverage-critic.md)
- [full scan orchestration](workflows/full-scan-orchestration.md)
- [attribution](ATTRIBUTION.md)
