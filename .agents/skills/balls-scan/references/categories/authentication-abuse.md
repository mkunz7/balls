# Authentication abuse and account discovery

Use this guide for login, signup, password reset, MFA, invitation, and account recovery flows. Read it alongside `authn.md`; this guide emphasizes endpoint coverage and observable differences rather than cryptographic implementation.

## Static review method

1. Inventory each authentication-related route, HTTP method, and state transition. Trace route decorators, middleware, shared helpers, and configured defaults.
2. Compare the code paths for unknown account, wrong password, disabled/limited account, malformed credential, successful authentication, and throttled/locked state.
3. Check whether responses disclose account existence through message text, status, redirects, response shape, or materially different work. Report only a code-supported difference; theoretical timing differences alone are insufficient.
4. Look for repository-defined limits on attempts by account and source, backoff, lockout, MFA challenge attempts, signup creation, and recovery requests. A limiter in a checked-in proxy or middleware counts only if the assessed route actually passes through it.
5. Check whether the limiter can be bypassed through client-controlled forwarding headers, alternate route aliases, or a second authentication path. Do not infer trusted-proxy behavior unless the repository configures it.
6. Trace credential inputs through normalization, encoding, length limits, hashing, comparison, and error handling. For Unicode or malformed inputs, identify a concrete failure or bypass; do not report a style concern alone.

## Evidence and impact gates

- Missing rate limiting is a candidate only when a reachable sensitive operation accepts repeated attacker-controlled attempts and the repository defines no effective bound. Do not claim a successful brute-force or account takeover without evidence for the credential/OTP keyspace, attempt rate, and validity window.
- Account enumeration requires a reachable response or state difference between valid and invalid identities. Generic responses that still disclose account existence through an observable branch must be traced carefully; a single noisy timing observation is not proof.
- Lockout can itself create denial of service if an unauthenticated party can trigger it against a victim. Establish the triggering policy and recovery behavior from source.
- Signup or recovery throttling should be reported separately from login throttling only when it has a distinct endpoint, resource, impact, or remediation.
- State source-defined behavior and unknown external runtime configuration separately. Do not assume a proxy supplies limits that are absent from the repository.

## Deduplication

Group repeated route-level symptoms under one finding only when the root cause and remediation are shared. Keep account enumeration, password-storage weaknesses, and attempt throttling distinct when each has an independent security effect.
