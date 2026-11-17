# Outbound HTTP trust boundaries

Use this guide for every server-side HTTP client call, including calls to internal services and user-selected URLs. Read it alongside `ssrf.md` and `resource-exhaustion.md`; it covers trust and authorization behavior that can be missed when reviewing only for SSRF.

## Static review method

1. Inventory each HTTP client call and trace the URL, headers, method, body, credentials, and redirect behavior back to their sources.
2. Inspect URL construction. Determine whether untrusted values enter the scheme, authority, path, query, or fragment. Check component-aware encoding and validation; string concatenation alone does not prove control of the host or an exploitable path.
3. Check the repository-defined destination and transport policy. If a checked-in URL uses plain HTTP, report that source-defined transport. Do not assume TLS termination, an environment override, or a trusted network unless repository evidence establishes it.
4. Inspect redirects, proxies, hostname/IP validation, and whether an attacker can reach loopback, private, link-local, or metadata destinations. Do not claim a reachable internal target merely because the client accepts a URL.
5. Treat every response as untrusted. Check status handling, JSON parsing, content type, response schema and types, and whether response fields control authorization, identity, roles, filesystem paths, or other durable state.
6. Check timeouts, response size, streaming, retries, and cleanup. Keep resource-exhaustion findings distinct when they have independent impact or remediation.

## Evidence and impact gates

- Separate arbitrary destination selection (SSRF), path/query manipulation of a fixed service, insecure transport, response trust, and resource exhaustion. They may chain, but require evidence for each link.
- For URL manipulation, prove what the chosen HTTP library does with the exact constructed URL. Do not infer authority override, request splitting, or privilege escalation from special characters in a path value alone.
- For response-driven authorization, show the untrusted response field and its path into an authorization decision, then establish who can influence that response. A separate SSRF sink does not automatically control another service's response.
- For cleartext transport, identify the actual URL/configuration selected by repository code and the sensitive data sent. State network-position requirements without assuming an external TLS wrapper.
- For SSRF, bound impact by the code's reachable destinations, response handling, and demonstrated data access. Internal-service reachability and cloud credentials are not automatic consequences.

## Deduplication

Link SSRF, response disclosure, authorization-state changes, and resource consumption into a chain when source evidence establishes the links. Do not merge independent root causes merely because they use the same HTTP client.
