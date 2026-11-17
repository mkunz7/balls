# Resource exhaustion and denial of service

Assess whether attacker-controlled work can consume a finite resource faster than the application or its deployment can bound it. Treat this as a distinct vulnerability class when it has an externally reachable trigger and a material availability impact.

## Review surfaces

- HTTP clients: missing connect/read timeouts, unbounded redirects, response buffering, streaming without byte caps, retry loops, and response decompression.
- File and media handling: unbounded upload/download size, image dimensions, archive entry count or expansion ratio, temporary-file leaks, and attacker-controlled retention.
- Parsers and algorithms: pathological regular expressions, deeply nested inputs, quadratic parsing, recursion, expensive serialization, and large collection expansion.
- Authentication and account flows: expensive password hashing on unlimited unauthenticated requests, repeated external service calls, account creation, and expensive verification operations.
- Shared infrastructure: worker/thread exhaustion, connection pools, file descriptors, disk quotas, database connections, queues, and memory pressure.
- Abuse controls: per-IP/account/user quotas, rate limits, concurrency limits, backpressure, circuit breakers, and bounded queues.

## Evidence requirements

For each candidate, establish the reachable source, the operation that consumes resources, and what prevents or fails to prevent a limit. Trace call paths and defaults; do not infer production worker counts, proxy limits, storage quotas, or rate limiting from absent deployment files.

Record the resource, attacker work required, concurrency or repetition needed, recovery behavior, and a realistic impact. A single request that returns an error is not automatically a denial-of-service vulnerability. Distinguish a request-level failure from exhaustion that degrades other users or persistent storage.

## Severity guidance

- **High:** unauthenticated low-cost requests can reliably exhaust shared workers, memory, disk, or a critical downstream service with limited recovery.
- **Medium:** repeated or sustained requests can materially degrade service, or the affected resource is bounded by deployment capacity but lacks application limits.
- **Low:** impact is local to one request or user, requires substantial resources, or is quickly recoverable with little cross-user effect.

Adjust severity to repository-defined controls and demonstrated preconditions. Do not assume absent proxy, worker, quota, or rate-limit controls exist. If external capacity determines the breadth of an outage, report the source-level unbounded operation and bound the cross-user impact as unknown; do not discard the code finding solely because deployment capacity is unknown.

## Common distinctions and deduplication

- Missing timeout and unbounded body size are separate controls, but may be one finding when they share a single outbound-fetch root cause. Explain both impacts and avoid duplicate counts.
- Rate limiting and per-item size limits mitigate different attack paths; connect findings where appropriate without collapsing unrelated sinks.
- Slow responses, large bodies, and many repeated requests can share a code path but have different resource and attacker-cost properties. Record each impact in the same finding or split only when ownership and remediation differ.
- Missing hardening headers or generic absence of a limit is not a finding without a reachable resource-consuming path and meaningful impact.

## Remediation patterns

- Set connect and read timeouts on outbound requests.
- Stream responses and enforce a cumulative byte cap before writing; clean up partial files.
- Validate media type and dimensions, cap decompression expansion, and set storage retention and quotas.
- Bound concurrency, queues, retries, and parser depth; use backpressure and circuit breakers where relevant.
- Rate-limit expensive unauthenticated endpoints and apply per-account or per-IP quotas with deployment context documented.
