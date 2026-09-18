# ADR-0004: Authentication and authorization model

Status: accepted · Date: 2026-09-19

## Context
Self-hosted, zero budget, no external identity provider guaranteed; CI needs non-interactive access; four roles required.

## Decision
Local users with argon2id password hashes (`pwdlib`); short-lived JWT access tokens (15 min, HS256 via `PyJWT`, key from env) in the `Authorization` header; opaque rotating refresh tokens (30 days) stored hashed, delivered in an `HttpOnly; Secure; SameSite=Strict` cookie scoped to the refresh path, with reuse detection revoking the chain; API keys (hashed, scoped, expiring) for CI; roles admin / security_engineer / developer / viewer enforced in the service layer. Skeleton lands in Phase 2; hardening in Phase 15.

## Alternatives considered
### GitHub OAuth — deferred (stretch)
Fewer passwords; requires an OAuth app and a public callback URL, which the laptop demo lacks.
### Server-side sessions — rejected
Would need Redis-backed session store for the worker-less API; JWT keeps the API stateless and the CI path simple.

## Consequences
- (−) local passwords to protect (rate limiting, lockout in Phase 15)
- (→) trigger: an org identity provider appears → add OIDC behind the same `auth` module
