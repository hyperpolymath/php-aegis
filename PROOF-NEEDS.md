# PROOF-NEEDS.md — php-aegis

## Current State

- **src/abi/*.idr**: NO
- **Dangerous patterns**: 0
- **LOC**: ~10,200 (PHP)
- **ABI layer**: Missing

## What Needs Proving

| Component | What | Why |
|-----------|------|-----|
| Security header generation | Generated headers are well-formed and complete | Malformed security headers leave sites unprotected |
| CSP policy construction | Content Security Policy prevents all XSS vectors | Incomplete CSP allows cross-site scripting |
| Webmention validation | IndieWeb Webmention verification is correct | Spoofed webmentions inject malicious content |
| Input validation | All validators reject malicious input | Validator bypass is a security vulnerability |

## Recommended Prover

**Idris2** — Create `src/abi/` with security header correctness types. CSP policy completeness is a natural fit for exhaustive pattern matching. PHP code would need a separate verification approach (potentially PHPStan + custom rules).

## Priority

**MEDIUM** — Security library deployed on production websites (lcb-website uses it). Incorrect security headers directly expose users to attacks. CSP completeness is the highest-value proof target.
