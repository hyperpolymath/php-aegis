# php-aegis Roadmap (Integration-Informed Priority)

This roadmap is prioritized based on real-world integration experience with WordPress semantic themes and the feedback received during the wp-sinople-theme security integration.

## Context: Why This Matters

During integration testing, the following gaps were identified:

1. **Feature set too minimal** - WordPress has `esc_html()`, `esc_attr()`, etc. already
2. **No RDF/Turtle support** - Semantic themes need specialized escaping
3. **Missing SPDX headers** - Compliance requirement not met
4. **Not leveraging PHP 8.1+** - Enums, union types, readonly properties unused

This roadmap addresses these gaps in priority order.

---

## Phase 1: Foundation Fixes (v0.1.1)

**Goal**: Address compliance and differentiation issues immediately.

### 1.1 SPDX License Headers ✅
- Add `SPDX-License-Identifier: MIT OR AGPL-3.0-or-later` to all PHP files
- Add `SPDX-FileCopyrightText` with year and author

### 1.2 Static Methods
- Convert `Validator` and `Sanitizer` to use static methods
- Rationale: No instance state needed, improves ergonomics
- Before: `(new Sanitizer())->html($input)`
- After: `Sanitizer::html($input)`

### 1.3 RDF/Turtle Escaping Module ✅
- `TurtleEscaper::string(string $input): string` - Escape for Turtle string literals
- `TurtleEscaper::iri(string $uri): string` - Escape/validate for Turtle IRIs
- This is a **unique differentiator** - no other PHP library does this properly

---

## Phase 2: Security Headers (v0.2.0)

**Goal**: Provide value beyond WordPress built-ins.

### 2.1 Headers Class
```php
Headers::contentSecurityPolicy(array $directives): void
Headers::strictTransportSecurity(int $maxAge, bool $subdomains = true): void
Headers::xFrameOptions(string $value = 'DENY'): void
Headers::xContentTypeOptions(): void  // nosniff
Headers::referrerPolicy(string $policy = 'strict-origin-when-cross-origin'): void
Headers::permissionsPolicy(array $permissions): void
```

### 2.2 All-in-One Security Headers
```php
Headers::secure(): void  // Apply sensible defaults for all headers
```

### Why This Matters
- WordPress doesn't provide header helpers
- Frameworks often require manual configuration
- This provides "secure by default" with one function call

---

## Phase 3: Extended Validators (v0.3.0)

**Goal**: Cover common validation needs with strict, type-safe implementations.

### 3.1 Network Validators
```php
Validator::ip(string $ip): bool  // IPv4 or IPv6
Validator::ipv4(string $ip): bool
Validator::ipv6(string $ip): bool
Validator::cidr(string $cidr): bool
Validator::hostname(string $host): bool
Validator::domain(string $domain): bool
```

### 3.2 Format Validators
```php
Validator::uuid(string $uuid): bool  // RFC 4122
Validator::slug(string $slug): bool  // URL-safe slugs
Validator::semver(string $version): bool  // Semantic versioning
Validator::iso8601(string $date): bool  // ISO 8601 datetime
Validator::json(string $json): bool  // Valid JSON
```

### 3.3 Security Validators
```php
Validator::noNullBytes(string $input): bool
Validator::printable(string $input): bool
Validator::safeFilename(string $filename): bool  // No path traversal
Validator::httpsUrl(string $url): bool  // Enforce HTTPS
```

---

## Phase 4: Context-Aware Sanitization (v0.4.0)

**Goal**: Provide correct escaping for every output context.

### 4.1 Context Enum (PHP 8.1+)
```php
enum OutputContext: string {
    case Html = 'html';
    case HtmlAttribute = 'attr';
    case JavaScript = 'js';
    case Css = 'css';
    case Url = 'url';
    case Sql = 'sql';  // For display only, not query building
    case Json = 'json';
    case Turtle = 'turtle';  // RDF Turtle
    case NTriples = 'ntriples';  // RDF N-Triples
}
```

### 4.2 Unified Escape Method
```php
Sanitizer::escape(string $input, OutputContext $context): string
```

### 4.3 Specialized Methods
```php
Sanitizer::jsString(string $input): string  // Safe for JS string literals
Sanitizer::cssString(string $input): string  // Safe for CSS values
Sanitizer::urlEncode(string $input): string  // Proper URL encoding
Sanitizer::jsonEncode(mixed $input): string  // Safe JSON with flags
```

---

## Phase 5: IndieWeb Security (v0.5.0)

**Goal**: First-class support for IndieWeb/semantic web patterns.

### 5.1 Micropub Content Sanitizer
```php
Micropub::sanitizeContent(string $html, array $allowedTags = []): string
Micropub::validateEntry(array $mf2): ValidationResult
```

### 5.2 IndieAuth Helpers
```php
IndieAuth::verifyToken(string $token, string $endpoint): TokenResult
IndieAuth::validateMe(string $url): bool  // Valid "me" URL
IndieAuth::validateRedirectUri(string $uri, string $clientId): bool
```

### 5.3 Webmention Validators
```php
Webmention::validateSource(string $url): bool  // Not internal IP
Webmention::validateTarget(string $url, string $domain): bool
```

---

## Phase 6: Rate Limiting (v0.6.0)

**Goal**: Protect against abuse without external dependencies.

### 6.1 Token Bucket Implementation
```php
interface RateLimitStore {
    public function get(string $key): ?TokenBucket;
    public function set(string $key, TokenBucket $bucket, int $ttl): void;
}

class MemoryStore implements RateLimitStore { ... }
class FileStore implements RateLimitStore { ... }
class RedisStore implements RateLimitStore { ... }  // Optional
class ApcuStore implements RateLimitStore { ... }   // Optional
```

### 6.2 Rate Limiter
```php
$limiter = new RateLimiter(
    store: new FileStore('/tmp/ratelimit'),
    capacity: 100,  // requests
    refillRate: 10, // per second
);

if (!$limiter->attempt($clientIp)) {
    http_response_code(429);
    exit;
}
```

---

## Differentiation Strategy

### What WordPress Has (don't duplicate)
- `esc_html()`, `esc_attr()`, `esc_url()`, `esc_js()`
- `wp_kses()`, `wp_kses_post()`
- `sanitize_*()` functions
- Nonce verification

### What php-aegis Provides (unique value)
| Feature | WordPress | Laravel | Symfony | php-aegis |
|---------|-----------|---------|---------|-----------|
| RDF/Turtle escaping | ❌ | ❌ | ❌ | ✅ |
| Security headers helper | ❌ | Partial | Partial | ✅ |
| IndieWeb validation | ❌ | ❌ | ❌ | ✅ |
| Zero dependencies | N/A | ❌ | ❌ | ✅ |
| PHP 8.1+ strict types | ❌ | ❌ | ❌ | ✅ |
| Rate limiting (no Redis) | ❌ | ❌ | ❌ | ✅ |

---

## Success Metrics

1. **Adoption**: Downloads on Packagist
2. **Integration**: Used in WordPress themes, Laravel packages
3. **Coverage**: CVE fixes attributable to php-aegis usage
4. **Community**: GitHub stars, issues, PRs

---

## Timeline Philosophy

Per project guidelines, no time estimates are provided. Work proceeds based on:
1. User demand (GitHub issues)
2. Security criticality
3. Contributor availability

Phases can be reordered based on community feedback.

---

*This roadmap reflects lessons learned from real WordPress integration.*
