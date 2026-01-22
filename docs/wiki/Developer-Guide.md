# Developer Guide

Complete API reference for php-aegis developers.

## Architecture

### Design Principles
- **Static methods**: No instantiation required
- **Zero dependencies**: Only PHP 8.1+ required
- **Strict types**: `declare(strict_types=1)` throughout
- **PSR-12 compliant**: Follows PHP coding standards
- **PMPL-1.0-or-later**: Polymath Public License

### Directory Structure
```
php-aegis/
├── src/
│   ├── Validator.php           # Input validation
│   ├── Sanitizer.php           # Output sanitization
│   ├── TurtleEscaper.php       # RDF/Turtle escaping
│   ├── Headers.php             # Security headers
│   ├── Crypto.php              # Cryptographic utilities
│   ├── WordPress/
│   │   └── Adapter.php         # WordPress functions
│   ├── IndieWeb/
│   │   ├── Micropub.php        # Micropub validation
│   │   ├── IndieAuth.php       # IndieAuth authentication
│   │   └── Webmention.php      # Webmention SSRF prevention
│   └── RateLimit/
│       ├── RateLimitStoreInterface.php
│       ├── TokenBucket.php
│       ├── MemoryStore.php
│       ├── FileStore.php
│       └── RateLimiter.php
└── tests/                      # Comprehensive test suite
```

## API Reference

### Validator Class

**Namespace**: `PhpAegis\Validator`

#### Email Validation
```php
public static function email(string $email): bool
```
Validates email addresses using `filter_var(FILTER_VALIDATE_EMAIL)`.

#### URL Validation
```php
public static function url(string $url): bool
public static function httpsUrl(string $url): bool
```
Validates URLs. `httpsUrl()` requires HTTPS scheme.

#### IP Validation
```php
public static function ip(string $ip): bool
public static function ipv4(string $ip): bool
public static function ipv6(string $ip): bool
```

#### UUID Validation
```php
public static function uuid(string $uuid): bool
```
Validates RFC 4122 UUIDs.

#### Complete Method List
- `email(string): bool`
- `url(string): bool`
- `httpsUrl(string): bool`
- `ip(string): bool`
- `ipv4(string): bool`
- `ipv6(string): bool`
- `uuid(string): bool`
- `slug(string): bool`
- `json(string): bool`
- `filename(string): bool`
- `semver(string): bool`
- `iso8601(string): bool`
- `hexColor(string): bool`
- `domain(string): bool`
- `printable(string): bool`
- `noNullBytes(string): bool`

### Sanitizer Class

**Namespace**: `PhpAegis\Sanitizer`

#### HTML Sanitization
```php
public static function html(string $input): string
```
Escapes HTML using `htmlspecialchars()` with `ENT_QUOTES | ENT_HTML5`.

#### JavaScript Sanitization
```php
public static function js(string $input): string
```
JSON-encodes strings for safe JavaScript embedding.

#### Complete Method List
- `html(string): string` - HTML content
- `attr(string): string` - HTML attributes
- `js(string): string` - JavaScript strings
- `css(string): string` - CSS values
- `url(string): string` - URL encoding
- `json(mixed): string` - JSON encoding
- `stripTags(string): string` - Remove HTML tags
- `filename(string): string` - Safe filenames
- `removeNullBytes(string): string` - Remove null bytes

### TurtleEscaper Class

**Namespace**: `PhpAegis\TurtleEscaper`

**UNIQUE FEATURE**: W3C-compliant RDF Turtle escaping.

```php
public static function literal(string $value, ?string $language = null, ?string $datatype = null): string
public static function iri(string $iri): string
public static function string(string $value): string
```

**Example**:
```php
TurtleEscaper::literal('Hello "World"', 'en');
// Output: "Hello \"World\""@en
```

### Headers Class

**Namespace**: `PhpAegis\Headers`

```php
public static function sendSecurityHeaders(): void
public static function csp(array $directives): void
public static function hsts(int $maxAge, bool $includeSubdomains = true, bool $preload = false): void
public static function xFrameOptions(string $value = 'DENY'): void
public static function xContentTypeOptions(): void
public static function referrerPolicy(string $policy = 'strict-origin-when-cross-origin'): void
public static function permissionsPolicy(array $directives = []): void
```

### RateLimiter Class

**Namespace**: `PhpAegis\RateLimit\RateLimiter`

#### Factory Methods
```php
public static function perSecond(int $maxRequests, RateLimitStoreInterface $store): self
public static function perMinute(int $maxRequests, RateLimitStoreInterface $store, int $burstAllowance = 0): self
public static function perHour(int $maxRequests, RateLimitStoreInterface $store, int $burstAllowance = 0): self
public static function perDay(int $maxRequests, RateLimitStoreInterface $store, int $burstAllowance = 0): self
```

#### Instance Methods
```php
public function attempt(string $key, int $tokens = 1): bool
public function remaining(string $key): float
public function resetAt(string $key): int
public function reset(string $key): void
```

### TokenBucket Class

**Namespace**: `PhpAegis\RateLimit\TokenBucket`

Low-level token bucket implementation:

```php
public function __construct(
    RateLimitStoreInterface $store,
    int $capacity,
    float $refillRate,
    int $refillPeriod = 1
)
public function attempt(string $key, int $tokens = 1): bool
public function remaining(string $key): float
public function resetAt(string $key): int
public function reset(string $key): void
```

### Storage Implementations

#### MemoryStore
**Namespace**: `PhpAegis\RateLimit\MemoryStore`

In-memory storage (development only):
```php
$store = new MemoryStore();
```

#### FileStore
**Namespace**: `PhpAegis\RateLimit\FileStore`

File-based storage (production):
```php
$store = new FileStore('/var/ratelimit', 'prefix_');
```

## WordPress Integration

**Namespace**: Functions in global namespace (WordPress style)

### Available Functions (23 total)

**Sanitization**:
- `aegis_html(string): string`
- `aegis_attr(string): string`
- `aegis_js(string): string`
- `aegis_url(string): string`
- `aegis_css(string): string`
- `aegis_json(mixed): string`
- `aegis_strip_tags(string): string`
- `aegis_filename(string): string`

**RDF/Turtle**:
- `aegis_turtle_string(string): string`
- `aegis_turtle_iri(string): string`
- `aegis_turtle_literal(string, ?string, ?string): string`
- `aegis_turtle_triple(string, string, string, ?string): string`

**Validation**:
- `aegis_validate_email(string): bool`
- `aegis_validate_url(string, bool): bool`
- `aegis_validate_ip(string): bool`
- `aegis_validate_uuid(string): bool`
- `aegis_validate_slug(string): bool`
- `aegis_validate_json(string): bool`
- `aegis_validate_semver(string): bool`
- `aegis_validate_domain(string): bool`

**Security Headers**:
- `aegis_send_security_headers(): void`
- `aegis_csp(array): void`
- `aegis_hsts(int, bool, bool): void`

## IndieWeb Integration

### Micropub
**Namespace**: `PhpAegis\IndieWeb\Micropub`

```php
public static function validateEntry(array $entry): array{valid: bool, errors: string[]}
public static function sanitizeEntry(array $entry): array
public static function validateTokenFormat(string $token): bool
public static function parseScopes(string $scopeString): array
public static function hasScope(array $scopes, string $requiredScope): bool
```

### IndieAuth
**Namespace**: `PhpAegis\IndieWeb\IndieAuth`

```php
public static function validateMe(string $url): bool
public static function validateRedirectUri(string $redirectUri, string $clientId): bool
public static function generateState(int $length = 32): string
public static function generateCodeVerifier(int $length = 64): string
public static function generateCodeChallenge(string $verifier): string
public static function verifyCodeChallenge(string $challenge, string $verifier, string $method): bool
```

### Webmention
**Namespace**: `PhpAegis\IndieWeb\Webmention`

```php
public static function isInternalIp(string $ip): bool
public static function validateSource(string $url, bool $allowHttp = false): bool
public static function validateTarget(string $url, string $yourDomain): bool
public static function validateWebmention(string $source, string $target, string $yourDomain, bool $allowHttp = false): array
public static function detectDnsRebinding(string $url, array $originalIps): bool
```

## Testing

### Running Tests
```bash
composer test
```

### Test Coverage
- **10 test files**: Core, WordPress, IndieWeb, RateLimit
- **400+ test methods**: Comprehensive coverage
- **PHPUnit 10**: Modern testing framework

### Writing Tests
```php
use PHPUnit\Framework\TestCase;
use PhpAegis\Validator;

class CustomTest extends TestCase
{
    public function testCustomValidation(): void
    {
        $this->assertTrue(Validator::email('test@example.com'));
    }
}
```

## Extending php-aegis

### Custom Storage Backend
Implement `RateLimitStoreInterface`:

```php
use PhpAegis\RateLimit\RateLimitStoreInterface;

class RedisStore implements RateLimitStoreInterface
{
    public function get(string $key): ?array { /* ... */ }
    public function set(string $key, array $data, int $ttl): void { /* ... */ }
    public function delete(string $key): void { /* ... */ }
    public function clear(): void { /* ... */ }
}
```

### Custom Validators
Add validation functions:

```php
function customValidator(string $input): bool
{
    // Validate against your rules
    return preg_match('/^[A-Z]{3}$/', $input) === 1;
}
```

## Performance Considerations

### Static Methods
Static methods have minimal overhead - no object instantiation.

### File-Based Rate Limiting
- **Write performance**: ~1000 writes/sec
- **Read performance**: ~5000 reads/sec
- **Storage**: ~100 bytes per key

### Memory Store
- **Fast**: All operations in memory
- **Limitation**: Data lost on process end
- **Use**: Development/testing only

## Security Considerations

### Input Validation
Always validate before processing:
```php
if (!Validator::email($input)) {
    throw new ValidationException();
}
```

### Output Sanitization
Context-aware escaping prevents XSS:
```php
echo Sanitizer::html($content);      // HTML context
echo Sanitizer::attr($value);        // Attribute context
echo Sanitizer::js($data);           // JavaScript context
```

### SSRF Prevention
Webmention validators prevent internal IP scanning:
```php
Webmention::validateSource($url);  // Checks for internal IPs
```

### Rate Limiting
Prevents abuse and DoS attacks:
```php
if (!$limiter->attempt($userId)) {
    throw new TooManyRequestsException();
}
```

## Contributing

See [Contributing Guide](Contributing.md) for development setup and guidelines.

## License

php-aegis is licensed under **PMPL-1.0-or-later** (Polymath Public License).
