# php-aegis Wiki

**php-aegis** is a comprehensive PHP security and hardening toolkit providing input validation, sanitization, XSS prevention, WordPress integration, IndieWeb protocol security, and rate limiting.

## Quick Links

### For Users
- **[User Guide](User-Guide.md)** - Get started with php-aegis
- **[WordPress Integration](WordPress-Integration.md)** - Using php-aegis with WordPress
- **[IndieWeb Security](IndieWeb-Security.md)** - Securing Micropub, IndieAuth, and Webmention
- **[Rate Limiting](Rate-Limiting.md)** - Implementing rate limits
- **[Examples](Examples.md)** - Code examples and recipes

### For Developers
- **[Developer Guide](Developer-Guide.md)** - API reference and internals
- **[Architecture](Architecture.md)** - Design decisions and patterns
- **[Contributing](Contributing.md)** - How to contribute to php-aegis

## Features

### Core Security
- **17 validators**: Email, URL, IP, UUID, slug, JSON, filename, semver, ISO 8601, hex color, domain, etc.
- **10 sanitizers**: HTML, JavaScript, CSS, URL, JSON, stripTags, filename, etc.
- **Security headers**: CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **Crypto utilities**: Secure random generation, constant-time comparisons

### Unique Features
- **RDF/Turtle escaping**: W3C-compliant semantic web security (UNIQUE - no other PHP library provides this)
- **Zero runtime dependencies**: Only requires PHP 8.1+
- **Static methods API**: No instantiation required

### Framework Integrations
- **WordPress**: 23 adapter functions (`aegis_html()`, `aegis_attr()`, etc.), MU-plugin template, dashboard widgets
- **IndieWeb**: Micropub content validation, IndieAuth PKCE authentication, Webmention SSRF prevention

### Rate Limiting
- **Token bucket algorithm**: Smooth rate limiting with burst allowance
- **Multiple storage backends**: Memory (dev), File (production), extensible for Redis/database
- **Preset configurations**: perSecond(), perMinute(), perHour(), perDay()

## Installation

```bash
composer require hyperpolymath/php-aegis
```

## Quick Start

### Basic Validation
```php
use PhpAegis\Validator;

if (Validator::email($input)) {
    // Safe to use
}
```

### Basic Sanitization
```php
use PhpAegis\Sanitizer;

$safe = Sanitizer::html($userInput);
echo $safe; // XSS-safe
```

### Rate Limiting
```php
use PhpAegis\RateLimit\RateLimiter;
use PhpAegis\RateLimit\FileStore;

$limiter = RateLimiter::perMinute(60, new FileStore('/tmp/ratelimit'));

if (!$limiter->attempt($userId)) {
    throw new TooManyRequestsException();
}
```

### WordPress Usage
```php
// Load in functions.php or MU-plugin
require_once __DIR__ . '/vendor/hyperpolymath/php-aegis/docs/wordpress/aegis-functions.php';

// Use WordPress-style functions
echo '<div>' . aegis_html($content) . '</div>';
echo '<a href="' . aegis_attr($url) . '">Link</a>';

// RDF/Turtle (unique feature)
echo aegis_turtle_triple($subject, $predicate, $object, 'en') . "\n";
```

## Project Status

**Version**: 0.2.0
**Completion**: 83%
**License**: PMPL-1.0-or-later

**Completed**:
- ✅ Core validators and sanitizers
- ✅ Security headers
- ✅ RDF/Turtle escaping
- ✅ WordPress integration (23 functions, MU-plugin, tests)
- ✅ IndieWeb security (Micropub, IndieAuth, Webmention)
- ✅ Rate limiting (token bucket, file/memory stores)
- ✅ Comprehensive test suite (10 files, 400+ test methods)

**Pending**:
- ⏳ Complete API reference documentation
- ⏳ Real-world validation (WordPress plugins/themes)
- ⏳ Publish to Packagist
- ⏳ Framework adapters (Laravel, Symfony)

## Support

- **Issues**: [GitHub Issues](https://github.com/hyperpolymath/php-aegis/issues)
- **Source**: [GitHub Repository](https://github.com/hyperpolymath/php-aegis)

## License

php-aegis is licensed under the **PMPL-1.0-or-later** (Polymath Public License).

See [LICENSE](../../LICENSE) for details.
