# User Guide

Complete guide to using php-aegis for secure PHP applications.

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Validation](#validation)
- [Sanitization](#sanitization)
- [Security Headers](#security-headers)
- [RDF/Turtle Escaping](#rdfturtle-escaping)
- [Rate Limiting](#rate-limiting)
- [WordPress Integration](#wordpress-integration)
- [IndieWeb Security](#indieweb-security)
- [Best Practices](#best-practices)

## Installation

### Requirements
- PHP 8.1 or higher
- Composer

### Install via Composer
```bash
composer require hyperpolymath/php-aegis
```

### Autoloading
php-aegis uses PSR-4 autoloading. If you're using Composer, classes are automatically available:

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';

use PhpAegis\Validator;
use PhpAegis\Sanitizer;
```

## Basic Usage

php-aegis provides static methods for validation and sanitization. No instantiation required!

### Validate Input
```php
use PhpAegis\Validator;

// Validate email
if (!Validator::email($_POST['email'])) {
    die('Invalid email');
}

// Validate URL
if (!Validator::url($_POST['website'])) {
    die('Invalid URL');
}

// Validate HTTPS-only URL
if (!Validator::httpsUrl($_POST['secure_url'])) {
    die('HTTPS required');
}
```

### Sanitize Output
```php
use PhpAegis\Sanitizer;

// HTML context
echo '<div>' . Sanitizer::html($userContent) . '</div>';

// HTML attribute context
echo '<a href="' . Sanitizer::attr($url) . '">Link</a>';

// JavaScript context
echo '<script>var data = ' . Sanitizer::js($data) . ';</script>';

// JSON context
echo Sanitizer::json(['user' => $username, 'data' => $data]);
```

## Validation

php-aegis provides 17 validation methods:

### Email Validation
```php
Validator::email('user@example.com'); // true
Validator::email('invalid'); // false
```

### URL Validation
```php
Validator::url('https://example.com'); // true
Validator::url('not a url'); // false

// HTTPS-only
Validator::httpsUrl('http://example.com'); // false
Validator::httpsUrl('https://example.com'); // true
```

### IP Address Validation
```php
Validator::ip('192.168.1.1'); // true
Validator::ipv4('192.168.1.1'); // true
Validator::ipv6('2001:db8::1'); // true
```

### UUID Validation
```php
Validator::uuid('550e8400-e29b-41d4-a716-446655440000'); // true
Validator::uuid('not-a-uuid'); // false
```

### Slug Validation
```php
Validator::slug('my-post-title'); // true
Validator::slug('Has Spaces'); // false
```

### JSON Validation
```php
Validator::json('{"valid": true}'); // true
Validator::json('{invalid}'); // false
```

### Filename Validation
```php
Validator::filename('document.pdf'); // true
Validator::filename('../../../etc/passwd'); // false
```

### Semver Validation
```php
Validator::semver('1.2.3'); // true
Validator::semver('v1.2.3'); // false
```

### ISO 8601 Date Validation
```php
Validator::iso8601('2025-01-22T12:00:00Z'); // true
Validator::iso8601('2025-01-32'); // false
```

### Hex Color Validation
```php
Validator::hexColor('#FF5733'); // true
Validator::hexColor('blue'); // false
```

### Domain Validation
```php
Validator::domain('example.com'); // true
Validator::domain('192.168.1.1'); // false (IP, not domain)
```

### Printable String Validation
```php
Validator::printable('Hello World'); // true
Validator::printable("Has\x00null"); // false
```

### Null Byte Detection
```php
Validator::noNullBytes('safe string'); // true
Validator::noNullBytes("has\x00null"); // false
```

## Sanitization

php-aegis provides 10 sanitization methods for different contexts:

### HTML Context
Escape for HTML content (like WordPress `esc_html()`):

```php
$safe = Sanitizer::html('<script>alert("xss")</script>');
// Output: &lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;
```

### HTML Attribute Context
Escape for HTML attributes (like WordPress `esc_attr()`):

```php
echo '<input value="' . Sanitizer::attr($userInput) . '">';
echo '<a href="' . Sanitizer::attr($url) . '">Link</a>';
```

### JavaScript Context
Escape for JavaScript strings (like WordPress `esc_js()`):

```php
echo '<script>var name = ' . Sanitizer::js($username) . ';</script>';
```

### CSS Context
Remove dangerous characters from CSS values:

```php
$safe = Sanitizer::css($userColor);
```

### URL Context
URL-encode strings (like WordPress `esc_url()`):

```php
$encoded = Sanitizer::url($path);
```

### JSON Context
Safe JSON encoding (like WordPress `wp_json_encode()`):

```php
$json = Sanitizer::json(['key' => '<script>xss</script>']);
// Escapes HTML entities in JSON
```

### Strip All Tags
Remove all HTML tags (like WordPress `wp_strip_all_tags()`):

```php
$plain = Sanitizer::stripTags('<p>Hello <b>World</b></p>');
// Output: Hello World
```

### Filename Sanitization
Sanitize filenames to prevent path traversal:

```php
$safe = Sanitizer::filename('../../../etc/passwd');
// Output: etc_passwd
```

### Remove Null Bytes
Remove null bytes from strings:

```php
$clean = Sanitizer::removeNullBytes("string\x00with\x00nulls");
```

## Security Headers

Apply security headers to protect against common attacks:

### Apply All Headers
```php
use PhpAegis\Headers;

Headers::sendSecurityHeaders();
```

This applies:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy

### Custom CSP
```php
Headers::csp([
    'default-src' => ["'self'"],
    'script-src' => ["'self'", 'https://cdn.example.com'],
    'style-src' => ["'self'", "'unsafe-inline'"],
]);
```

### Custom HSTS
```php
// 1 year, include subdomains, preload
Headers::hsts(31536000, true, true);
```

### Individual Headers
```php
Headers::xFrameOptions('SAMEORIGIN');
Headers::xContentTypeOptions();
Headers::referrerPolicy('no-referrer');
Headers::permissionsPolicy([
    'geolocation' => [],
    'camera' => [],
]);
```

## RDF/Turtle Escaping

**UNIQUE FEATURE**: php-aegis is the only PHP library providing W3C-compliant RDF Turtle escaping.

### Why This Matters
RDF Turtle is used in semantic web applications. Incorrect escaping leads to RDF injection vulnerabilities. php-aegis fixed a real vulnerability in `wp-sinople-theme` that was using `addslashes()` (SQL escaping) instead of proper Turtle escaping.

### Basic Turtle Escaping
```php
use PhpAegis\TurtleEscaper;

// Escape string literal
$escaped = TurtleEscaper::literal('String with "quotes" and \n newlines');

// Escape IRI/URI
$escaped = TurtleEscaper::iri('https://example.org/resource#1');

// Escape string (just the value part)
$escaped = TurtleEscaper::string('Value with special chars');
```

### Complete RDF Triples
```php
$subject = 'https://example.org/person/1';
$predicate = 'http://xmlns.com/foaf/0.1/name';
$object = 'Alice Smith';

// Build complete triple with language tag
echo TurtleEscaper::literal($object, 'en'); // "Alice Smith"@en

// Build complete triple with datatype
echo TurtleEscaper::literal('42', null, 'http://www.w3.org/2001/XMLSchema#integer');
// "42"^^<http://www.w3.org/2001/XMLSchema#integer>
```

## Rate Limiting

Implement rate limiting to prevent abuse:

### Quick Start
```php
use PhpAegis\RateLimit\RateLimiter;
use PhpAegis\RateLimit\FileStore;

// 60 requests per minute
$limiter = RateLimiter::perMinute(60, new FileStore('/tmp/ratelimit'));

$userId = $_SERVER['REMOTE_ADDR']; // or user ID

if (!$limiter->attempt($userId)) {
    header('HTTP/1.1 429 Too Many Requests');
    header('Retry-After: ' . $limiter->resetAt($userId));
    die('Rate limit exceeded');
}

// Process request normally
```

### Different Rates
```php
// 10 requests per second
$limiter = RateLimiter::perSecond(10, $store);

// 1000 requests per hour
$limiter = RateLimiter::perHour(1000, $store);

// 10000 requests per day
$limiter = RateLimiter::perDay(10000, $store);
```

### Custom Burst Allowance
```php
// 1000 requests/hour, but allow 50 burst
$limiter = RateLimiter::perHour(1000, $store, 50);
```

### Check Remaining Requests
```php
$remaining = $limiter->remaining($userId);
echo "Requests left: $remaining";
```

### Storage Backends
```php
// Memory (development only)
use PhpAegis\RateLimit\MemoryStore;
$store = new MemoryStore();

// File (production single-server)
use PhpAegis\RateLimit\FileStore;
$store = new FileStore('/var/ratelimit');
```

See [Rate Limiting Guide](Rate-Limiting.md) for advanced usage.

## WordPress Integration

Use php-aegis in WordPress with familiar function names:

### Installation
Load in `functions.php` or create an MU-plugin:

```php
require_once __DIR__ . '/vendor/hyperpolymath/php-aegis/docs/wordpress/aegis-functions.php';
```

### WordPress-Style Functions
```php
// Sanitization
echo aegis_html($content);
echo '<a href="' . aegis_attr($url) . '">Link</a>';
echo '<script>var data = ' . aegis_js($data) . ';</script>';

// Validation
if (aegis_validate_email($email)) {
    // Safe
}

// RDF/Turtle (unique!)
echo aegis_turtle_triple($subject, $predicate, $object, 'en');

// Security headers
aegis_send_security_headers();
```

See [WordPress Integration Guide](WordPress-Integration.md) for complete details.

## IndieWeb Security

Secure IndieWeb protocols (Micropub, IndieAuth, Webmention):

### Micropub Content Validation
```php
use PhpAegis\IndieWeb\Micropub;

$entry = /* Micropub entry from POST */;

$result = Micropub::validateEntry($entry);
if (!$result['valid']) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_request', 'errors' => $result['errors']]);
    exit;
}

// Sanitize before storage
$sanitized = Micropub::sanitizeEntry($entry);
```

### IndieAuth PKCE Authentication
```php
use PhpAegis\IndieWeb\IndieAuth;

// Generate state for CSRF protection
$state = IndieAuth::generateState();
$_SESSION['indieauth_state'] = $state;

// Generate PKCE verifier/challenge
$verifier = IndieAuth::generateCodeVerifier();
$challenge = IndieAuth::generateCodeChallenge($verifier);
$_SESSION['code_verifier'] = $verifier;

// Build auth URL
$authUrl = $authorizationEndpoint . '?' . http_build_query([
    'response_type' => 'code',
    'client_id' => $clientId,
    'redirect_uri' => $redirectUri,
    'state' => $state,
    'code_challenge' => $challenge,
    'code_challenge_method' => 'S256',
]);
```

### Webmention SSRF Prevention
```php
use PhpAegis\IndieWeb\Webmention;

$source = $_POST['source'];
$target = $_POST['target'];
$yourDomain = 'example.com';

$result = Webmention::validateWebmention($source, $target, $yourDomain);
if (!$result['valid']) {
    http_response_code(400);
    echo json_encode(['error' => implode(', ', $result['errors'])]);
    exit;
}

// Safe to fetch source URL
```

See [IndieWeb Security Guide](IndieWeb-Security.md) for complete details.

## Best Practices

### Defense in Depth
Always validate input AND sanitize output:

```php
// Validate input
if (!Validator::email($_POST['email'])) {
    die('Invalid email');
}

// Sanitize output
echo '<p>Email: ' . Sanitizer::html($_POST['email']) . '</p>';
```

### Context-Aware Sanitization
Use the correct sanitizer for the context:

```php
// HTML content
echo '<div>' . Sanitizer::html($content) . '</div>';

// HTML attribute
echo '<input value="' . Sanitizer::attr($value) . '">';

// JavaScript
echo '<script>var x = ' . Sanitizer::js($value) . ';</script>';

// CSS
echo '<div style="color: ' . Sanitizer::css($color) . ';">';
```

### Always Validate First
Don't just sanitize - validate that input meets requirements:

```php
// BAD: Just sanitizing
$email = Sanitizer::html($_POST['email']);

// GOOD: Validate then use
if (!Validator::email($_POST['email'])) {
    die('Invalid email');
}
$email = $_POST['email']; // Now safe to use
```

### Use HTTPS-Only Validation
For security-critical URLs, require HTTPS:

```php
// Regular URL validation
Validator::url($url); // Allows HTTP

// HTTPS-only validation
Validator::httpsUrl($url); // Requires HTTPS
```

### Apply Security Headers
Apply security headers on every request:

```php
// In index.php or bootstrap file
use PhpAegis\Headers;

Headers::sendSecurityHeaders();
```

### Rate Limit Everything
Rate limit all user-facing endpoints:

```php
// API endpoints
$apiLimiter = RateLimiter::perHour(1000, $store);

// Login attempts
$loginLimiter = RateLimiter::perMinute(5, $store);

// Form submissions
$formLimiter = RateLimiter::perMinute(10, $store);
```

## Troubleshooting

### Headers Already Sent
If you get "headers already sent" errors, ensure Headers methods are called before any output:

```php
// GOOD
Headers::sendSecurityHeaders();
echo 'Content';

// BAD
echo 'Content';
Headers::sendSecurityHeaders(); // Error!
```

### Rate Limit Not Working
Ensure the storage directory is writable:

```bash
chmod 755 /var/ratelimit
```

### RDF Injection Not Prevented
Ensure you're using TurtleEscaper methods, not generic escaping:

```php
// BAD
$escaped = addslashes($value); // SQL escaping!

// GOOD
$escaped = TurtleEscaper::literal($value); // Turtle escaping
```

## Next Steps

- [WordPress Integration](WordPress-Integration.md) - WordPress-specific guide
- [IndieWeb Security](IndieWeb-Security.md) - IndieWeb protocols guide
- [Rate Limiting](Rate-Limiting.md) - Advanced rate limiting
- [Examples](Examples.md) - Code examples and recipes
- [Developer Guide](Developer-Guide.md) - API reference

## Support

- Report issues: [GitHub Issues](https://github.com/hyperpolymath/php-aegis/issues)
- View source: [GitHub Repository](https://github.com/hyperpolymath/php-aegis)
