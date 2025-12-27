# php-aegis Positioning & Target Audience

## The Problem We Discovered

After integrating php-aegis with multiple WordPress projects (themes and plugins), we found:

> **WordPress already has comprehensive security APIs** (`esc_html()`, `esc_attr()`, `wp_kses()`, etc.) that are deeply integrated with the WordPress ecosystem.

This means php-aegis **should not compete** with WordPress core functions. Instead, it should:

1. **Target non-WordPress PHP applications** where no security API exists
2. **Provide unique capabilities** that WordPress (and other frameworks) lack

---

## Target Audience Matrix

| Audience | php-aegis Value | Recommendation |
|----------|-----------------|----------------|
| **WordPress plugins/themes** | Low | Use WordPress core functions |
| **Laravel applications** | Medium | Use Laravel's helpers, aegis for gaps |
| **Symfony applications** | Medium | Use Twig's escaping, aegis for gaps |
| **Vanilla PHP applications** | **High** | php-aegis is the primary security layer |
| **API-only services** | **High** | No view layer = no framework escaping |
| **CLI tools** | **High** | No framework = aegis fills the gap |
| **Microservices** | **High** | Lightweight, zero-dependency |
| **Semantic Web apps** | **Very High** | TurtleEscaper is unique |

---

## What WordPress Has (Don't Duplicate)

| WordPress Function | Purpose | php-aegis Equivalent |
|--------------------|---------|---------------------|
| `esc_html()` | HTML content escaping | `Sanitizer::html()` |
| `esc_attr()` | HTML attribute escaping | `Sanitizer::attr()` |
| `esc_url()` | URL escaping with protocol check | `Sanitizer::url()` |
| `esc_js()` | JavaScript escaping | `Sanitizer::js()` |
| `wp_kses()` | HTML filtering with allowlist | ❌ Not implemented |
| `wp_kses_post()` | HTML filtering for posts | ❌ Not implemented |
| `sanitize_text_field()` | Text sanitization | `Sanitizer::stripTags()` |
| `is_email()` | Email validation | `Validator::email()` |
| `wp_http_validate_url()` | URL validation + SSL | `Validator::url()` |
| `absint()` | Positive integer | `Validator::int(..., min: 0)` |

**For WordPress projects**: Use WordPress functions. They're more battle-tested, ecosystem-integrated, and maintained by Automattic.

---

## What php-aegis Provides (Unique Value)

These capabilities are **not available** in WordPress, Laravel, or Symfony:

### 1. RDF/Turtle Escaping (Unique)

No other PHP library provides W3C-compliant Turtle escaping.

```php
use PhpAegis\TurtleEscaper;

// Safe for semantic web applications
TurtleEscaper::string($userLabel);
TurtleEscaper::iri($userProvidedUri);
TurtleEscaper::triple($subject, $predicate, $object, 'en');
```

**Use cases**:
- Linked Data platforms
- Knowledge graphs
- Semantic WordPress themes (like wp-sinople-theme)
- SPARQL endpoint integrations

### 2. Security Headers Helper

WordPress doesn't provide header helpers. Frameworks have partial support.

```php
use PhpAegis\Headers;

// One-line security hardening
Headers::secure();

// Or fine-grained control
Headers::contentSecurityPolicy([...]);
Headers::strictTransportSecurity(maxAge: 31536000, preload: true);
Headers::permissionsPolicy([...]);
```

### 3. Extended Validators Not in WordPress

| php-aegis | WordPress Equivalent | Notes |
|-----------|---------------------|-------|
| `Validator::uuid()` | ❌ None | RFC 4122 UUID validation |
| `Validator::ip()` | ❌ None | IPv4/IPv6 validation |
| `Validator::ipv4()` | ❌ None | IPv4 only |
| `Validator::ipv6()` | ❌ None | IPv6 only |
| `Validator::domain()` | ❌ None | RFC 1035 domain validation |
| `Validator::hostname()` | ❌ None | Domain or IP |
| `Validator::slug()` | `sanitize_title()` | WP sanitizes, aegis validates |
| `Validator::semver()` | ❌ None | Semantic versioning |
| `Validator::iso8601()` | ❌ None | ISO 8601 datetime |
| `Validator::hexColor()` | `sanitize_hex_color()` | WP sanitizes, aegis validates |
| `Validator::safeFilename()` | `sanitize_file_name()` | WP sanitizes, aegis validates |
| `Validator::json()` | ❌ None | JSON structure validation |
| `Validator::int(min, max)` | ❌ None | Integer with range |
| `Validator::printable()` | ❌ None | ASCII printable only |
| `Validator::noNullBytes()` | ❌ None | Path traversal prevention |
| `Validator::httpsUrl()` | `wp_http_validate_url()` | WP has `$ssl` param |

### 4. Zero Dependencies

- WordPress functions require WordPress
- Laravel helpers require Laravel
- Symfony components require Symfony

php-aegis works in any PHP 8.1+ environment with no dependencies.

---

## Recommended Usage Patterns

### For WordPress Projects

```php
// DON'T: Use php-aegis for basic escaping
echo \PhpAegis\Sanitizer::html($content);  // ❌ Redundant

// DO: Use WordPress functions
echo esc_html($content);  // ✅ Preferred

// DO: Use php-aegis for unique capabilities
$headers = new \PhpAegis\Headers();
$headers::secure();  // ✅ WordPress lacks this

// DO: Use php-aegis for semantic web features
echo \PhpAegis\TurtleEscaper::string($label);  // ✅ WordPress lacks this

// DO: Use php-aegis for validation gaps
if (!\PhpAegis\Validator::uuid($_GET['id'])) {  // ✅ WordPress lacks this
    wp_die('Invalid ID');
}
```

### For Laravel Projects

```php
// DON'T: Use php-aegis for Blade escaping
{{ $content }}  // Blade auto-escapes, don't use aegis

// DO: Use php-aegis in non-Blade contexts
$uuid = $request->input('resource_id');
if (!Validator::uuid($uuid)) {
    abort(400, 'Invalid resource ID');
}

// DO: Use for security headers (Laravel's is less comprehensive)
Headers::secure();
```

### For Vanilla PHP / APIs

```php
// DO: Use php-aegis as your primary security layer
use PhpAegis\{Validator, Sanitizer, Headers};

// Apply security headers
Headers::secure();

// Validate input
if (!Validator::email($_POST['email'])) {
    http_response_code(400);
    exit(json_encode(['error' => 'Invalid email']));
}

// Sanitize output
echo Sanitizer::html($userContent);
```

---

## Marketing Positioning

### Tagline Options

1. **"Security for the rest of PHP"** - Emphasizes non-framework use
2. **"Where frameworks fear to tread"** - Emphasizes unique capabilities
3. **"Semantic web security, done right"** - Emphasizes Turtle escaping niche

### README Messaging

```
php-aegis is a zero-dependency PHP security toolkit for:
- API services without view layers
- CLI tools and microservices
- Semantic web applications (RDF/Turtle)
- Any PHP app without a framework

For WordPress, use WordPress core functions.
For Laravel/Symfony, use framework helpers + aegis for gaps.
```

---

## Roadmap Implications

Based on this positioning, prioritize:

1. **RDF/Turtle escaping** - Already done, unique differentiator
2. **Security headers** - Already done, fills framework gaps
3. **Extended validators** - Focus on what WordPress lacks (UUID, IP, semver, etc.)
4. **IndieWeb security** - Micropub, IndieAuth, Webmention (unique niche)
5. **Rate limiting** - File-based, no Redis required

De-prioritize:
- HTML/attribute escaping improvements (frameworks do this well)
- WordPress adapter (WordPress users should use WordPress functions)

---

## Success Metrics

| Metric | Target Audience Indicator |
|--------|--------------------------|
| Downloads from API/microservice projects | Primary audience |
| Usage in semantic web tools | Niche but high-value |
| Issues asking about WordPress | Signals need for better docs |
| PRs adding framework adapters | Community wants integration |

---

*This positioning reflects insights from WordPress theme (wp-sinople-theme) and plugin (Zotpress) integration attempts.*
