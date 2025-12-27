# Secure Defaults Checklist

This document provides a comprehensive checklist for secure PHP development using php-aegis. Follow these guidelines to ensure your application follows security best practices.

## Table of Contents

- [PHP Configuration](#php-configuration)
- [Input Validation](#input-validation)
- [Output Sanitization](#output-sanitization)
- [HTTP Security Headers](#http-security-headers)
- [Authentication & Sessions](#authentication--sessions)
- [Database Security](#database-security)
- [File Operations](#file-operations)
- [Cryptography](#cryptography)
- [Error Handling](#error-handling)
- [CI/CD Security](#cicd-security)
- [Dependency Management](#dependency-management)

---

## PHP Configuration

### Required Settings

```ini
; Strict error reporting (development)
error_reporting = E_ALL
display_errors = Off
log_errors = On

; Session security
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Strict
session.use_strict_mode = 1
session.use_only_cookies = 1

; Disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source,eval

; File upload limits
upload_max_filesize = 10M
max_file_uploads = 5

; Exposure reduction
expose_php = Off
```

### Checklist

- [ ] `declare(strict_types=1)` at top of every PHP file
- [ ] Error display disabled in production (`display_errors = Off`)
- [ ] Error logging enabled (`log_errors = On`)
- [ ] Dangerous functions disabled where not needed
- [ ] PHP version exposure disabled (`expose_php = Off`)
- [ ] Session cookies are HttpOnly and Secure
- [ ] Appropriate memory and execution limits set

---

## Input Validation

### Using php-aegis Validator

```php
use PhpAegis\Validator;

// Always validate before use
$email = Validator::email($_POST['email'] ?? '') ? $_POST['email'] : null;
$url = Validator::httpsUrl($_POST['website'] ?? '') ? $_POST['website'] : null;
$id = Validator::uuid($_GET['id'] ?? '') ? $_GET['id'] : null;
```

### Checklist

- [ ] **Never trust user input** - validate ALL external data
- [ ] Use `Validator::email()` for email addresses
- [ ] Use `Validator::httpsUrl()` for URLs (enforce HTTPS)
- [ ] Use `Validator::uuid()` for identifiers
- [ ] Use `Validator::int()` with min/max bounds for integers
- [ ] Use `Validator::noNullBytes()` to prevent null byte injection
- [ ] Use `Validator::safeFilename()` for user-provided filenames
- [ ] Use `Validator::printable()` for text that should have no control chars
- [ ] Reject invalid input rather than attempting to "fix" it
- [ ] Validate data types, lengths, formats, and ranges
- [ ] Use allowlists over denylists where possible

### Validation Priority

| Input Source | Risk Level | Required Validation |
|-------------|------------|---------------------|
| `$_GET` | High | Always validate |
| `$_POST` | High | Always validate |
| `$_FILES` | Critical | Validate + scan |
| `$_COOKIE` | High | Always validate |
| `$_SERVER` | Medium | Validate if user-influenced |
| Database | Medium | Validate on retrieval |
| APIs | Medium | Validate responses |

---

## Output Sanitization

### Using php-aegis Sanitizer

```php
use PhpAegis\Sanitizer;

// HTML context
echo Sanitizer::html($userInput);

// HTML attribute context
echo '<input value="' . Sanitizer::attr($value) . '">';

// JavaScript context
echo '<script>var data = ' . Sanitizer::js($data) . ';</script>';

// URL context
echo '<a href="' . Sanitizer::url($link) . '">Link</a>';

// CSS context (limited support - prefer external stylesheets)
echo '<div style="color: ' . Sanitizer::css($color) . ';">';
```

### Checklist

- [ ] **Context-aware escaping** - use the right method for each context
- [ ] Use `Sanitizer::html()` for HTML body content
- [ ] Use `Sanitizer::attr()` for HTML attributes
- [ ] Use `Sanitizer::js()` for inline JavaScript
- [ ] Use `Sanitizer::url()` for URL components
- [ ] Use `Sanitizer::json()` for JSON output
- [ ] Use `Sanitizer::filename()` before file operations
- [ ] Never use `htmlspecialchars()` alone - it's not context-aware
- [ ] Never output user data in `<script>` without `Sanitizer::js()`
- [ ] Never use user data in CSS without validation

### XSS Prevention Matrix

| Context | Safe Method | Unsafe |
|---------|-------------|--------|
| HTML body | `Sanitizer::html()` | `echo $var` |
| HTML attribute | `Sanitizer::attr()` | `value="$var"` |
| JavaScript | `Sanitizer::js()` | `var x = '$var'` |
| URL | `Sanitizer::url()` | `href="$var"` |
| CSS | `Sanitizer::css()` | `style="$var"` |
| JSON | `Sanitizer::json()` | `json_encode()` alone |

---

## HTTP Security Headers

### Using php-aegis Headers

```php
use PhpAegis\Headers;

// Apply all recommended security headers at once
Headers::secure();

// Or configure individually
Headers::contentSecurityPolicy("default-src 'self'; script-src 'self'");
Headers::strictTransportSecurity(31536000, true, true);
Headers::frameOptions('DENY');
Headers::contentTypeOptions();
Headers::referrerPolicy('strict-origin-when-cross-origin');
Headers::permissionsPolicy([
    'camera' => [],
    'microphone' => [],
    'geolocation' => ['self'],
]);
```

### Checklist

- [ ] Call `Headers::secure()` early in request lifecycle
- [ ] Use Content-Security-Policy (CSP) to prevent XSS
- [ ] Enable HSTS with `includeSubDomains` and `preload`
- [ ] Set `X-Frame-Options: DENY` unless framing is needed
- [ ] Set `X-Content-Type-Options: nosniff`
- [ ] Configure appropriate `Referrer-Policy`
- [ ] Restrict features with `Permissions-Policy`
- [ ] Remove server identification headers

### Recommended Header Values

| Header | Recommended Value |
|--------|-------------------|
| Content-Security-Policy | `default-src 'self'; script-src 'self'; style-src 'self'` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload` |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` |

---

## Authentication & Sessions

### Checklist

- [ ] Use `password_hash()` with `PASSWORD_ARGON2ID` (or `PASSWORD_BCRYPT`)
- [ ] Use `password_verify()` for comparison (timing-safe)
- [ ] Regenerate session ID on privilege change (`session_regenerate_id(true)`)
- [ ] Set session cookie flags: `HttpOnly`, `Secure`, `SameSite=Strict`
- [ ] Implement session timeout (idle and absolute)
- [ ] Use CSRF tokens for state-changing operations
- [ ] Rate-limit authentication attempts
- [ ] Log authentication events
- [ ] Use secure password reset flows (time-limited tokens)

### Password Requirements

```php
// Minimum secure password hashing
$hash = password_hash($password, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,  // 64MB
    'time_cost' => 4,        // 4 iterations
    'threads' => 3,          // 3 parallel threads
]);

// Verify
if (password_verify($input, $hash)) {
    // Check if rehash needed (algorithm updates)
    if (password_needs_rehash($hash, PASSWORD_ARGON2ID)) {
        $newHash = password_hash($input, PASSWORD_ARGON2ID);
        // Update stored hash
    }
}
```

---

## Database Security

### Checklist

- [ ] **Always use prepared statements** with bound parameters
- [ ] Use PDO with `ATTR_EMULATE_PREPARES = false`
- [ ] Set `ATTR_ERRMODE = ERRMODE_EXCEPTION`
- [ ] Use least-privilege database accounts
- [ ] Escape identifiers (table/column names) if dynamic
- [ ] Validate and allowlist ORDER BY columns
- [ ] Limit query results appropriately
- [ ] Log slow queries and failures

### Secure PDO Configuration

```php
$pdo = new PDO($dsn, $user, $pass, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false,      // Use real prepared statements
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::MYSQL_ATTR_MULTI_STATEMENTS => false, // Prevent multi-query attacks
]);

// Always use prepared statements
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);  // $id is bound, not interpolated
```

---

## File Operations

### Checklist

- [ ] Validate file extensions against allowlist
- [ ] Validate MIME types (don't trust Content-Type header alone)
- [ ] Use `Validator::safeFilename()` for user-provided names
- [ ] Store uploads outside web root
- [ ] Generate random filenames for stored files
- [ ] Set restrictive permissions (0644 for files, 0755 for dirs)
- [ ] Limit file sizes at PHP and web server level
- [ ] Scan uploads for malware if handling untrusted files
- [ ] Never use user input in `include`/`require` paths

### Secure File Upload

```php
use PhpAegis\Validator;
use PhpAegis\Sanitizer;

$allowed = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$maxSize = 5 * 1024 * 1024; // 5MB

$file = $_FILES['upload'] ?? null;
if (!$file || $file['error'] !== UPLOAD_ERR_OK) {
    throw new Exception('Upload failed');
}

if ($file['size'] > $maxSize) {
    throw new Exception('File too large');
}

$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed, true)) {
    throw new Exception('Invalid file type');
}

// Generate safe filename
$safeName = bin2hex(random_bytes(16)) . '.' . $ext;
$uploadDir = '/var/uploads/';  // Outside web root!
move_uploaded_file($file['tmp_name'], $uploadDir . $safeName);
```

---

## Cryptography

### Checklist

- [ ] **Never use MD5 or SHA1** for security purposes
- [ ] Use `random_bytes()` for secure random data
- [ ] Use `hash_equals()` for timing-safe comparisons
- [ ] Use `sodium_*` functions for encryption
- [ ] Use `PASSWORD_ARGON2ID` for password hashing
- [ ] Store secrets in environment variables, not code
- [ ] Use HTTPS everywhere (no HTTP)
- [ ] Pin certificates for sensitive API connections

### Secure Defaults

| Use Case | Algorithm | PHP Function |
|----------|-----------|--------------|
| Passwords | Argon2id | `password_hash()` |
| Random tokens | CSPRNG | `random_bytes()` |
| Data hashing | SHA-256+ | `hash('sha256', ...)` |
| HMAC | SHA-256+ | `hash_hmac('sha256', ...)` |
| Encryption | XChaCha20-Poly1305 | `sodium_crypto_secretbox()` |
| Key derivation | Argon2id | `sodium_crypto_pwhash()` |
| String comparison | Timing-safe | `hash_equals()` |

---

## Error Handling

### Checklist

- [ ] Never expose stack traces to users in production
- [ ] Log errors with sufficient context for debugging
- [ ] Use custom error pages (don't reveal framework/PHP version)
- [ ] Handle exceptions at application boundaries
- [ ] Don't log sensitive data (passwords, tokens, PII)
- [ ] Monitor error logs for security issues
- [ ] Return generic error messages to clients

### Error Handler Pattern

```php
set_exception_handler(function (Throwable $e): void {
    // Log full details
    error_log(sprintf(
        "[%s] %s in %s:%d\n%s",
        get_class($e),
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        $e->getTraceAsString()
    ));

    // Generic response to client
    http_response_code(500);
    echo json_encode(['error' => 'An unexpected error occurred']);
    exit(1);
});
```

---

## CI/CD Security

### Required Checks

- [ ] PHPStan at level 9 (maximum strictness)
- [ ] PHP-CS-Fixer with PSR-12 standard
- [ ] PHPUnit tests with coverage requirements
- [ ] Secret scanning (TruffleHog, git-secrets)
- [ ] Dependency vulnerability scanning (Composer audit)
- [ ] SAST scanning (CodeQL, Psalm)
- [ ] License compliance checking

### Workflow Security

- [ ] Pin GitHub Actions to commit SHAs (not version tags)
- [ ] Use minimal permissions (`permissions: read-all`)
- [ ] Never store secrets in code or logs
- [ ] Require code review for main branch
- [ ] Enable branch protection rules
- [ ] Sign commits with GPG

### Sample CI Checks

```yaml
# Minimum CI checks for PHP projects
- PHPStan level 9
- PHP-CS-Fixer --dry-run
- PHPUnit with coverage
- composer audit (dependency vulnerabilities)
- TruffleHog (secret detection)
- SPDX license header check
```

---

## Dependency Management

### Checklist

- [ ] Run `composer audit` regularly
- [ ] Use `composer.lock` for reproducible builds
- [ ] Review dependencies before adding
- [ ] Minimize dependency count
- [ ] Prefer well-maintained packages
- [ ] Check licenses are compatible (SPDX)
- [ ] Enable Dependabot/Renovate for updates
- [ ] Verify package integrity (checksums)

### composer.json Best Practices

```json
{
    "config": {
        "sort-packages": true,
        "preferred-install": "dist",
        "optimize-autoloader": true,
        "secure-http": true
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
```

---

## Quick Reference

### Do ✅

- Validate all input with php-aegis Validator
- Escape all output with php-aegis Sanitizer
- Use prepared statements for all database queries
- Apply security headers with php-aegis Headers
- Use `declare(strict_types=1)` everywhere
- Use Argon2id for password hashing
- Pin CI action versions to commit SHAs
- Log security events

### Don't ❌

- Trust user input without validation
- Output user data without escaping
- Concatenate SQL queries with user input
- Use MD5/SHA1 for security
- Store secrets in code
- Expose error details to users
- Use `eval()`, `exec()`, or similar functions
- Disable HTTPS requirements

---

## Testing Your Secure Defaults

Run these commands to verify your configuration:

```bash
# Static analysis (max strictness)
composer analyze   # PHPStan level 9

# Code style
composer lint      # PHP-CS-Fixer check

# Tests
composer test      # PHPUnit

# Dependency audit
composer audit     # Check for vulnerabilities
```

---

## Resources

- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP: The Right Way - Security](https://phptherightway.com/#security)
- [OWASP Top 10](https://owasp.org/Top10/)
- [php-aegis Documentation](https://github.com/hyperpolymath/php-aegis)
