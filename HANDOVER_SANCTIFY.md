# Handover Document: sanctify-php Integration Insights

## Context

This document summarizes findings from integrating `php-aegis` and `sanctify-php` into a WordPress semantic theme (wp-sinople-theme). It provides actionable recommendations for the `sanctify-php` team based on real-world usage patterns.

## Role Clarification

| Tool | Role | When Used |
|------|------|-----------|
| **php-aegis** | Runtime security library | During request handling (validation, sanitization, headers) |
| **sanctify-php** | Static analysis tool | During development/CI (find vulnerabilities before deploy) |

These are **complementary**, not competing tools:
- `sanctify-php` finds the bugs
- `php-aegis` provides the fixes

## Issues Discovered During Integration

### 1. Haskell Toolchain Dependency

**Problem**: `sanctify-php` requires GHC/Cabal to build, which is a significant barrier for PHP developers.

**Impact**: Most PHP teams don't have Haskell expertise or toolchain installed.

**Recommendations**:
- Provide pre-built binaries for Linux (x86_64, aarch64), macOS (Intel, Apple Silicon), Windows
- Create official Docker image: `ghcr.io/hyperpolymath/sanctify-php:latest`
- Consider GitHub Actions integration that runs analysis without local install
- Add installation via common package managers (Homebrew, apt, nix)

**Example Docker usage**:
```bash
docker run --rm -v $(pwd):/workspace ghcr.io/hyperpolymath/sanctify-php analyze /workspace
```

### 2. PHP 8.x Syntax Support

**Problem**: Parser may not handle all PHP 8.x syntax (enums, union types, named arguments, attributes, match expressions, constructor property promotion).

**Test cases needed**:
```php
// Enums (PHP 8.1+)
enum Status: string {
    case Draft = 'draft';
    case Published = 'published';
}

// Union types (PHP 8.0+)
function process(string|int $input): string|false { ... }

// Attributes (PHP 8.0+)
#[Route('/api/users')]
class UserController { ... }

// Constructor property promotion (PHP 8.0+)
class User {
    public function __construct(
        public readonly string $name,
        private int $age = 0,
    ) {}
}

// Named arguments (PHP 8.0+)
htmlspecialchars(string: $input, flags: ENT_QUOTES);

// Match expressions (PHP 8.0+)
$result = match($status) {
    Status::Draft => 'Editing',
    Status::Published => 'Live',
};
```

**Recommendation**: Add PHP 8.x grammar rules and comprehensive test suite.

### 3. RDF/Turtle Output Context Awareness

**Problem**: Static analyzer doesn't detect RDF/Turtle injection vulnerabilities in semantic web themes.

**Background**: Semantic WordPress themes output RDF Turtle format for linked data. Standard XSS detection won't catch Turtle-specific injection vectors.

**Vulnerable pattern** (not currently detected):
```php
// DANGEROUS: addslashes() is insufficient for Turtle
$turtle = '<' . $uri . '> rdfs:label "' . addslashes($label) . '" .';
```

**Attack vectors**:
```turtle
# Turtle escape sequences
\n \r \t \\ \" \uXXXX \UXXXXXXXX

# IRI injection
<http://evil.com> owl:sameAs <http://trusted.com>
```

**Recommendation**: Add detection rules for:
- `addslashes()` used in RDF/Turtle context
- Unescaped variables in Turtle string literals (`"..."`)
- Unescaped IRIs (`<...>`)
- Missing use of proper escaping functions

**Suggested rule signatures**:
```
turtle_string_injection: Detects unescaped user input in Turtle string literals
turtle_iri_injection: Detects unescaped user input in Turtle IRIs
rdf_semantic_injection: Detects potential semantic attacks via RDF
```

### 4. WordPress Integration Documentation

**Problem**: No clear guidance for WordPress-specific vulnerability patterns.

**WordPress-specific patterns to detect**:

```php
// DANGEROUS: Direct $_GET/$_POST usage
echo $_GET['query'];  // XSS

// DANGEROUS: Missing nonce verification
if (isset($_POST['action'])) { ... }  // CSRF

// DANGEROUS: Direct SQL interpolation
$wpdb->query("SELECT * FROM users WHERE id = " . $_GET['id']);  // SQLi

// DANGEROUS: Unescaped output
echo $user_input;  // Should use esc_html(), esc_attr(), etc.

// DANGEROUS: Privileged action without capability check
add_action('wp_ajax_delete_user', 'delete_user_handler');
function delete_user_handler() {
    // Missing: current_user_can('delete_users')
    wp_delete_user($_POST['user_id']);
}
```

**WordPress-specific safe patterns**:
```php
// Safe escaping functions
esc_html($text)
esc_attr($attr)
esc_url($url)
wp_kses($html, $allowed)
wp_kses_post($html)

// Safe nonce verification
wp_verify_nonce($_POST['_wpnonce'], 'action_name')
check_admin_referer('action_name')

// Safe capability checks
current_user_can('edit_posts')
```

**Recommendation**: Create WordPress-specific ruleset that:
- Detects missing `esc_*` function usage
- Detects missing nonce verification in form handlers
- Detects missing capability checks in AJAX handlers
- Recognizes WordPress sanitization functions as safe sinks

### 5. IndieWeb/Micropub Pattern Detection

**Problem**: No awareness of IndieWeb protocols (Micropub, IndieAuth, Webmention).

**Patterns to detect**:

```php
// DANGEROUS: Missing IndieAuth token verification
function handle_micropub($request) {
    $content = $request['content'];  // Unverified!
    create_post($content);
}

// DANGEROUS: Webmention SSRF
function verify_webmention($source) {
    $response = wp_remote_get($source);  // Can hit internal IPs
}

// DANGEROUS: Micropub content injection
$mf2 = Mf2\parse($html, $source);
$content = $mf2['items'][0]['properties']['content'][0];
echo $content;  // Unsanitized from external source
```

**Recommendation**: Add rules for common IndieWeb vulnerability patterns.

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Development Workflow                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Developer   │───▶│ sanctify-php │───▶│   Fix Code   │  │
│  │  Writes Code │    │  (Analysis)  │    │  (Guidance)  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                              │                               │
│                              ▼                               │
│                     ┌──────────────┐                        │
│                     │  php-aegis   │                        │
│                     │  (Runtime)   │                        │
│                     └──────────────┘                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Recommended sanctify-php Output Format

When `sanctify-php` detects a vulnerability, it should suggest the `php-aegis` fix:

```
VULNERABILITY: XSS in output context
FILE: theme/template.php:42
CODE: echo $user_input;

RECOMMENDATION:
  Use php-aegis Sanitizer for proper encoding:

  Before: echo $user_input;
  After:  echo \PhpAegis\Sanitizer::html($user_input);

  Install: composer require hyperpolymath/php-aegis
```

## Priority Recommendations Summary

| Priority | Issue | Effort |
|----------|-------|--------|
| P0 | Pre-built binaries / Docker image | Medium |
| P0 | PHP 8.x syntax support | High |
| P1 | WordPress-specific rulesets | Medium |
| P1 | RDF/Turtle context detection | Medium |
| P2 | IndieWeb protocol patterns | Low |
| P2 | php-aegis fix suggestions in output | Low |

## Contact

For questions about this integration or to coordinate between repos:
- php-aegis: https://github.com/hyperpolymath/php-aegis
- Integration tested in: wp-sinople-theme

---

*Generated from real-world WordPress semantic theme integration experience.*
