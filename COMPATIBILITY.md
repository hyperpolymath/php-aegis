# php-aegis Compatibility Strategy

> **Note**: This document describes the planned compatibility strategy. The `php-aegis-compat` package is not yet implemented. See the [roadmap](ROADMAP_PRIORITY.md) for status.

## The Problem

php-aegis requires PHP 8.1+, but WordPress officially supports PHP 7.4+. This limits adoption in the WordPress ecosystem where many hosts still run PHP 7.4 or 8.0.

## Strategy: Dual-Package Approach

Instead of downgrading the main library, we will provide a separate compatibility package.

```
hyperpolymath/php-aegis          # PHP 8.1+ (main, recommended) ✅ Available
hyperpolymath/php-aegis-compat   # PHP 7.4+ (polyfill, limited) 📋 Planned
```

### Why Not Downgrade?

1. **Security**: PHP 8.1+ has better security defaults
2. **Type Safety**: Union types, enums, readonly properties
3. **Performance**: PHP 8.x is significantly faster
4. **Maintenance**: Supporting old PHP versions increases complexity

### The Compatibility Package

`php-aegis-compat` provides:
- Same API surface as php-aegis
- Works on PHP 7.4, 8.0
- Gracefully degrades when php-aegis is available

```php
<?php
// php-aegis-compat automatically uses php-aegis if available

namespace PhpAegisCompat;

if (class_exists('\\PhpAegis\\Sanitizer')) {
    // PHP 8.1+ with php-aegis installed
    class_alias('\\PhpAegis\\Sanitizer', 'PhpAegisCompat\\Sanitizer');
} else {
    // PHP 7.4/8.0 fallback
    class Sanitizer {
        public static function html(string $input): string {
            return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        // ... limited subset of methods
    }
}
```

### Installation

```bash
# For PHP 8.1+ projects (recommended)
composer require hyperpolymath/php-aegis

# For PHP 7.4+ projects (compatibility)
composer require hyperpolymath/php-aegis-compat
```

### What's Included in Compat

| Feature | php-aegis | php-aegis-compat |
|---------|-----------|------------------|
| `Sanitizer::html()` | ✅ | ✅ |
| `Sanitizer::attr()` | ✅ | ✅ |
| `Sanitizer::js()` | ✅ | ✅ |
| `Sanitizer::url()` | ✅ | ✅ |
| `Validator::email()` | ✅ | ✅ |
| `Validator::url()` | ✅ | ✅ |
| `Validator::ip()` | ✅ | ✅ |
| `Headers::secure()` | ✅ | ✅ |
| `TurtleEscaper` | ✅ | ❌ (complex escaping) |
| Enums/Union types | ✅ | ❌ (PHP 8.1+) |
| `readonly` properties | ✅ | ❌ (PHP 8.1+) |

---

## WordPress Adapter

WordPress uses `snake_case` naming conventions. We provide a WordPress adapter.

### Option 1: Function Wrappers

```php
<?php
// wp-content/mu-plugins/php-aegis-wordpress.php

if (!class_exists('\\PhpAegis\\Sanitizer') && !class_exists('\\PhpAegisCompat\\Sanitizer')) {
    return; // Neither package installed
}

$sanitizer = class_exists('\\PhpAegis\\Sanitizer')
    ? '\\PhpAegis\\Sanitizer'
    : '\\PhpAegisCompat\\Sanitizer';

// WordPress-style function wrappers
function aegis_html(string $input): string {
    global $sanitizer;
    return $sanitizer::html($input);
}

function aegis_attr(string $input): string {
    global $sanitizer;
    return $sanitizer::attr($input);
}

function aegis_js(string $input): string {
    global $sanitizer;
    return $sanitizer::js($input);
}

function aegis_url(string $input): string {
    global $sanitizer;
    return $sanitizer::url($input);
}

// Headers
function aegis_send_security_headers(): void {
    if (class_exists('\\PhpAegis\\Headers')) {
        \PhpAegis\Headers::secure();
    } elseif (class_exists('\\PhpAegisCompat\\Headers')) {
        \PhpAegisCompat\Headers::secure();
    }
}
```

### Option 2: WordPress Plugin

A dedicated WordPress plugin that:
1. Auto-detects php-aegis or php-aegis-compat
2. Registers WordPress-style functions
3. Integrates with WordPress's existing escaping functions
4. Adds admin UI for security header configuration

---

## Laravel Adapter

Laravel uses dependency injection. We provide a service provider.

```php
<?php
// config/app.php
'providers' => [
    PhpAegis\Laravel\AegisServiceProvider::class,
],

// Usage in controllers
public function store(Request $request, Sanitizer $sanitizer)
{
    $safe = $sanitizer->html($request->input('content'));
}

// Blade directive
@aegis($userContent) // Calls Sanitizer::html()
```

---

## Migration Path

### For WordPress Themes/Plugins

```php
// Before: Using WordPress functions only
echo esc_html($user_input);

// After: Using php-aegis with WordPress fallback
if (function_exists('aegis_html')) {
    echo aegis_html($user_input);
} else {
    echo esc_html($user_input);
}

// Or: Graceful one-liner
echo function_exists('aegis_html') ? aegis_html($user_input) : esc_html($user_input);
```

### For New Projects

```php
// Just use php-aegis directly
use PhpAegis\Sanitizer;

echo Sanitizer::html($user_input);
```

---

## Version Support Timeline

| PHP Version | Support Status | Recommended Package |
|-------------|---------------|---------------------|
| 7.4 | Legacy (EOL Dec 2022) | php-aegis-compat |
| 8.0 | Legacy (EOL Nov 2023) | php-aegis-compat |
| 8.1 | Security fixes only | php-aegis |
| 8.2 | Active | php-aegis |
| 8.3 | Active (current) | php-aegis |
| 8.4+ | Future | php-aegis |

**Recommendation**: Upgrade to PHP 8.2+ and use php-aegis directly.

---

## Implementation Checklist

- [ ] Create `hyperpolymath/php-aegis-compat` repository
- [ ] Implement core Sanitizer/Validator classes for PHP 7.4
- [ ] Add auto-detection for php-aegis (use if available)
- [ ] Create WordPress mu-plugin adapter
- [ ] Create Laravel service provider
- [ ] Publish both packages to Packagist
- [ ] Document migration paths

---

*This strategy maximizes adoption while maintaining security and code quality in the main package.*
