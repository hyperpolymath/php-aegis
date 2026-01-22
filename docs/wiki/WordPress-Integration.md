# WordPress Integration

Complete guide to using php-aegis with WordPress.

## Installation

### Option 1: Must-Use Plugin (Recommended)
1. Install php-aegis via Composer in your WordPress root
2. Copy MU-plugin template:
   ```bash
   cp vendor/hyperpolymath/php-aegis/docs/wordpress/aegis-mu-plugin.php wp-content/mu-plugins/
   ```
3. Activate automatically (MU-plugins auto-activate)

### Option 2: Theme Functions
Add to `functions.php`:
```php
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/vendor/hyperpolymath/php-aegis/docs/wordpress/aegis-functions.php';
```

### Option 3: Regular Plugin
Create `wp-content/plugins/php-aegis-wp/php-aegis-wp.php`:
```php
<?php
/**
 * Plugin Name: php-aegis WordPress Integration
 * Description: Security utilities from php-aegis
 * Version: 0.2.0
 */

require_once __DIR__ . '/../../vendor/autoload.php';
require_once __DIR__ . '/../../vendor/hyperpolymath/php-aegis/docs/wordpress/aegis-functions.php';
```

## Available Functions

php-aegis provides 23 WordPress-style functions:

### Sanitization (8 functions)

#### aegis_html()
WordPress equivalent: `esc_html()`
```php
echo '<p>' . aegis_html($content) . '</p>';
```

#### aegis_attr()
WordPress equivalent: `esc_attr()`
```php
echo '<input value="' . aegis_attr($value) . '">';
```

#### aegis_js()
WordPress equivalent: `esc_js()`
```php
echo '<script>var data = ' . aegis_js($data) . ';</script>';
```

#### aegis_url()
WordPress equivalent: `esc_url()`
```php
echo '<a href="' . aegis_url($link) . '">Link</a>';
```

#### aegis_css()
Remove dangerous CSS characters:
```php
echo '<div style="color: ' . aegis_css($color) . ';">';
```

#### aegis_json()
WordPress equivalent: `wp_json_encode()`
```php
echo '<script>var config = ' . aegis_json($config) . ';</script>';
```

#### aegis_strip_tags()
WordPress equivalent: `wp_strip_all_tags()`
```php
$plain = aegis_strip_tags('<p>HTML <b>content</b></p>');
```

#### aegis_filename()
WordPress equivalent: `sanitize_file_name()`
```php
$safe = aegis_filename('../../../etc/passwd');
```

### RDF/Turtle Functions (4 functions - UNIQUE!)

**No WordPress equivalent** - php-aegis exclusive feature!

#### aegis_turtle_string()
```php
$escaped = aegis_turtle_string('Value with "quotes"');
```

#### aegis_turtle_iri()
```php
$escaped = aegis_turtle_iri('https://example.org/resource#1');
```

#### aegis_turtle_literal()
```php
// With language tag
echo aegis_turtle_literal('Hello World', 'en');
// Output: "Hello World"@en

// With datatype
echo aegis_turtle_literal('42', null, 'http://www.w3.org/2001/XMLSchema#integer');
```

#### aegis_turtle_triple()
```php
$subject = 'https://example.org/person/1';
$predicate = 'http://xmlns.com/foaf/0.1/name';
$object = 'Alice Smith';

echo aegis_turtle_triple($subject, $predicate, $object, 'en') . "\n";
// Output: <https://example.org/person/1> <http://xmlns.com/foaf/0.1/name> "Alice Smith"@en .
```

### Validation Functions (8 functions)

#### aegis_validate_email()
WordPress equivalent: `is_email()`
```php
if (!aegis_validate_email($email)) {
    wp_die('Invalid email');
}
```

#### aegis_validate_url()
WordPress equivalent: `wp_http_validate_url()`
```php
if (!aegis_validate_url($url)) {
    wp_die('Invalid URL');
}

// HTTPS-only
if (!aegis_validate_url($url, true)) {
    wp_die('HTTPS required');
}
```

#### Other Validators
- `aegis_validate_ip($ip)` - IP address
- `aegis_validate_uuid($uuid)` - UUID
- `aegis_validate_slug($slug)` - URL slug
- `aegis_validate_json($json)` - JSON string
- `aegis_validate_semver($version)` - Semantic version
- `aegis_validate_domain($domain)` - Domain name

### Security Header Functions (3 functions)

#### aegis_send_security_headers()
Apply all security headers:
```php
add_action('send_headers', 'aegis_send_security_headers');
```

#### aegis_csp()
Set Content-Security-Policy:
```php
aegis_csp([
    'default-src' => ["'self'"],
    'script-src' => ["'self'", 'https://cdn.example.com'],
]);
```

#### aegis_hsts()
Set Strict-Transport-Security:
```php
aegis_hsts(31536000, true, true); // 1 year, subdomains, preload
```

## Usage Examples

### Theme Template
```php
<?php get_header(); ?>

<article>
    <h1><?php echo aegis_html(get_the_title()); ?></h1>
    <div class="content">
        <?php echo aegis_html(get_the_content()); ?>
    </div>

    <a href="<?php echo aegis_url(get_permalink()); ?>"
       title="<?php echo aegis_attr(get_the_title()); ?>">
        Read more
    </a>
</article>

<?php get_footer(); ?>
```

### Custom Meta Box
```php
add_action('add_meta_boxes', function() {
    add_meta_box('custom_meta', 'Custom Data', function($post) {
        $value = get_post_meta($post->ID, 'custom_field', true);
        ?>
        <input type="text"
               name="custom_field"
               value="<?php echo aegis_attr($value); ?>">
        <?php
    });
});

add_action('save_post', function($post_id) {
    if (isset($_POST['custom_field'])) {
        // Validate first
        if (!aegis_validate_email($_POST['custom_field'])) {
            wp_die('Invalid email');
        }
        update_post_meta($post_id, 'custom_field', $_POST['custom_field']);
    }
});
```

### Ajax Handler
```php
add_action('wp_ajax_custom_action', function() {
    if (!aegis_validate_uuid($_POST['item_id'])) {
        wp_send_json_error('Invalid ID');
    }

    $result = ['message' => 'Success', 'data' => $data];
    echo aegis_json($result);
    wp_die();
});
```

### Settings Page
```php
add_action('admin_menu', function() {
    add_options_page('Security Settings', 'Security', 'manage_options', 'security-settings', function() {
        ?>
        <h1><?php echo aegis_html('Security Settings'); ?></h1>
        <form method="post">
            <?php wp_nonce_field('security_settings'); ?>

            <label>API URL (HTTPS only):</label>
            <input type="url"
                   name="api_url"
                   value="<?php echo aegis_attr(get_option('api_url')); ?>"
                   required>

            <button type="submit">Save</button>
        </form>
        <?php

        if ($_POST) {
            check_admin_referer('security_settings');

            if (!aegis_validate_url($_POST['api_url'], true)) {
                echo '<div class="error">HTTPS required</div>';
            } else {
                update_option('api_url', $_POST['api_url']);
                echo '<div class="updated">Saved</div>';
            }
        }
    });
});
```

## RDF/Turtle in WordPress

### Semantic Web Plugins
Use php-aegis for semantic web features:

```php
// Generate RDF data for posts
add_action('wp_head', function() {
    if (!is_single()) return;

    $post_id = get_the_ID();
    $post_url = get_permalink($post_id);
    $title = get_the_title($post_id);
    $author = get_the_author();

    echo '<script type="text/turtle">' . "\n";
    echo aegis_turtle_triple(
        $post_url,
        'http://purl.org/dc/terms/title',
        $title,
        get_locale()
    ) . "\n";
    echo aegis_turtle_triple(
        $post_url,
        'http://purl.org/dc/terms/creator',
        $author,
        null
    ) . "\n";
    echo '</script>' . "\n";
});
```

## MU-Plugin Features

The MU-plugin template provides:

### Auto-Load Composer
Automatically finds Composer autoloader in 3 locations:
1. `wp-content/vendor/autoload.php`
2. `../vendor/autoload.php` (WordPress root)
3. `../../vendor/autoload.php` (above WordPress)

### Security Headers on Every Request
```php
add_action('send_headers', function() {
    if (function_exists('aegis_send_security_headers')) {
        aegis_send_security_headers();
    }
}, 1);
```

### Dashboard Widget
Shows php-aegis status and available functions.

### Post Editor Meta Box
Quick reference for php-aegis functions in post editor.

### Admin Notices
Alerts if Composer dependencies missing.

## Best Practices

### 1. Validate Input, Sanitize Output
```php
// Input validation
if (!aegis_validate_email($_POST['email'])) {
    wp_die('Invalid email');
}

// Output sanitization
echo '<p>' . aegis_html($email) . '</p>';
```

### 2. Context-Aware Escaping
```php
echo '<div>' . aegis_html($content) . '</div>';                  // HTML
echo '<input value="' . aegis_attr($value) . '">';               // Attribute
echo '<script>var x = ' . aegis_js($data) . ';</script>';        // JavaScript
echo '<div style="color: ' . aegis_css($color) . ';">';          // CSS
```

### 3. Security Headers Early
```php
// In MU-plugin or early in functions.php
add_action('send_headers', 'aegis_send_security_headers', 1);
```

### 4. RDF for Semantic Data
```php
// Use RDF/Turtle for semantic web features
function generate_schema_org_rdf($post) {
    $url = get_permalink($post);
    $title = get_the_title($post);

    return aegis_turtle_triple(
        $url,
        'http://schema.org/name',
        $title,
        get_locale()
    );
}
```

## Migrating from WordPress Functions

| WordPress Function | php-aegis Equivalent | Notes |
|-------------------|----------------------|-------|
| `esc_html()` | `aegis_html()` | Same behavior |
| `esc_attr()` | `aegis_attr()` | Same behavior |
| `esc_js()` | `aegis_js()` | Same behavior |
| `esc_url()` | `aegis_url()` | Same behavior |
| `wp_json_encode()` | `aegis_json()` | Similar |
| `wp_strip_all_tags()` | `aegis_strip_tags()` | Same behavior |
| `sanitize_file_name()` | `aegis_filename()` | Similar |
| `is_email()` | `aegis_validate_email()` | Same behavior |
| `wp_http_validate_url()` | `aegis_validate_url()` | Similar |
| N/A | `aegis_turtle_*()` | **UNIQUE!** |

## Troubleshooting

### Functions Not Available
Check Composer autoloader is loaded:
```php
if (!function_exists('aegis_html')) {
    require_once __DIR__ . '/vendor/autoload.php';
    require_once __DIR__ . '/vendor/hyperpolymath/php-aegis/docs/wordpress/aegis-functions.php';
}
```

### Headers Already Sent
Call `aegis_send_security_headers()` before any output:
```php
add_action('send_headers', 'aegis_send_security_headers', 1); // Priority 1
```

## Next Steps

- [User Guide](User-Guide.md) - General php-aegis usage
- [Examples](Examples.md) - More code examples
- [Rate Limiting](Rate-Limiting.md) - Add rate limiting to WordPress
