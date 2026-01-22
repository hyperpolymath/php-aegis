# Code Examples

Practical examples and recipes for common use cases.

## Table of Contents

- [Input Validation](#input-validation)
- [Output Sanitization](#output-sanitization)
- [Security Headers](#security-headers)
- [Rate Limiting](#rate-limiting)
- [WordPress](#wordpress)
- [IndieWeb](#indieweb)
- [Complete Applications](#complete-applications)

## Input Validation

### Form Validation
```php
use PhpAegis\Validator;

$errors = [];

// Email
if (!Validator::email($_POST['email'])) {
    $errors['email'] = 'Invalid email address';
}

// URL
if (!Validator::httpsUrl($_POST['website'])) {
    $errors['website'] = 'Must be an HTTPS URL';
}

// UUID
if (!Validator::uuid($_POST['item_id'])) {
    $errors['item_id'] = 'Invalid item ID';
}

if (empty($errors)) {
    // Process form
} else {
    // Show errors
}
```

### API Request Validation
```php
$data = json_decode(file_get_contents('php://input'), true);

if (!Validator::json(file_get_contents('php://input'))) {
    http_response_code(400);
    exit('Invalid JSON');
}

if (!Validator::email($data['email'] ?? '')) {
    http_response_code(400);
    exit('Invalid email');
}
```

## Output Sanitization

### HTML Template
```php
use PhpAegis\Sanitizer;

?>
<!DOCTYPE html>
<html>
<head>
    <title><?php echo Sanitizer::html($pageTitle); ?></title>
</head>
<body>
    <h1><?php echo Sanitizer::html($heading); ?></h1>

    <div class="content">
        <?php echo Sanitizer::html($userContent); ?>
    </div>

    <a href="<?php echo Sanitizer::attr($link); ?>"
       title="<?php echo Sanitizer::attr($linkTitle); ?>">
        <?php echo Sanitizer::html($linkText); ?>
    </a>

    <script>
        var config = <?php echo Sanitizer::json($config); ?>;
        var message = <?php echo Sanitizer::js($message); ?>;
    </script>
</body>
</html>
```

### JSON API Response
```php
use PhpAegis\Sanitizer;

header('Content-Type: application/json');

$response = [
    'user' => [
        'name' => $username,
        'email' => $email,
        'bio' => $bio,
    ],
    'message' => 'Success',
];

echo Sanitizer::json($response);
```

## Security Headers

### Basic Protection
```php
use PhpAegis\Headers;

// Apply all recommended headers
Headers::sendSecurityHeaders();

// Continues with your application
```

### Custom CSP
```php
Headers::csp([
    'default-src' => ["'self'"],
    'script-src' => [
        "'self'",
        'https://cdn.example.com',
        "'sha256-ABC123...'",
    ],
    'style-src' => [
        "'self'",
        "'unsafe-inline'", // Be careful with this
    ],
    'img-src' => [
        "'self'",
        'data:',
        'https:',
    ],
    'connect-src' => ["'self'", 'https://api.example.com'],
]);
```

### SPA Application
```php
// Strict CSP for single-page app
Headers::csp([
    'default-src' => ["'none'"],
    'script-src' => ["'self'"],
    'style-src' => ["'self'"],
    'img-src' => ["'self'", 'data:'],
    'font-src' => ["'self'"],
    'connect-src' => ["'self'"],
    'base-uri' => ["'self'"],
    'form-action' => ["'self'"],
]);

// HSTS
Headers::hsts(31536000, true, true);
```

## Rate Limiting

### API Endpoint
```php
use PhpAegis\RateLimit\RateLimiter;
use PhpAegis\RateLimit\FileStore;

$store = new FileStore(__DIR__ . '/var/ratelimit');
$limiter = RateLimiter::perHour(1000, $store, 100);

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? 'anonymous';

if (!$limiter->attempt($apiKey)) {
    http_response_code(429);
    header('X-RateLimit-Remaining: 0');
    header('Retry-After: ' . $limiter->resetAt($apiKey));
    exit(json_encode(['error' => 'rate_limit_exceeded']));
}

// Add rate limit headers
header('X-RateLimit-Remaining: ' . (int)$limiter->remaining($apiKey));

// Process request
```

### Login Protection
```php
$loginLimiter = RateLimiter::perMinute(5, $store);
$identifier = $_POST['username'] . ':' . $_SERVER['REMOTE_ADDR'];

if (!$loginLimiter->attempt($identifier)) {
    $wait = $loginLimiter->resetAt($identifier);
    exit("Too many login attempts. Try again in $wait seconds.");
}

// Attempt login
$success = attemptLogin($_POST['username'], $_POST['password']);

if ($success) {
    // Reset limit on successful login
    $loginLimiter->reset($identifier);
}
```

### Multi-Tier API
```php
function getRateLimiter($user, $store) {
    return match($user['tier']) {
        'free' => RateLimiter::perHour(100, $store, 10),
        'basic' => RateLimiter::perHour(1000, $store, 50),
        'premium' => RateLimiter::perHour(10000, $store, 100),
        'enterprise' => RateLimiter::perHour(100000, $store, 1000),
    };
}

$limiter = getRateLimiter($currentUser, $store);

if (!$limiter->attempt($currentUser['id'])) {
    http_response_code(429);
    exit(json_encode([
        'error' => 'rate_limit_exceeded',
        'tier' => $currentUser['tier'],
        'upgrade_url' => '/pricing',
    ]));
}
```

## WordPress

### Custom Post Type
```php
add_action('init', function() {
    register_post_type('product', [
        'label' => 'Products',
        'public' => true,
    ]);
});

add_action('add_meta_boxes', function() {
    add_meta_box('product_meta', 'Product Details', function($post) {
        $price = get_post_meta($post->ID, 'price', true);
        $sku = get_post_meta($post->ID, 'sku', true);
        ?>
        <label>Price:</label>
        <input type="text" name="price" value="<?php echo aegis_attr($price); ?>">

        <label>SKU:</label>
        <input type="text" name="sku" value="<?php echo aegis_attr($sku); ?>">
        <?php
    }, 'product');
});

add_action('save_post_product', function($post_id) {
    if (isset($_POST['price'])) {
        // Validate
        if (!is_numeric($_POST['price'])) {
            wp_die('Invalid price');
        }
        update_post_meta($post_id, 'price', $_POST['price']);
    }

    if (isset($_POST['sku'])) {
        // Validate UUID format
        if (!aegis_validate_uuid($_POST['sku'])) {
            wp_die('Invalid SKU (must be UUID)');
        }
        update_post_meta($post_id, 'sku', $_POST['sku']);
    }
});
```

### REST API Endpoint
```php
add_action('rest_api_init', function() {
    register_rest_route('custom/v1', '/items', [
        'methods' => 'POST',
        'callback' => function($request) {
            // Validate email
            $email = $request->get_param('email');
            if (!aegis_validate_email($email)) {
                return new WP_Error('invalid_email', 'Invalid email', ['status' => 400]);
            }

            // Validate URL
            $website = $request->get_param('website');
            if (!aegis_validate_url($website, true)) {
                return new WP_Error('invalid_url', 'Must be HTTPS', ['status' => 400]);
            }

            // Create item
            $item_id = createItem(['email' => $email, 'website' => $website]);

            return [
                'success' => true,
                'item_id' => $item_id,
            ];
        },
        'permission_callback' => function() {
            return current_user_can('edit_posts');
        },
    ]);
});
```

## IndieWeb

### Micropub Endpoint
```php
use PhpAegis\IndieWeb\Micropub;

header('Link: <https://your-site.com/micropub>; rel="micropub"');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate token
    $token = getBearerToken();
    if (!Micropub::validateTokenFormat($token)) {
        http_response_code(401);
        exit;
    }

    $tokenInfo = verifyToken($token);
    $scopes = Micropub::parseScopes($tokenInfo['scope']);

    if (!Micropub::hasScope($scopes, 'create')) {
        http_response_code(403);
        exit;
    }

    // Validate entry
    $entry = json_decode(file_get_contents('php://input'), true);
    $validation = Micropub::validateEntry($entry);

    if (!$validation['valid']) {
        http_response_code(400);
        exit(json_encode(['error' => 'invalid_request']));
    }

    // Sanitize and save
    $sanitized = Micropub::sanitizeEntry($entry);
    $postUrl = createPost($sanitized);

    http_response_code(201);
    header('Location: ' . $postUrl);
}
```

### Webmention Receiver
```php
use PhpAegis\IndieWeb\Webmention;

header('Link: <https://your-site.com/webmention>; rel="webmention"');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $source = $_POST['source'];
    $target = $_POST['target'];

    $result = Webmention::validateWebmention($source, $target, 'your-site.com');

    if (!$result['valid']) {
        http_response_code(400);
        exit(implode(', ', $result['errors']));
    }

    // Queue for async processing
    queueWebmention($source, $target);

    http_response_code(202); // Accepted
}
```

## Complete Applications

### Secure Contact Form
```php
<?php
use PhpAegis\Validator;
use PhpAegis\Sanitizer;
use PhpAegis\Headers;
use PhpAegis\RateLimit\RateLimiter;
use PhpAegis\RateLimit\FileStore;

// Security headers
Headers::sendSecurityHeaders();

// Rate limiting
$store = new FileStore('/tmp/ratelimit');
$limiter = RateLimiter::perMinute(5, $store);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$limiter->attempt($_SERVER['REMOTE_ADDR'])) {
        http_response_code(429);
        exit('Too many submissions. Please wait.');
    }

    $errors = [];

    // Validate
    if (!Validator::email($_POST['email'])) {
        $errors[] = 'Invalid email';
    }

    if (strlen($_POST['message']) < 10) {
        $errors[] = 'Message too short';
    }

    if (empty($errors)) {
        // Send email (simplified)
        mail(
            'admin@example.com',
            'Contact Form',
            Sanitizer::html($_POST['message']),
            'From: ' . Sanitizer::html($_POST['email'])
        );

        echo 'Thank you! We will respond soon.';
    } else {
        foreach ($errors as $error) {
            echo Sanitizer::html($error) . '<br>';
        }
    }
}
?>

<form method="post">
    <label>Email:</label>
    <input type="email" name="email" required>

    <label>Message:</label>
    <textarea name="message" required></textarea>

    <button type="submit">Send</button>
</form>
```

### RESTful API
```php
<?php
use PhpAegis\Validator;
use PhpAegis\Sanitizer;
use PhpAegis\Headers;
use PhpAegis\RateLimit\RateLimiter;
use PhpAegis\RateLimit\FileStore;

// Security headers
Headers::sendSecurityHeaders();
header('Content-Type: application/json');

// Rate limiting
$store = new FileStore('/var/ratelimit');
$limiter = RateLimiter::perHour(1000, $store, 100);

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';

if (!$limiter->attempt($apiKey)) {
    http_response_code(429);
    exit(Sanitizer::json(['error' => 'rate_limit_exceeded']));
}

// Routing
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET' && $path === '/api/items') {
    $items = getItems();
    echo Sanitizer::json($items);
}

elseif ($method === 'POST' && $path === '/api/items') {
    $data = json_decode(file_get_contents('php://input'), true);

    if (!Validator::email($data['email'] ?? '')) {
        http_response_code(400);
        exit(Sanitizer::json(['error' => 'invalid_email']));
    }

    $id = createItem($data);
    http_response_code(201);
    echo Sanitizer::json(['id' => $id]);
}

else {
    http_response_code(404);
    echo Sanitizer::json(['error' => 'not_found']);
}
```

## Best Practices Summary

1. **Always validate input first**
2. **Use context-appropriate sanitization**
3. **Apply security headers on every request**
4. **Rate limit all public endpoints**
5. **Use HTTPS-only validation** for security-critical URLs
6. **Sanitize before output**, not before storage
7. **Use RDF/Turtle escaping** for semantic web data
8. **Test with real attack vectors**

## Next Steps

- [User Guide](User-Guide.md) - Comprehensive usage guide
- [Developer Guide](Developer-Guide.md) - Complete API reference
- [WordPress Integration](WordPress-Integration.md) - WordPress-specific guide
