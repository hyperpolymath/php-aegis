# IndieWeb Security Guide

Secure IndieWeb protocols with php-aegis: Micropub, IndieAuth, and Webmention.

## Overview

php-aegis provides security validators for three IndieWeb protocols:

1. **Micropub**: Content validation and sanitization
2. **IndieAuth**: OAuth 2.0 authentication with PKCE
3. **Webmention**: SSRF (Server-Side Request Forgery) prevention

## Micropub

**W3C Recommendation** for creating posts via HTTP.

### Basic Validation
```php
use PhpAegis\IndieWeb\Micropub;

$entry = json_decode(file_get_contents('php://input'), true);

$result = Micropub::validateEntry($entry);
if (!$result['valid']) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid_request', 'errors' => $result['errors']]);
    exit;
}
```

### Content Sanitization
```php
// Remove dangerous content before storage
$sanitized = Micropub::sanitizeEntry($entry);

// Now safe to store
savePost($sanitized);
```

### Token Validation
```php
$token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$token = str_replace('Bearer ', '', $token);

if (!Micropub::validateTokenFormat($token)) {
    http_response_code(401);
    exit(json_encode(['error' => 'invalid_token']));
}

// Verify with IndieAuth server
$tokenInfo = verifyWithAuthServer($token);
```

### Scope Checking
```php
$scopes = Micropub::parseScopes($tokenInfo['scope']);

// Check if user can create posts
if (!Micropub::hasScope($scopes, 'create')) {
    http_response_code(403);
    exit(json_encode(['error' => 'insufficient_scope']));
}
```

### Complete Micropub Endpoint
```php
use PhpAegis\IndieWeb\Micropub;

// 1. Validate token
$token = getBearerToken();
if (!Micropub::validateTokenFormat($token)) {
    http_response_code(401);
    exit;
}

// 2. Verify with auth server
$tokenInfo = verifyToken($token);
$scopes = Micropub::parseScopes($tokenInfo['scope']);

// 3. Check scope
if (!Micropub::hasScope($scopes, 'create')) {
    http_response_code(403);
    exit;
}

// 4. Validate entry
$entry = json_decode(file_get_contents('php://input'), true);
$validation = Micropub::validateEntry($entry);

if (!$validation['valid']) {
    http_response_code(400);
    exit(json_encode(['error' => 'invalid_request', 'errors' => $validation['errors']]));
}

// 5. Sanitize
$sanitized = Micropub::sanitizeEntry($entry);

// 6. Create post
$postUrl = createPost($sanitized, $tokenInfo['me']);

http_response_code(201);
header('Location: ' . $postUrl);
```

## IndieAuth

**OAuth 2.0-based decentralized authentication** using domain names.

### Authorization Request (Client)
```php
use PhpAegis\IndieWeb\IndieAuth;

// 1. Validate profile URL
$profileUrl = $_POST['profile_url'];
if (!IndieAuth::validateMe($profileUrl)) {
    die('Invalid profile URL');
}

// 2. Generate state (CSRF protection)
$state = IndieAuth::generateState();
$_SESSION['indieauth_state'] = $state;

// 3. Generate PKCE verifier/challenge
$verifier = IndieAuth::generateCodeVerifier();
$challenge = IndieAuth::generateCodeChallenge($verifier);
$_SESSION['code_verifier'] = $verifier;

// 4. Build authorization URL
$authEndpoint = discoverAuthorizationEndpoint($profileUrl);
$authUrl = $authEndpoint . '?' . http_build_query([
    'response_type' => 'code',
    'client_id' => 'https://your-app.com/',
    'redirect_uri' => 'https://your-app.com/callback',
    'state' => $state,
    'code_challenge' => $challenge,
    'code_challenge_method' => 'S256',
    'scope' => 'profile create',
]);

header('Location: ' . $authUrl);
```

### Callback Handler (Client)
```php
use PhpAegis\IndieWeb\IndieAuth;

// 1. Validate state
if (!isset($_GET['state']) || !IndieAuth::validateStateFormat($_GET['state'])) {
    die('Invalid state');
}

if ($_GET['state'] !== $_SESSION['indieauth_state']) {
    die('State mismatch (CSRF)');
}

// 2. Validate code format
if (!IndieAuth::validateCodeFormat($_GET['code'])) {
    die('Invalid authorization code');
}

// 3. Exchange code for token (with PKCE verifier)
$tokenEndpoint = discoverTokenEndpoint($profileUrl);
$response = exchangeCode(
    $tokenEndpoint,
    $_GET['code'],
    'https://your-app.com/callback',
    'https://your-app.com/',
    $_SESSION['code_verifier']
);

// 4. Store access token
$_SESSION['access_token'] = $response['access_token'];
$_SESSION['me'] = $response['me'];
```

### Authorization Server
```php
use PhpAegis\IndieWeb\IndieAuth;

// Validate redirect URI matches client ID
if (!IndieAuth::validateRedirectUri($_POST['redirect_uri'], $_POST['client_id'])) {
    http_response_code(400);
    exit('redirect_uri must be same origin as client_id');
}

// Validate code challenge
if (!IndieAuth::validateCodeChallenge($_POST['code_challenge'], 'S256')) {
    http_response_code(400);
    exit('Invalid code challenge');
}

// Generate authorization code
$code = bin2hex(random_bytes(32));

// Store code with challenge for verification
storeAuthorizationCode($code, [
    'client_id' => $_POST['client_id'],
    'redirect_uri' => $_POST['redirect_uri'],
    'code_challenge' => $_POST['code_challenge'],
    'code_challenge_method' => 'S256',
]);
```

### Token Exchange (Authorization Server)
```php
use PhpAegis\IndieWeb\IndieAuth;

$codeData = getAuthorizationCode($_POST['code']);

// Verify PKCE challenge
if (!IndieAuth::verifyCodeChallenge(
    $codeData['code_challenge'],
    $_POST['code_verifier'],
    $codeData['code_challenge_method']
)) {
    http_response_code(400);
    exit('Invalid code verifier');
}

// Issue access token
$accessToken = bin2hex(random_bytes(32));
storeAccessToken($accessToken, [
    'me' => $codeData['me'],
    'client_id' => $codeData['client_id'],
    'scope' => $codeData['scope'],
]);

echo json_encode([
    'access_token' => $accessToken,
    'token_type' => 'Bearer',
    'scope' => $codeData['scope'],
    'me' => $codeData['me'],
]);
```

## Webmention

**W3C Recommendation** for website-to-website notifications.

**CRITICAL**: Webmention is vulnerable to SSRF attacks. php-aegis prevents internal IP scanning.

### Basic Validation
```php
use PhpAegis\IndieWeb\Webmention;

$source = $_POST['source'];
$target = $_POST['target'];
$yourDomain = 'example.com';

$result = Webmention::validateWebmention($source, $target, $yourDomain);

if (!$result['valid']) {
    http_response_code(400);
    echo implode(', ', $result['errors']);
    exit;
}

// Safe to fetch source URL
```

### SSRF Protection
```php
// Prevents scanning internal IPs
if (Webmention::isInternalIp('192.168.1.1')) {
    // Blocked: RFC 1918 private IP
}

if (Webmention::isInternalIp('127.0.0.1')) {
    // Blocked: Loopback
}

if (Webmention::isInternalIp('169.254.1.1')) {
    // Blocked: Link-local
}
```

### DNS Rebinding Protection
```php
// Store original IPs after validation
$originalIps = resolveHostToIps($sourceHost);

// Before making HTTP request, check for DNS rebinding
if (Webmention::detectDnsRebinding($source, $originalIps)) {
    http_response_code(400);
    exit('DNS rebinding detected (TOCTOU attack)');
}
```

### Complete Webmention Endpoint
```php
use PhpAegis\IndieWeb\Webmention;

// 1. Validate Webmention
$source = $_POST['source'];
$target = $_POST['target'];

$validation = Webmention::validateWebmention($source, $target, 'your-domain.com');
if (!$validation['valid']) {
    http_response_code(400);
    exit(implode(', ', $validation['errors']));
}

// 2. Queue for processing (async recommended)
queueWebmentionVerification($source, $target);

http_response_code(202); // Accepted
exit;

// 3. Process asynchronously
function processWebmention($source, $target) {
    // Re-resolve to check for DNS rebinding
    $parts = parse_url($source);
    $currentIps = resolveHost($parts['host']);
    $storedIps = getStoredIps($source);

    if (Webmention::detectDnsRebinding($source, $storedIps)) {
        return; // DNS rebinding attack
    }

    // Fetch source with safe settings
    $userAgent = Webmention::generateUserAgent('your-domain.com');
    $timeout = Webmention::getSafeTimeout();

    $html = fetchUrl($source, [
        'user_agent' => $userAgent,
        'timeout' => $timeout,
    ]);

    // Verify source links to target
    if (!str_contains($html, $target)) {
        return; // Not a valid mention
    }

    // Store Webmention
    saveWebmention($source, $target);
}
```

## Security Best Practices

### Micropub
1. **Always validate tokens** with authorization server
2. **Check scopes** before allowing actions
3. **Sanitize content** before storage
4. **Validate URLs** are HTTPS
5. **Detect XSS** in content

### IndieAuth
1. **Always use PKCE** (S256 method)
2. **Validate state** to prevent CSRF
3. **Require HTTPS** for redirect URIs
4. **Validate profile URLs** are domains (not IPs)
5. **Time-limit codes** (5 minutes max)

### Webmention
1. **Always validate source URLs** to prevent SSRF
2. **Check for DNS rebinding** before HTTP requests
3. **Process asynchronously** to prevent DoS
4. **Rate limit** Webmention endpoints
5. **Verify backlinks** before saving

## Testing

### Micropub Testing
```bash
curl -X POST https://your-site.com/micropub \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":["h-entry"],"properties":{"content":["Hello World"]}}'
```

### IndieAuth Testing
Use [IndieAuth.com](https://indieauth.com) to test your implementation.

### Webmention Testing
```bash
curl -X POST https://your-site.com/webmention \
  -d "source=https://alice.com/post&target=https://your-site.com/article"
```

## Resources

- [Micropub Spec](https://www.w3.org/TR/micropub/)
- [IndieAuth Spec](https://indieauth.spec.indieweb.org/)
- [Webmention Spec](https://www.w3.org/TR/webmention/)
- [IndieWeb Wiki](https://indieweb.org/)

## Next Steps

- [User Guide](User-Guide.md) - General php-aegis usage
- [Developer Guide](Developer-Guide.md) - API reference
- [Examples](Examples.md) - More code examples
