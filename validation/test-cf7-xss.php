#!/usr/bin/env php
<?php
/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * Contact Form 7 XSS prevention test
 *
 * Tests that php-aegis sanitization prevents XSS in Contact Form 7 submissions
 */

declare(strict_types=1);

// Get WordPress path from CLI argument
$wpPath = $argv[1] ?? '/tmp/php-aegis-wp-test';

// Load WordPress
if (!file_exists("$wpPath/wp-load.php")) {
    echo "ERROR: WordPress not found at $wpPath\n";
    exit(1);
}

require_once "$wpPath/wp-load.php";

// Check if Contact Form 7 is active
if (!defined('WPCF7_VERSION')) {
    echo "ERROR: Contact Form 7 is not active\n";
    exit(1);
}

// Load php-aegis adapter
require_once "$wpPath/wp-content/mu-plugins/Adapter.php";

// XSS payloads to test
$xssPayloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    'javascript:alert("XSS")',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    '<iframe src="javascript:alert(\'XSS\')">',
    '<body onload=alert("XSS")>',
    '<input onfocus=alert("XSS") autofocus>',
];

echo "=== Contact Form 7 XSS Prevention Test ===\n\n";

$passed = 0;
$failed = 0;

foreach ($xssPayloads as $payload) {
    // Simulate CF7 form submission data
    $submittedData = [
        'your-name' => $payload,
        'your-email' => 'test@example.com',
        'your-message' => $payload,
    ];

    // Process with php-aegis sanitization
    $sanitizedData = [];
    foreach ($submittedData as $key => $value) {
        if ($key === 'your-email') {
            $sanitizedData[$key] = aegis_email($value);
        } else {
            $sanitizedData[$key] = aegis_html($value);
        }
    }

    // Check if XSS payload was neutralized
    $safe = true;
    $dangerousPatterns = [
        '<script',
        'javascript:',
        'onerror=',
        'onload=',
        'onfocus=',
        '<iframe',
        '<body',
        '<svg',
    ];

    foreach ($dangerousPatterns as $pattern) {
        if (stripos($sanitizedData['your-name'], $pattern) !== false ||
            stripos($sanitizedData['your-message'], $pattern) !== false) {
            $safe = false;
            break;
        }
    }

    if ($safe) {
        echo "✓ PASS: XSS payload neutralized\n";
        echo "  Original: " . substr($payload, 0, 50) . "\n";
        echo "  Sanitized: " . substr($sanitizedData['your-name'], 0, 50) . "\n\n";
        $passed++;
    } else {
        echo "✗ FAIL: XSS payload not neutralized\n";
        echo "  Original: $payload\n";
        echo "  Sanitized: {$sanitizedData['your-name']}\n\n";
        $failed++;
    }
}

echo "=== Test Summary ===\n";
echo "Total: " . ($passed + $failed) . "\n";
echo "Passed: $passed\n";
echo "Failed: $failed\n";

if ($failed === 0) {
    echo "\n✓ All XSS prevention tests passed!\n";
    exit(0);
} else {
    echo "\n✗ Some XSS payloads were not properly sanitized.\n";
    exit(1);
}
