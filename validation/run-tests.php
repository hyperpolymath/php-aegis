#!/usr/bin/env php
<?php
/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * CLI runner for php-aegis real-world validation tests
 */

declare(strict_types=1);

// Determine paths
$phpAegisPath = dirname(__DIR__);
$wordpressPath = $argv[1] ?? '/tmp/php-aegis-wp-test';

// Load php-aegis
require_once $phpAegisPath . '/src/Validator.php';
require_once $phpAegisPath . '/src/Sanitizer.php';
require_once $phpAegisPath . '/src/Headers.php';
require_once $phpAegisPath . '/src/WordPress/Adapter.php';

// Load test class
require_once __DIR__ . '/RealWorldTest.php';

use PhpAegis\Validation\RealWorldTest;

// Parse CLI arguments
$verbose = in_array('--verbose', $argv) || in_array('-v', $argv);
$jsonOutput = in_array('--json', $argv);

// Banner
if (!$jsonOutput && $verbose) {
    echo "╔════════════════════════════════════════════════════════════════╗\n";
    echo "║       php-aegis Real-World Validation Test Suite              ║\n";
    echo "║       Version 0.2.0                                            ║\n";
    echo "╚════════════════════════════════════════════════════════════════╝\n";
    echo "\n";
    echo "WordPress Path: $wordpressPath\n";
    echo "php-aegis Path: $phpAegisPath\n";
    echo "\n";
}

// Run tests
$test = new RealWorldTest($wordpressPath, $verbose);

try {
    $results = $test->runAll();

    // Output results
    if ($jsonOutput) {
        echo $test->getResultsJson() . "\n";
    } else {
        echo "\n";
        echo "╔════════════════════════════════════════════════════════════════╗\n";
        echo "║                    Test Results Summary                        ║\n";
        echo "╚════════════════════════════════════════════════════════════════╝\n";
        echo "\n";

        // Calculate totals
        $totalPassed = 0;
        $totalFailed = 0;
        $totalTests = 0;

        foreach ($results as $category => $data) {
            if (isset($data['passed']) && isset($data['failed'])) {
                $totalPassed += $data['passed'];
                $totalFailed += $data['failed'];
                $totalTests += $data['total'];
            } elseif (is_array($data)) {
                foreach ($data as $test => $result) {
                    if (isset($result['passed'])) {
                        $totalPassed += $result['passed'];
                        $totalFailed += $result['failed'];
                        $totalTests += $result['total'];
                    }
                }
            }
        }

        echo "Total Tests: $totalTests\n";
        echo "Passed: $totalPassed\n";
        echo "Failed: $totalFailed\n";

        if ($totalTests > 0) {
            $passRate = round(($totalPassed / $totalTests) * 100, 2);
            echo "Pass Rate: $passRate%\n";
        }

        echo "\n";

        if ($totalFailed === 0) {
            echo "✓ All tests passed!\n";
            exit(0);
        } else {
            echo "✗ Some tests failed. Review the results for details.\n";
            exit(1);
        }
    }
} catch (Exception $e) {
    if ($jsonOutput) {
        echo json_encode([
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString(),
        ], JSON_PRETTY_PRINT) . "\n";
    } else {
        echo "ERROR: " . $e->getMessage() . "\n";
        echo $e->getTraceAsString() . "\n";
    }
    exit(1);
}
