<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\Tests\IndieWeb;

use PHPUnit\Framework\TestCase;
use PhpAegis\IndieWeb\IndieAuth;

/**
 * Tests for IndieAuth authentication security utilities.
 *
 * Validates OAuth 2.0-based decentralized authentication with PKCE support.
 */
class IndieAuthTest extends TestCase
{
    // ========================================================================
    // Profile URL (me) Validation Tests
    // ========================================================================

    public function testValidateMeAcceptsValidHttpsUrl(): void
    {
        $this->assertTrue(IndieAuth::validateMe('https://example.com'));
        $this->assertTrue(IndieAuth::validateMe('https://alice.example.com'));
        $this->assertTrue(IndieAuth::validateMe('https://example.com/'));
        $this->assertTrue(IndieAuth::validateMe('https://example.com/alice'));
    }

    public function testValidateMeRejectsHttpUrl(): void
    {
        $this->assertFalse(IndieAuth::validateMe('http://example.com'));
    }

    public function testValidateMeRejectsIpAddress(): void
    {
        $this->assertFalse(IndieAuth::validateMe('https://192.168.1.1'));
        $this->assertFalse(IndieAuth::validateMe('https://127.0.0.1'));
        $this->assertFalse(IndieAuth::validateMe('https://[::1]'));
    }

    public function testValidateMeRejectsUserinfo(): void
    {
        $this->assertFalse(IndieAuth::validateMe('https://user@example.com'));
        $this->assertFalse(IndieAuth::validateMe('https://user:pass@example.com'));
    }

    public function testValidateMeRejectsFragment(): void
    {
        $this->assertFalse(IndieAuth::validateMe('https://example.com#fragment'));
        $this->assertFalse(IndieAuth::validateMe('https://example.com/alice#section'));
    }

    public function testValidateMeAcceptsQueryString(): void
    {
        // Query strings are allowed
        $this->assertTrue(IndieAuth::validateMe('https://example.com?param=value'));
    }

    public function testValidateMeRejectsInvalidUrls(): void
    {
        $this->assertFalse(IndieAuth::validateMe('not-a-url'));
        $this->assertFalse(IndieAuth::validateMe('ftp://example.com'));
        $this->assertFalse(IndieAuth::validateMe(''));
    }

    // ========================================================================
    // Redirect URI Validation Tests
    // ========================================================================

    public function testValidateRedirectUriAcceptsSameOrigin(): void
    {
        $clientId = 'https://app.example.com';
        $redirectUri = 'https://app.example.com/callback';

        $this->assertTrue(IndieAuth::validateRedirectUri($redirectUri, $clientId));
    }

    public function testValidateRedirectUriRejectsDifferentHost(): void
    {
        $clientId = 'https://app.example.com';
        $redirectUri = 'https://evil.com/callback';

        $this->assertFalse(IndieAuth::validateRedirectUri($redirectUri, $clientId));
    }

    public function testValidateRedirectUriRejectsDifferentSubdomain(): void
    {
        $clientId = 'https://app.example.com';
        $redirectUri = 'https://other.example.com/callback';

        $this->assertFalse(IndieAuth::validateRedirectUri($redirectUri, $clientId));
    }

    public function testValidateRedirectUriRequiresHttps(): void
    {
        $clientId = 'https://example.com';
        $redirectUri = 'http://example.com/callback';

        $this->assertFalse(IndieAuth::validateRedirectUri($redirectUri, $clientId));
    }

    public function testValidateRedirectUriRejectsInvalidUrls(): void
    {
        $clientId = 'https://example.com';

        $this->assertFalse(IndieAuth::validateRedirectUri('not-a-url', $clientId));
        $this->assertFalse(IndieAuth::validateRedirectUri('', $clientId));
    }

    // ========================================================================
    // Authorization Code Validation Tests
    // ========================================================================

    public function testValidateCodeFormatAcceptsValidCode(): void
    {
        $code = str_repeat('a', 32); // 32 chars
        $this->assertTrue(IndieAuth::validateCodeFormat($code));

        $code = bin2hex(random_bytes(32)); // 64 hex chars
        $this->assertTrue(IndieAuth::validateCodeFormat($code));

        $code = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); // URL-safe base64
        $this->assertTrue(IndieAuth::validateCodeFormat($code));
    }

    public function testValidateCodeFormatRejectsTooShort(): void
    {
        $code = str_repeat('a', 31); // 31 chars
        $this->assertFalse(IndieAuth::validateCodeFormat($code));
    }

    public function testValidateCodeFormatRejectsInvalidCharacters(): void
    {
        $code = str_repeat('a', 32) . '!@#$';
        $this->assertFalse(IndieAuth::validateCodeFormat($code));

        $code = str_repeat('a', 32) . ' ';
        $this->assertFalse(IndieAuth::validateCodeFormat($code));
    }

    public function testValidateCodeFormatRejectsNullBytes(): void
    {
        $code = str_repeat('a', 32) . "\0";
        $this->assertFalse(IndieAuth::validateCodeFormat($code));
    }

    // ========================================================================
    // State Parameter Validation Tests
    // ========================================================================

    public function testValidateStateFormatAcceptsValidState(): void
    {
        $state = str_repeat('a', 16); // 16 chars minimum
        $this->assertTrue(IndieAuth::validateStateFormat($state));

        $state = bin2hex(random_bytes(16)); // 32 hex chars
        $this->assertTrue(IndieAuth::validateStateFormat($state));
    }

    public function testValidateStateFormatRejectsTooShort(): void
    {
        $state = str_repeat('a', 15); // 15 chars
        $this->assertFalse(IndieAuth::validateStateFormat($state));
    }

    public function testValidateStateFormatRejectsInvalidCharacters(): void
    {
        $state = str_repeat('a', 16) . '!@#$';
        $this->assertFalse(IndieAuth::validateStateFormat($state));
    }

    public function testValidateStateFormatRejectsNullBytes(): void
    {
        $state = str_repeat('a', 16) . "\0";
        $this->assertFalse(IndieAuth::validateStateFormat($state));
    }

    // ========================================================================
    // State Generation Tests
    // ========================================================================

    public function testGenerateStateReturnsUrlSafeString(): void
    {
        $state = IndieAuth::generateState();

        $this->assertIsString($state);
        $this->assertGreaterThanOrEqual(32, strlen($state)); // At least 32 bytes of randomness
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $state);
    }

    public function testGenerateStateReturnsUniqueValues(): void
    {
        $state1 = IndieAuth::generateState();
        $state2 = IndieAuth::generateState();

        $this->assertNotEquals($state1, $state2);
    }

    public function testGenerateStateAcceptsCustomLength(): void
    {
        $state = IndieAuth::generateState(16);
        $this->assertIsString($state);
        $this->assertTrue(IndieAuth::validateStateFormat($state));
    }

    // ========================================================================
    // PKCE Code Verifier Tests
    // ========================================================================

    public function testValidateCodeVerifierFormatAcceptsValid(): void
    {
        $verifier = str_repeat('a', 43); // Minimum 43 chars
        $this->assertTrue(IndieAuth::validateCodeVerifierFormat($verifier));

        $verifier = str_repeat('a', 128); // Maximum 128 chars
        $this->assertTrue(IndieAuth::validateCodeVerifierFormat($verifier));

        $verifier = str_repeat('a', 64); // Middle range
        $this->assertTrue(IndieAuth::validateCodeVerifierFormat($verifier));
    }

    public function testValidateCodeVerifierFormatRejectsTooShort(): void
    {
        $verifier = str_repeat('a', 42); // 42 chars
        $this->assertFalse(IndieAuth::validateCodeVerifierFormat($verifier));
    }

    public function testValidateCodeVerifierFormatRejectsTooLong(): void
    {
        $verifier = str_repeat('a', 129); // 129 chars
        $this->assertFalse(IndieAuth::validateCodeVerifierFormat($verifier));
    }

    public function testValidateCodeVerifierFormatAcceptsAllowedCharacters(): void
    {
        // Allowed: A-Z a-z 0-9 . _ ~ -
        $verifier = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~-';
        $this->assertTrue(IndieAuth::validateCodeVerifierFormat($verifier));
    }

    public function testValidateCodeVerifierFormatRejectsInvalidCharacters(): void
    {
        $verifier = str_repeat('a', 43) . '!@#$';
        $this->assertFalse(IndieAuth::validateCodeVerifierFormat($verifier));
    }

    // ========================================================================
    // PKCE Code Verifier Generation Tests
    // ========================================================================

    public function testGenerateCodeVerifierReturnsValidFormat(): void
    {
        $verifier = IndieAuth::generateCodeVerifier();

        $this->assertIsString($verifier);
        $this->assertTrue(IndieAuth::validateCodeVerifierFormat($verifier));
    }

    public function testGenerateCodeVerifierReturnsUniqueValues(): void
    {
        $verifier1 = IndieAuth::generateCodeVerifier();
        $verifier2 = IndieAuth::generateCodeVerifier();

        $this->assertNotEquals($verifier1, $verifier2);
    }

    public function testGenerateCodeVerifierAcceptsValidLength(): void
    {
        $verifier = IndieAuth::generateCodeVerifier(43);
        $this->assertTrue(IndieAuth::validateCodeVerifierFormat($verifier));

        $verifier = IndieAuth::generateCodeVerifier(128);
        $this->assertTrue(IndieAuth::validateCodeVerifierFormat($verifier));
    }

    public function testGenerateCodeVerifierRejectsInvalidLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        IndieAuth::generateCodeVerifier(42); // Too short
    }

    // ========================================================================
    // PKCE Code Challenge Tests
    // ========================================================================

    public function testGenerateCodeChallengeReturnsValidFormat(): void
    {
        $verifier = IndieAuth::generateCodeVerifier();
        $challenge = IndieAuth::generateCodeChallenge($verifier);

        $this->assertIsString($challenge);
        $this->assertSame(43, strlen($challenge)); // SHA256 base64url is 43 chars
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $challenge);
    }

    public function testGenerateCodeChallengeIsDeterministic(): void
    {
        $verifier = IndieAuth::generateCodeVerifier();
        $challenge1 = IndieAuth::generateCodeChallenge($verifier);
        $challenge2 = IndieAuth::generateCodeChallenge($verifier);

        $this->assertSame($challenge1, $challenge2);
    }

    public function testGenerateCodeChallengeDifferentVerifiersDifferentChallenges(): void
    {
        $verifier1 = IndieAuth::generateCodeVerifier();
        $verifier2 = IndieAuth::generateCodeVerifier();

        $challenge1 = IndieAuth::generateCodeChallenge($verifier1);
        $challenge2 = IndieAuth::generateCodeChallenge($verifier2);

        $this->assertNotEquals($challenge1, $challenge2);
    }

    // ========================================================================
    // PKCE Verification Tests
    // ========================================================================

    public function testVerifyCodeChallengeS256Method(): void
    {
        $verifier = IndieAuth::generateCodeVerifier();
        $challenge = IndieAuth::generateCodeChallenge($verifier);

        $this->assertTrue(IndieAuth::verifyCodeChallenge($challenge, $verifier, 'S256'));
    }

    public function testVerifyCodeChallengeS256RejectsWrongVerifier(): void
    {
        $verifier1 = IndieAuth::generateCodeVerifier();
        $verifier2 = IndieAuth::generateCodeVerifier();
        $challenge = IndieAuth::generateCodeChallenge($verifier1);

        $this->assertFalse(IndieAuth::verifyCodeChallenge($challenge, $verifier2, 'S256'));
    }

    public function testVerifyCodeChallengePlainMethod(): void
    {
        $verifier = IndieAuth::generateCodeVerifier();

        // In plain method, challenge equals verifier
        $this->assertTrue(IndieAuth::verifyCodeChallenge($verifier, $verifier, 'plain'));
    }

    public function testVerifyCodeChallengePlainRejectsWrongVerifier(): void
    {
        $verifier1 = IndieAuth::generateCodeVerifier();
        $verifier2 = IndieAuth::generateCodeVerifier();

        $this->assertFalse(IndieAuth::verifyCodeChallenge($verifier1, $verifier2, 'plain'));
    }

    public function testVerifyCodeChallengeRejectsInvalidMethod(): void
    {
        $verifier = IndieAuth::generateCodeVerifier();
        $challenge = IndieAuth::generateCodeChallenge($verifier);

        $this->assertFalse(IndieAuth::verifyCodeChallenge($challenge, $verifier, 'invalid'));
    }

    // ========================================================================
    // Code Challenge Validation Tests
    // ========================================================================

    public function testValidateCodeChallengeS256AcceptsValid(): void
    {
        $verifier = IndieAuth::generateCodeVerifier();
        $challenge = IndieAuth::generateCodeChallenge($verifier);

        $this->assertTrue(IndieAuth::validateCodeChallenge($challenge, 'S256'));
    }

    public function testValidateCodeChallengeS256RejectsWrongLength(): void
    {
        $challenge = str_repeat('a', 42); // Should be 43
        $this->assertFalse(IndieAuth::validateCodeChallenge($challenge, 'S256'));

        $challenge = str_repeat('a', 44); // Should be 43
        $this->assertFalse(IndieAuth::validateCodeChallenge($challenge, 'S256'));
    }

    public function testValidateCodeChallengePlainUsesVerifierValidation(): void
    {
        $verifier = IndieAuth::generateCodeVerifier();
        $this->assertTrue(IndieAuth::validateCodeChallenge($verifier, 'plain'));

        $tooShort = str_repeat('a', 42);
        $this->assertFalse(IndieAuth::validateCodeChallenge($tooShort, 'plain'));
    }

    public function testValidateCodeChallengeRejectsInvalidMethod(): void
    {
        $challenge = IndieAuth::generateCodeChallenge(IndieAuth::generateCodeVerifier());
        $this->assertFalse(IndieAuth::validateCodeChallenge($challenge, 'invalid'));
    }

    // ========================================================================
    // Scope Format Validation Tests
    // ========================================================================

    public function testValidateScopeFormatAcceptsValid(): void
    {
        $this->assertTrue(IndieAuth::validateScopeFormat('profile'));
        $this->assertTrue(IndieAuth::validateScopeFormat('create update delete'));
        $this->assertTrue(IndieAuth::validateScopeFormat('create_post update_profile'));
    }

    public function testValidateScopeFormatAcceptsEmpty(): void
    {
        $this->assertTrue(IndieAuth::validateScopeFormat(''));
        $this->assertTrue(IndieAuth::validateScopeFormat('   '));
    }

    public function testValidateScopeFormatRejectsUppercase(): void
    {
        $this->assertFalse(IndieAuth::validateScopeFormat('CREATE'));
        $this->assertFalse(IndieAuth::validateScopeFormat('create UPDATE'));
    }

    public function testValidateScopeFormatRejectsInvalidCharacters(): void
    {
        $this->assertFalse(IndieAuth::validateScopeFormat('create-post'));
        $this->assertFalse(IndieAuth::validateScopeFormat('create.post'));
        $this->assertFalse(IndieAuth::validateScopeFormat('create!'));
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    public function testCompleteIndieAuthFlow(): void
    {
        // Step 1: Validate profile URL
        $profileUrl = 'https://alice.example.com';
        $this->assertTrue(IndieAuth::validateMe($profileUrl));

        // Step 2: Generate state for CSRF protection
        $state = IndieAuth::generateState();
        $this->assertTrue(IndieAuth::validateStateFormat($state));

        // Step 3: Generate PKCE verifier and challenge
        $verifier = IndieAuth::generateCodeVerifier();
        $challenge = IndieAuth::generateCodeChallenge($verifier);
        $this->assertTrue(IndieAuth::validateCodeChallenge($challenge, 'S256'));

        // Step 4: Validate redirect URI
        $clientId = 'https://app.example.com';
        $redirectUri = 'https://app.example.com/callback';
        $this->assertTrue(IndieAuth::validateRedirectUri($redirectUri, $clientId));

        // Step 5: Validate authorization code format
        $code = bin2hex(random_bytes(32));
        $this->assertTrue(IndieAuth::validateCodeFormat($code));

        // Step 6: Verify PKCE challenge
        $this->assertTrue(IndieAuth::verifyCodeChallenge($challenge, $verifier, 'S256'));

        // Step 7: Validate scope
        $this->assertTrue(IndieAuth::validateScopeFormat('profile create'));
    }

    public function testSecurityChecksPreventAttacks(): void
    {
        // Prevent redirect to different domain
        $clientId = 'https://app.example.com';
        $maliciousRedirect = 'https://evil.com/steal-code';
        $this->assertFalse(IndieAuth::validateRedirectUri($maliciousRedirect, $clientId));

        // Prevent IP-based profile URLs
        $this->assertFalse(IndieAuth::validateMe('https://192.168.1.1'));

        // Prevent userinfo in profile URL
        $this->assertFalse(IndieAuth::validateMe('https://user:pass@example.com'));

        // Prevent weak state parameters
        $weakState = 'short';
        $this->assertFalse(IndieAuth::validateStateFormat($weakState));

        // Prevent weak code verifiers
        $weakVerifier = str_repeat('a', 42);
        $this->assertFalse(IndieAuth::validateCodeVerifierFormat($weakVerifier));
    }
}
