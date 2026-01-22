<?php

/**
 * SPDX-License-Identifier: PMPL-1.0-or-later
 * SPDX-FileCopyrightText: 2024-2026 Hyperpolymath
 */

declare(strict_types=1);

namespace PhpAegis\IndieWeb;

use PhpAegis\Validator;

/**
 * IndieAuth security utilities.
 *
 * IndieAuth is a decentralized authentication protocol built on OAuth 2.0,
 * allowing users to sign in using their own domain name.
 *
 * @link https://indieauth.spec.indieweb.org/
 */
final class IndieAuth
{
    /**
     * Validate "me" URL (IndieAuth profile URL).
     *
     * Per IndieAuth spec, the "me" parameter must be:
     * - A valid HTTPS URL
     * - A domain (not an IP address)
     * - Not contain userinfo (username:password)
     * - Not contain fragment (#)
     *
     * @param string $url Profile URL to validate
     * @return bool True if valid
     */
    public static function validateMe(string $url): bool
    {
        // Must be valid HTTPS URL
        if (!Validator::httpsUrl($url)) {
            return false;
        }

        $parts = parse_url($url);
        if ($parts === false) {
            return false;
        }

        // Must have a host
        if (!isset($parts['host'])) {
            return false;
        }

        // Host must be a domain, not an IP
        if (!Validator::domain($parts['host'])) {
            return false;
        }

        // Must not contain userinfo (username:password@)
        if (isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }

        // Must not contain fragment (#)
        if (isset($parts['fragment'])) {
            return false;
        }

        return true;
    }

    /**
     * Validate redirect URI matches client ID origin.
     *
     * Per IndieAuth spec, the redirect_uri must be on the same origin
     * as the client_id (or explicitly registered).
     *
     * @param string $redirectUri Redirect URI to validate
     * @param string $clientId Client ID
     * @return bool True if same origin
     */
    public static function validateRedirectUri(
        string $redirectUri,
        string $clientId
    ): bool {
        // Both must be valid HTTPS URLs
        if (!Validator::httpsUrl($redirectUri) || !Validator::httpsUrl($clientId)) {
            return false;
        }

        $redirectParts = parse_url($redirectUri);
        $clientParts = parse_url($clientId);

        if ($redirectParts === false || $clientParts === false) {
            return false;
        }

        // Hosts must match exactly
        if (!isset($redirectParts['host']) || !isset($clientParts['host'])) {
            return false;
        }

        return $redirectParts['host'] === $clientParts['host'];
    }

    /**
     * Validate authorization code format.
     *
     * This only validates format, not authenticity.
     * You must verify the code with your authorization server.
     *
     * @param string $code Authorization code
     * @return bool True if format is valid
     */
    public static function validateCodeFormat(string $code): bool
    {
        // Codes should be at least 32 characters
        if (strlen($code) < 32) {
            return false;
        }

        // Codes should be alphanumeric + safe punctuation only
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $code)) {
            return false;
        }

        // Must not contain null bytes
        return Validator::noNullBytes($code);
    }

    /**
     * Validate state parameter format (CSRF token).
     *
     * State should be a cryptographically random string.
     *
     * @param string $state State parameter
     * @return bool True if format is valid
     */
    public static function validateStateFormat(string $state): bool
    {
        // State should be at least 16 characters
        if (strlen($state) < 16) {
            return false;
        }

        // State should be alphanumeric + safe punctuation only
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $state)) {
            return false;
        }

        // Must not contain null bytes
        return Validator::noNullBytes($state);
    }

    /**
     * Generate secure state parameter.
     *
     * Creates a cryptographically random state for CSRF protection.
     *
     * @param int $length Length in bytes (default: 32)
     * @return string URL-safe state parameter
     */
    public static function generateState(int $length = 32): string
    {
        $bytes = random_bytes($length);
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Validate code challenge for PKCE (Proof Key for Code Exchange).
     *
     * @param string $challenge Code challenge
     * @param string $method Challenge method ('S256' or 'plain')
     * @return bool True if format is valid
     */
    public static function validateCodeChallenge(string $challenge, string $method): bool
    {
        // Method must be S256 (recommended) or plain (discouraged)
        if (!in_array($method, ['S256', 'plain'], true)) {
            return false;
        }

        if ($method === 'S256') {
            // S256 challenges are base64url-encoded SHA256 hashes
            // They should be exactly 43 characters (256 bits / 6 bits per char, rounded up)
            if (strlen($challenge) !== 43) {
                return false;
            }

            // Must be base64url (alphanumeric + - and _)
            return preg_match('/^[A-Za-z0-9_-]+$/', $challenge) === 1;
        }

        // Plain challenges are just the verifier
        return self::validateCodeVerifierFormat($challenge);
    }

    /**
     * Validate code verifier format for PKCE.
     *
     * @param string $verifier Code verifier
     * @return bool True if format is valid
     */
    public static function validateCodeVerifierFormat(string $verifier): bool
    {
        // Verifier must be 43-128 characters
        $length = strlen($verifier);
        if ($length < 43 || $length > 128) {
            return false;
        }

        // Must be alphanumeric + safe punctuation
        return preg_match('/^[A-Za-z0-9._~-]+$/', $verifier) === 1;
    }

    /**
     * Generate secure code verifier for PKCE.
     *
     * @param int $length Length in bytes (default: 64, range: 43-128)
     * @return string URL-safe code verifier
     */
    public static function generateCodeVerifier(int $length = 64): string
    {
        if ($length < 43 || $length > 128) {
            throw new \InvalidArgumentException('Code verifier length must be 43-128 bytes');
        }

        $bytes = random_bytes($length);
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Generate code challenge from verifier (S256 method).
     *
     * @param string $verifier Code verifier
     * @return string Code challenge
     */
    public static function generateCodeChallenge(string $verifier): string
    {
        $hash = hash('sha256', $verifier, true);
        return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
    }

    /**
     * Verify code challenge matches verifier.
     *
     * @param string $challenge Code challenge
     * @param string $verifier Code verifier
     * @param string $method Challenge method
     * @return bool True if valid
     */
    public static function verifyCodeChallenge(
        string $challenge,
        string $verifier,
        string $method
    ): bool {
        if ($method === 'S256') {
            $expectedChallenge = self::generateCodeChallenge($verifier);
            return hash_equals($challenge, $expectedChallenge);
        }

        if ($method === 'plain') {
            return hash_equals($challenge, $verifier);
        }

        return false;
    }

    /**
     * Validate scope string format.
     *
     * Scopes should be space-separated lowercase identifiers.
     *
     * @param string $scopeString Space-separated scopes
     * @return bool True if format is valid
     */
    public static function validateScopeFormat(string $scopeString): bool
    {
        if (trim($scopeString) === '') {
            return true; // Empty scope is valid
        }

        // Scopes should be space-separated lowercase words
        return preg_match('/^[a-z_]+(\\s+[a-z_]+)*$/', $scopeString) === 1;
    }
}
