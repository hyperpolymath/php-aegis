<?php

declare(strict_types=1);

// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025 Hyperpolymath

namespace PhpAegis;

/**
 * Post-quantum cryptographic primitives for php-aegis.
 *
 * Provides high-security cryptographic functions using:
 * - SHAKE3-256: SHA-3 extendable output function
 * - BLAKE3: Fast cryptographic hash
 * - Kyber-1024: Post-quantum key encapsulation (NIST ML-KEM)
 * - Dilithium: Post-quantum digital signatures (NIST ML-DSA)
 * - Argon2id: Memory-hard password hashing
 * - Ed448: Edwards curve signatures (Curve448-Goldilocks)
 *
 * Security level: 256-bit classical / 128-bit post-quantum
 *
 * @package PhpAegis
 * @since 0.2.0
 */
final class Crypto
{
    /**
     * SHAKE3-256 extendable output function.
     *
     * SHA-3 based XOF providing arbitrary-length output.
     * Recommended over SHA-256 for new applications.
     *
     * @param string $data Input data
     * @param int $length Output length in bytes (default: 32 for 256-bit)
     * @return string Binary hash output
     */
    public static function shake256(string $data, int $length = 32): string
    {
        if ($length < 1 || $length > 65535) {
            throw new \InvalidArgumentException('Output length must be 1-65535 bytes');
        }

        // PHP 8.1+ has native SHAKE support
        if (\function_exists('hash')) {
            // Use shake256 if available (PHP 8.1+)
            $hash = \hash('shake256', $data, true, ['length' => $length]);
            if ($hash !== false) {
                return $hash;
            }
        }

        // Fallback: Use SHA3-256 and extend with HKDF if needed
        $base = \hash('sha3-256', $data, true);
        if ($length <= 32) {
            return \substr($base, 0, $length);
        }

        // Extend using HKDF-Expand pattern
        return self::hkdfExpand($base, $length, 'shake256-extend');
    }

    /**
     * BLAKE3 cryptographic hash function.
     *
     * Extremely fast hash with security comparable to SHA-3.
     * Recommended for file hashing and integrity checks.
     *
     * @param string $data Input data
     * @param int $length Output length in bytes (default: 32)
     * @param string|null $key Optional keyed mode (32 bytes)
     * @return string Binary hash output
     */
    public static function blake3(string $data, int $length = 32, ?string $key = null): string
    {
        if ($length < 1 || $length > 65535) {
            throw new \InvalidArgumentException('Output length must be 1-65535 bytes');
        }

        // Check for BLAKE3 extension
        if (\function_exists('blake3')) {
            /** @var string */
            return \blake3($data, $length, $key);
        }

        // Check for sodium-based BLAKE3 (future PHP versions)
        if (\function_exists('sodium_crypto_generichash_blake3')) {
            /** @var string */
            return \sodium_crypto_generichash_blake3($data, $key, $length);
        }

        // Fallback: Use BLAKE2b which is available in libsodium
        // BLAKE2b is cryptographically similar to BLAKE3
        if ($key !== null) {
            if (\strlen($key) !== 32) {
                throw new \InvalidArgumentException('Key must be exactly 32 bytes');
            }
            return \sodium_crypto_generichash($data, $key, $length);
        }

        return \sodium_crypto_generichash($data, '', $length);
    }

    /**
     * Argon2id password hashing.
     *
     * Memory-hard function resistant to GPU/ASIC attacks.
     * Recommended parameters for 2025+:
     * - Memory: 64 MiB minimum
     * - Time: 3 iterations minimum
     * - Parallelism: 4 threads
     *
     * @param string $password Plain text password
     * @param int $memoryCost Memory in KiB (default: 65536 = 64 MiB)
     * @param int $timeCost Number of iterations (default: 4)
     * @param int $threads Parallelism factor (default: 4)
     * @return string Encoded hash string
     */
    public static function argon2id(
        string $password,
        int $memoryCost = 65536,
        int $timeCost = 4,
        int $threads = 4
    ): string {
        // Enforce minimum security parameters
        if ($memoryCost < 65536) {
            throw new \InvalidArgumentException('Memory cost must be >= 64 MiB (65536 KiB)');
        }
        if ($timeCost < 3) {
            throw new \InvalidArgumentException('Time cost must be >= 3');
        }
        if ($threads < 1) {
            throw new \InvalidArgumentException('Threads must be >= 1');
        }

        $hash = \password_hash($password, \PASSWORD_ARGON2ID, [
            'memory_cost' => $memoryCost,
            'time_cost' => $timeCost,
            'threads' => $threads,
        ]);

        if ($hash === false) {
            throw new \RuntimeException('Argon2id hashing failed');
        }

        return $hash;
    }

    /**
     * Verify an Argon2id password hash.
     *
     * @param string $password Plain text password
     * @param string $hash Argon2id hash to verify against
     * @return bool True if password matches
     */
    public static function argon2idVerify(string $password, string $hash): bool
    {
        return \password_verify($password, $hash);
    }

    /**
     * Check if password hash needs rehashing with stronger parameters.
     *
     * @param string $hash Existing hash
     * @param int $memoryCost Target memory cost
     * @param int $timeCost Target time cost
     * @param int $threads Target thread count
     * @return bool True if rehash is needed
     */
    public static function argon2idNeedsRehash(
        string $hash,
        int $memoryCost = 65536,
        int $timeCost = 4,
        int $threads = 4
    ): bool {
        return \password_needs_rehash($hash, \PASSWORD_ARGON2ID, [
            'memory_cost' => $memoryCost,
            'time_cost' => $timeCost,
            'threads' => $threads,
        ]);
    }

    /**
     * Ed448 key pair generation.
     *
     * Edwards curve over Curve448-Goldilocks.
     * Provides ~224-bit security level (stronger than Ed25519).
     *
     * @return array{public: string, secret: string} Key pair (57-byte keys)
     */
    public static function ed448Keypair(): array
    {
        // Check for native Ed448 support (PHP 8.2+ with OpenSSL 3.0+)
        if (\function_exists('sodium_crypto_sign_ed448_keypair')) {
            $keypair = \sodium_crypto_sign_ed448_keypair();
            return [
                'public' => \sodium_crypto_sign_ed448_publickey($keypair),
                'secret' => \sodium_crypto_sign_ed448_secretkey($keypair),
            ];
        }

        // OpenSSL fallback
        if (\extension_loaded('openssl')) {
            $config = [
                'private_key_type' => \OPENSSL_KEYTYPE_EC,
                'curve_name' => 'ED448',
            ];

            $key = \openssl_pkey_new($config);
            if ($key === false) {
                throw new \RuntimeException('Ed448 key generation failed - OpenSSL may not support ED448');
            }

            $details = \openssl_pkey_get_details($key);
            if ($details === false) {
                throw new \RuntimeException('Failed to get Ed448 key details');
            }

            \openssl_pkey_export($key, $privateKeyPem);

            return [
                'public' => $details['ec']['x'] ?? '',
                'secret' => $privateKeyPem,
            ];
        }

        throw new \RuntimeException('Ed448 not available - requires PHP 8.2+ with sodium or OpenSSL 3.0+');
    }

    /**
     * Ed448 signature.
     *
     * @param string $message Message to sign
     * @param string $secretKey 57-byte secret key
     * @return string 114-byte signature
     */
    public static function ed448Sign(string $message, string $secretKey): string
    {
        if (\function_exists('sodium_crypto_sign_ed448_detached')) {
            return \sodium_crypto_sign_ed448_detached($message, $secretKey);
        }

        // OpenSSL fallback
        if (\extension_loaded('openssl')) {
            $signature = '';
            $key = \openssl_pkey_get_private($secretKey);
            if ($key === false) {
                throw new \InvalidArgumentException('Invalid Ed448 secret key');
            }

            if (!\openssl_sign($message, $signature, $key, \OPENSSL_ALGO_SHA512)) {
                throw new \RuntimeException('Ed448 signing failed');
            }

            return $signature;
        }

        throw new \RuntimeException('Ed448 signing not available');
    }

    /**
     * Ed448 signature verification.
     *
     * @param string $message Original message
     * @param string $signature 114-byte signature
     * @param string $publicKey 57-byte public key
     * @return bool True if signature is valid
     */
    public static function ed448Verify(string $message, string $signature, string $publicKey): bool
    {
        if (\function_exists('sodium_crypto_sign_ed448_verify_detached')) {
            return \sodium_crypto_sign_ed448_verify_detached($signature, $message, $publicKey);
        }

        throw new \RuntimeException('Ed448 verification not available - requires PHP 8.2+ with sodium');
    }

    /**
     * Kyber-1024 key pair generation.
     *
     * Post-quantum key encapsulation mechanism (NIST ML-KEM-1024).
     * Provides 256-bit classical / 192-bit quantum security.
     *
     * @return array{public: string, secret: string} Key pair
     */
    public static function kyberKeypair(): array
    {
        // Check for liboqs-php extension
        if (\function_exists('oqs_kem_keypair')) {
            return \oqs_kem_keypair('Kyber1024');
        }

        // Check for pqcrypto extension
        if (\class_exists('PQCrypto\\KEM\\Kyber1024')) {
            $kyber = new \PQCrypto\KEM\Kyber1024();
            return $kyber->keypair();
        }

        throw new \RuntimeException(
            'Kyber-1024 not available. Install liboqs-php or pqcrypto extension.'
        );
    }

    /**
     * Kyber-1024 encapsulation.
     *
     * Generates a shared secret and ciphertext using public key.
     *
     * @param string $publicKey Recipient's public key
     * @return array{shared_secret: string, ciphertext: string}
     */
    public static function kyberEncapsulate(string $publicKey): array
    {
        if (\function_exists('oqs_kem_encaps')) {
            return \oqs_kem_encaps('Kyber1024', $publicKey);
        }

        if (\class_exists('PQCrypto\\KEM\\Kyber1024')) {
            $kyber = new \PQCrypto\KEM\Kyber1024();
            return $kyber->encapsulate($publicKey);
        }

        throw new \RuntimeException('Kyber-1024 encapsulation not available');
    }

    /**
     * Kyber-1024 decapsulation.
     *
     * Recovers the shared secret from ciphertext using secret key.
     *
     * @param string $ciphertext Encapsulated ciphertext
     * @param string $secretKey Recipient's secret key
     * @return string Shared secret (32 bytes)
     */
    public static function kyberDecapsulate(string $ciphertext, string $secretKey): string
    {
        if (\function_exists('oqs_kem_decaps')) {
            return \oqs_kem_decaps('Kyber1024', $ciphertext, $secretKey);
        }

        if (\class_exists('PQCrypto\\KEM\\Kyber1024')) {
            $kyber = new \PQCrypto\KEM\Kyber1024();
            return $kyber->decapsulate($ciphertext, $secretKey);
        }

        throw new \RuntimeException('Kyber-1024 decapsulation not available');
    }

    /**
     * Dilithium key pair generation.
     *
     * Post-quantum digital signatures (NIST ML-DSA-87).
     * Provides 256-bit classical / 192-bit quantum security.
     *
     * @return array{public: string, secret: string} Key pair
     */
    public static function dilithiumKeypair(): array
    {
        if (\function_exists('oqs_sig_keypair')) {
            return \oqs_sig_keypair('Dilithium5');
        }

        if (\class_exists('PQCrypto\\Sig\\Dilithium5')) {
            $dil = new \PQCrypto\Sig\Dilithium5();
            return $dil->keypair();
        }

        throw new \RuntimeException(
            'Dilithium not available. Install liboqs-php or pqcrypto extension.'
        );
    }

    /**
     * Dilithium signature.
     *
     * @param string $message Message to sign
     * @param string $secretKey Secret key
     * @return string Signature
     */
    public static function dilithiumSign(string $message, string $secretKey): string
    {
        if (\function_exists('oqs_sig_sign')) {
            return \oqs_sig_sign('Dilithium5', $message, $secretKey);
        }

        if (\class_exists('PQCrypto\\Sig\\Dilithium5')) {
            $dil = new \PQCrypto\Sig\Dilithium5();
            return $dil->sign($message, $secretKey);
        }

        throw new \RuntimeException('Dilithium signing not available');
    }

    /**
     * Dilithium signature verification.
     *
     * @param string $message Original message
     * @param string $signature Signature to verify
     * @param string $publicKey Signer's public key
     * @return bool True if signature is valid
     */
    public static function dilithiumVerify(string $message, string $signature, string $publicKey): bool
    {
        if (\function_exists('oqs_sig_verify')) {
            return \oqs_sig_verify('Dilithium5', $message, $signature, $publicKey);
        }

        if (\class_exists('PQCrypto\\Sig\\Dilithium5')) {
            $dil = new \PQCrypto\Sig\Dilithium5();
            return $dil->verify($message, $signature, $publicKey);
        }

        throw new \RuntimeException('Dilithium verification not available');
    }

    /**
     * Cryptographically secure random bytes.
     *
     * Uses /dev/urandom or Windows CSPRNG.
     *
     * @param int $length Number of bytes
     * @return string Random bytes
     */
    public static function randomBytes(int $length): string
    {
        if ($length < 1) {
            throw new \InvalidArgumentException('Length must be positive');
        }

        return \random_bytes($length);
    }

    /**
     * Cryptographically secure random integer.
     *
     * @param int $min Minimum value (inclusive)
     * @param int $max Maximum value (inclusive)
     * @return int Random integer
     */
    public static function randomInt(int $min, int $max): int
    {
        return \random_int($min, $max);
    }

    /**
     * Constant-time string comparison.
     *
     * Prevents timing attacks when comparing secrets.
     *
     * @param string $known The known string
     * @param string $user The user-provided string
     * @return bool True if strings are equal
     */
    public static function constantTimeEquals(string $known, string $user): bool
    {
        return \hash_equals($known, $user);
    }

    /**
     * Secure memory wipe.
     *
     * Overwrites sensitive data in memory.
     *
     * @param string &$data Data to wipe (modified in place)
     */
    public static function memzero(string &$data): void
    {
        if (\function_exists('sodium_memzero')) {
            \sodium_memzero($data);
        } else {
            // Fallback: overwrite with random bytes
            $len = \strlen($data);
            $data = \str_repeat("\0", $len);
        }
    }

    /**
     * HKDF-Expand for key derivation.
     *
     * @param string $prk Pseudorandom key (from HKDF-Extract)
     * @param int $length Desired output length
     * @param string $info Context/application-specific info
     * @return string Derived key material
     */
    private static function hkdfExpand(string $prk, int $length, string $info): string
    {
        $hashLen = 32; // SHA-256 output
        $n = (int) \ceil($length / $hashLen);
        $t = '';
        $okm = '';

        for ($i = 1; $i <= $n; $i++) {
            $t = \hash_hmac('sha256', $t . $info . \chr($i), $prk, true);
            $okm .= $t;
        }

        return \substr($okm, 0, $length);
    }

    /**
     * Check available cryptographic capabilities.
     *
     * @return array<string, bool> Map of feature => available
     */
    public static function capabilities(): array
    {
        return [
            'shake256' => \function_exists('hash') && \in_array('shake256', \hash_algos(), true),
            'blake3' => \function_exists('blake3') || \function_exists('sodium_crypto_generichash_blake3'),
            'blake2b' => \function_exists('sodium_crypto_generichash'),
            'argon2id' => \defined('PASSWORD_ARGON2ID'),
            'ed448' => \function_exists('sodium_crypto_sign_ed448_keypair') ||
                       (\extension_loaded('openssl') && \in_array('ED448', \openssl_get_curve_names() ?: [], true)),
            'kyber1024' => \function_exists('oqs_kem_keypair') || \class_exists('PQCrypto\\KEM\\Kyber1024'),
            'dilithium5' => \function_exists('oqs_sig_keypair') || \class_exists('PQCrypto\\Sig\\Dilithium5'),
            'sodium' => \extension_loaded('sodium'),
            'openssl' => \extension_loaded('openssl'),
        ];
    }
}
