<?php
/**
 * crypto_vault.php - Refactored Secure Implementation
 * Fixes Applied: AES-256-GCM, Decoupled Keys, 12-byte IV Serialization, AEAD Exception Trapping
 *
 * Chain-of-defence vs. the legacy artifact:
 *   Flaw F (AES-128-ECB pattern leakage) -> AES-256-GCM AEAD (semantic security + integrity)
 *   Flaw G (hardcoded "MedVaultKey123!") -> key pulled from the runtime environment (.env)
 */

class CryptoVault
{
    private string $key;

    public function __construct()
    {
        // 1. Environmental Decoupling: fetch the master key strictly from process memory (.env),
        //    never from a hardcoded literal committed to version control.
        $env_key = getenv('APP_MASTER_KEY');
        if ($env_key === false || $env_key === '') {
            throw new RuntimeException("Fatal: Cryptographic environment boundary missing (APP_MASTER_KEY).");
        }

        // Derive a fixed 256-bit (32-byte) key for the engine from the environment secret.
        $this->key = hash('sha256', $env_key, true);
    }

    /**
     * Ingress pipeline: generate IV -> encrypt -> serialize [IV || ciphertext || tag] -> base64.
     */
    public function encryptRecord(string $plaintext): string
    {
        // Dynamic, single-use 12-byte (96-bit) IV — the canonical nonce size for GCM.
        $iv = random_bytes(12);

        // Authenticated encryption yields ciphertext plus a 16-byte authentication tag (by reference).
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($ciphertext === false) {
            throw new RuntimeException("Encryption failure: openssl_encrypt returned false.");
        }

        // Serialize & pack:  [ 12-byte IV ] + [ Ciphertext ] + [ 16-byte Tag ]
        $serializedPayload = $iv . $ciphertext . $tag;

        // Encode for safe database/network transport.
        return base64_encode($serializedPayload);
    }

    /**
     * Egress pipeline: base64 decode -> unpack -> verify tag -> decrypt.
     * A tampered payload is rejected as an *isolated, catchable* RuntimeException,
     * never an unhandled interpreter crash.
     */
    public function decryptRecord(string $base64Payload): string
    {
        $decoded = base64_decode($base64Payload, true);
        if ($decoded === false) {
            throw new RuntimeException("Fatal: Payload is not valid Base64.");
        }

        // Minimum structural length: 12-byte IV + 16-byte tag = 28 bytes.
        if (strlen($decoded) < 28) {
            throw new RuntimeException("Fatal: Payload structure corrupted or truncated.");
        }

        // Structural memory slicing back into the three components.
        $iv         = substr($decoded, 0, 12);
        $tag        = substr($decoded, -16);
        $ciphertext = substr($decoded, 12, -16);

        // GCM verifies the tag internally; on mismatch openssl_decrypt returns false.
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        // 2. Isolated failure-state defence: trap the AEAD verification failure explicitly.
        if ($plaintext === false) {
            error_log("CRITICAL SECURITY EVENT: Malicious payload tampering detected in vault.");
            throw new RuntimeException("AEAD Authentication Tag Mismatch: Execution halted.");
        }

        return $plaintext;
    }
}
