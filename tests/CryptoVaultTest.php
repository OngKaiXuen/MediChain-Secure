<?php
/**
 * CryptoVaultTest.php - Automated verification of the cryptographic subsystem.
 *
 * Maps to the three mandated runtime states (Q3 b):
 *   1. Untampered cryptographic lifecycle   -> testUntamperedLifecycle
 *   2. Tampered ciphertext -> AEAD exception -> testTamperedCiphertextThrowsAeadException
 *   3. Credential hash integrity            -> testArgon2idIntegrity
 *
 * It also proves the distinction between an *anticipated* security exception
 * (expectException, test PASSES) and an unhandled crash (would ERROR the run).
 */

use PHPUnit\Framework\TestCase;

final class CryptoVaultTest extends TestCase
{
    private CryptoVault $vault;

    protected function setUp(): void
    {
        // Simulate the decoupled .env master-key injection for the test process.
        putenv('APP_MASTER_KEY=super-secret-environment-key');
        $this->vault = new CryptoVault();
    }

    /** State 1: a valid record encrypts and decrypts back to the exact plaintext. */
    public function testUntamperedLifecycle(): void
    {
        $plaintext = 'PatientID: 9942 | DIAGNOSIS: Stage-2 Carcinoma';

        $payload   = $this->vault->encryptRecord($plaintext);
        $recovered = $this->vault->decryptRecord($payload);

        $this->assertSame($plaintext, $recovered, 'Decryption failed to yield the original plaintext.');
    }

    /** Different IV per call => identical plaintext must produce different ciphertext (no ECB leakage). */
    public function testNonDeterministicCiphertext(): void
    {
        $a = $this->vault->encryptRecord('DIAGNOSIS: Acute Type-2 Diabetes');
        $b = $this->vault->encryptRecord('DIAGNOSIS: Acute Type-2 Diabetes');

        $this->assertNotSame($a, $b, 'Identical plaintext produced identical ciphertext (IV reuse / ECB leakage).');
    }

    /** State 2: a single flipped byte must be trapped as a thrown AEAD exception, not silently accepted. */
    public function testTamperedCiphertextThrowsAeadException(): void
    {
        $payload = $this->vault->encryptRecord('PatientID: 9942');

        // Attacker flips one byte inside the ciphertext region (offset 20 is past the 12-byte IV).
        $raw       = base64_decode($payload);
        $raw[20]   = $raw[20] ^ chr(1);
        $tampered  = base64_encode($raw);

        // Assert the ANTICIPATED security exception is thrown (this is a PASS, not a crash).
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('AEAD Authentication Tag Mismatch');

        $this->vault->decryptRecord($tampered);
    }

    /** A truncated payload is rejected structurally before it ever reaches the cipher. */
    public function testTruncatedPayloadIsRejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->vault->decryptRecord(base64_encode('too-short'));
    }

    /** State 3: Argon2id accepts the correct credential and rejects a rogue one. */
    public function testArgon2idIntegrity(): void
    {
        $hash = password_hash('CorrectPassword', PASSWORD_ARGON2ID);

        $this->assertTrue(password_verify('CorrectPassword', $hash), 'Valid password was rejected.');
        $this->assertFalse(password_verify('RoguePassword', $hash), 'Rogue password was incorrectly accepted.');
    }
}
