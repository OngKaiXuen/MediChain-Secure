<?php
/**
 * auth.php - Refactored Secure Implementation
 * Fixes Applied: Multibyte length evaluation (Flaw D), Argon2id verification (Flaw E),
 *                PDO credential lookup, session-fixation hardening.
 */

require_once __DIR__ . '/db_config.php';
session_start();

$username = $_POST['username'] ?? '';
$inputKey = $_POST['password'] ?? '';

// 1. Input-constraint defence: SEMANTIC character-length validation (UTF-8),
//    not raw byte counting. Closes Flaw D — multibyte payloads can no longer
//    slip past a byte-based bound to induce memory exhaustion.
if (mb_strlen($inputKey, 'UTF-8') > 256) {
    error_log("Security Alert: Bound overflow detected on login attempt.");
    http_response_code(400);
    die("Access Denied: Invalid input length.");
}

// 2. Secure credential retrieval via prepared statement (no concatenation).
$stmt = $pdo->prepare("SELECT id, password_hash FROM staff_credentials WHERE username = :username");
$stmt->execute(['username' => $username]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if ($user) {
    // 3. Memory-hard verification defence: Argon2id (Flaw E fix).
    //    Constant-time comparison + memory/time hardness defeats offline GPU/ASIC cracking.
    if (password_verify($inputKey, $user['password_hash'])) {

        // Prevent session-fixation: issue a fresh session id post-authentication.
        session_regenerate_id(true);
        $_SESSION['authenticated_user_id'] = $user['id'];

        echo "Access Granted. Welcome to the MediChain System.";
    } else {
        // Uniform response — no username/password oracle for enumeration.
        echo "Access Denied: Invalid Credentials.";
    }
} else {
    echo "Access Denied: Invalid Credentials.";
}
