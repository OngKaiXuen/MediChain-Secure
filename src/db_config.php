<?php
/**
 * db_config.php - Secure PDO bootstrap
 *
 * Provides a single hardened $pdo instance to search.php and auth.php.
 * Credentials are decoupled into the runtime environment (.env) — never hardcoded.
 */

require_once __DIR__ . '/../vendor/autoload.php';

// Load .env once (values reach getenv()/$_ENV/$_SERVER). safeLoad() = no crash if .env is absent.
if (!getenv('DB_HOST')) {
    Dotenv\Dotenv::createUnsafeImmutable(__DIR__ . '/..')->safeLoad();
}

$host = getenv('DB_HOST') ?: '127.0.0.1';
$db   = getenv('DB_NAME') ?: 'medic_vault_db';
$user = getenv('DB_USER') ?: 'app_user';        // least-privilege account, NOT root
$pass = getenv('DB_PASS') ?: '';
$charset = 'utf8mb4';

$dsn = "mysql:host={$host};dbname={$db};charset={$charset}";

try {
    $pdo = new PDO($dsn, $user, $pass, [
        // Surface driver errors as catchable exceptions instead of silent failures.
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        // Use real server-side prepared statements (no client-side emulation / escaping).
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);
} catch (PDOException $e) {
    error_log("Database connection error: " . $e->getMessage());
    // Generic message — never echo the driver error to the client.
    http_response_code(500);
    die("Service temporarily unavailable.");
}
