<?php
/**
 * search.php - Refactored Secure Implementation
 * Fixes Applied: PDO Prepared Statements (SQLi, Flaw A), htmlspecialchars context-aware output (XSS, Flaws B & C)
 */

require_once __DIR__ . '/db_config.php'; // provides a hardened $pdo (least-privilege, not root)

$keyword = $_GET['keyword'] ?? '';

if ($keyword !== '') {
    // 1. Output-boundary defence: context-aware HTML entity encoding of the reflected input.
    //    Neutralises Flaw B/C — the browser renders the payload as inert text, not markup.
    $safe_keyword = htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8');
    echo "<div>Result found for keyword: " . $safe_keyword . "</div><br>";

    try {
        // 2. Data-plane defence: immutable prepared statement.
        //    The command plane (SQL grammar) is compiled BEFORE any user data is bound.
        $stmt = $pdo->prepare(
            "SELECT id, name, illness_history FROM patient_records WHERE name LIKE :keyword"
        );

        // The wildcard is applied to the *value*; the value is bound as scalar data,
        // structurally isolated from the SQL syntax. Injection payloads stay inert data.
        $stmt->execute(['keyword' => '%' . $keyword . '%']);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if ($results) {
            foreach ($results as $row) {
                // Secondary output encoding for database-originated data (stored-XSS defence-in-depth).
                echo "ID: "   . htmlspecialchars((string) $row['id'], ENT_QUOTES, 'UTF-8') . " - ";
                echo "Name: " . htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8') . " | ";
                echo "History: " . htmlspecialchars($row['illness_history'], ENT_QUOTES, 'UTF-8') . "<br>";
            }
        } else {
            echo "No records found.";
        }
    } catch (PDOException $e) {
        // Generic error prevents schema/SQL leakage to the client.
        error_log("Database Error: " . $e->getMessage());
        http_response_code(500);
        die("An error occurred while retrieving records.");
    }
}
