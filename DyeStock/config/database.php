<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
$host     = 'localhost';
$dbname   = 'dyestock';
$username = 'root';
$password = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    die("Database connection failed. Import database.sql first!");
}

function isLoggedIn()       { return isset($_SESSION['user_id']); }
function getCurrentUserId() { return $_SESSION['user_id'] ?? null; }
function getRole()          { return $_SESSION['role'] ?? 'staff'; }
function isManager()        { return getRole() === 'manager'; }
function isStaff()          { return getRole() === 'staff'; }

// Any logged-in user
function requireLogin() {
    if (!isLoggedIn()) { header('Location: login.php'); exit; }
}

// Manager only — redirects staff to dashboard with error
function requireManager() {
    requireLogin();
    if (!isManager()) {
        header('Location: dashboard.php?error=access_denied');
        exit;
    }
}
?>