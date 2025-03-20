<?php
/**
 * Example vulnerable PHP file for testing GrepIntel
 */

// SQL Injection vulnerability
function getUserData($userId) {
    $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
    $result = mysql_query($query);
    return $result;
}

// XSS vulnerability
function displayUserInput() {
    echo $_GET['message'];
}

// Command Injection vulnerability
function runCommand($command) {
    system($command);
}

// Path Traversal vulnerability
function readUserFile($filename) {
    $content = file_get_contents($filename);
    return $content;
}

// CSRF vulnerability
function processForm() {
    // No CSRF token validation
    $username = $_POST['username'];
    $password = $_POST['password'];
    // Process the form...
}

// Insecure Authentication
function verifyPassword($username, $password) {
    $hashedPassword = md5($password);
    // Check against stored password...
}
