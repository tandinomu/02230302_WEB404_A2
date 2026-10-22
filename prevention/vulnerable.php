<?php
/**
 * vulnerable.php  —  THE WRONG WAY (for teaching only)
 *
 * Simulates a login check that builds its SQL by gluing user input straight
 * into the query string. This is the root cause of SQL injection.
 *
 * Run:  php vulnerable.php "<username>" "<password>"
 */

// 1) Read the "user input" from the command line (stands in for a web form).
$username = $argv[1] ?? '';
$password = $argv[2] ?? '';

// 2) Set up a tiny in-memory database with two users (fresh every run).
$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
$pdo->exec("INSERT INTO users (username, password) VALUES ('admin', 's3cr3t'), ('alice', 'wonderland')");

// 3) THE BUG: the input is concatenated directly into the SQL text, so input
//    like  admin' --  changes the STRUCTURE of the query, not just its data.
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

echo "Input username : $username\n";
echo "Input password : $password\n";
echo "SQL executed   : $sql\n";
echo "-----\n";

// 4) Run it and decide "login" success by whether any row came back.
$rows = $pdo->query($sql)->fetchAll(PDO::FETCH_ASSOC);
if ($rows) {
    echo "RESULT: ACCESS GRANTED  (logged in as '{$rows[0]['username']}')\n";
} else {
    echo "RESULT: ACCESS DENIED\n";
}
