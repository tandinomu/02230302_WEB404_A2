<?php
/**
 * secure.php  —  THE RIGHT WAY
 *
 * Exactly the same login check, but using a PARAMETERIZED QUERY (prepared
 * statement). User input is sent to the database SEPARATELY from the SQL text,
 * so it can only ever be treated as a value — never as SQL code.
 *
 * Run:  php secure.php "<username>" "<password>"
 */

// 1) Same "user input" from the command line.
$username = $argv[1] ?? '';
$password = $argv[2] ?? '';

// 2) Same tiny in-memory database with the same two users.
$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
$pdo->exec("INSERT INTO users (username, password) VALUES ('admin', 's3cr3t'), ('alice', 'wonderland')");

// 3) THE FIX: the SQL contains PLACEHOLDERS (:username, :password), not the
//    input itself. The query structure is fixed and parsed BEFORE any user
//    data is attached.
$sql  = "SELECT * FROM users WHERE username = :username AND password = :password";
$stmt = $pdo->prepare($sql);

// 4) The input is bound as DATA. Even  admin' --  is looked up as a literal
//    username string; it cannot change the query.
$stmt->execute([':username' => $username, ':password' => $password]);

echo "Input username : $username\n";
echo "Input password : $password\n";
echo "SQL prepared   : $sql\n";
echo "Bound as data  : username=[$username]  password=[$password]\n";
echo "-----\n";

$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
if ($rows) {
    echo "RESULT: ACCESS GRANTED  (logged in as '{$rows[0]['username']}')\n";
} else {
    echo "RESULT: ACCESS DENIED\n";
}
