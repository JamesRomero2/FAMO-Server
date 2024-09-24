<?php

$dbCredentials = array(
    "host2" => "127.0.0.1", //stg
    "msis" => array(
        "username" => "root",
        "password" => "",
        "database" => "msis"
    )
);
try {
    $db = new PDO("mysql:host=" . $dbCredentials["host2"] . ";dbname=" . $dbCredentials["msis"]["database"] . ";charset=utf8", $dbCredentials["msis"]["username"], $dbCredentials["msis"]["password"]);
} catch(PDOException $e) {
    echo "Connection failed: " . $e->getMessage();
}
