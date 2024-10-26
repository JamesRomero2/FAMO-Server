<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
header("Access-Control-Expose-Headers: Event-Key");

require_once("../../common/connection.php");

$http = file_get_contents("php://input");
$data = json_decode($http);
$method = $_SERVER['REQUEST_METHOD'];
date_default_timezone_set('Asia/Manila');

$heads = getallheaders();

if (!isset($heads['Event-Key']) || empty($heads['Event-Key'])) {
    exit();
} else {
    $event = $heads['Event-Key'];
}

if ($method === 'POST') {
    if ($event === 'login') {
        if (!isset($data -> username) || !isset($data -> password)) {
            http_response_code(400);
            echo json_encode(['error' => 'Username and password are required']);
            return;
        } else {
            try {
                $username = $data -> username;
                $password = $data -> password;
                $stmt = $db->prepare("SELECT id, username, first_name, last_name, role, password FROM users WHERE username = :username AND password = :password AND status = 'active' AND deleted = 0 LIMIT 1");
                // $stmt = $db->prepare("SELECT id, username, first_name, last_name, role, password FROM users WHERE username = :username AND status = 'active' AND deleted = 0 LIMIT 1");
                $stmt->bindParam(':username', $username, PDO::PARAM_STR);
                $stmt->bindParam(':password', $password, PDO::PARAM_STR);
                $stmt->execute();
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
                // if ($user && password_verify($password, $user['password'])) {
                if ($user) {
                    session_start();
                    session_regenerate_id();
                    $response = [
                        'first_name' => $user['first_name'],
                        'last_name' => $user['last_name'],
                        'role' => (int) $user['role'],
                        'session_id' => session_id(),
                    ];
                    
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['first_name'] = $user['first_name'];
                    $_SESSION['last_name'] = $user['last_name'];
                    $_SESSION['role'] = $user['role'];
    
                    $updateStmt = $db->prepare("UPDATE users SET last_logged_in = NOW() WHERE username = :username");
                    $updateStmt->bindParam(':username', $username, PDO::PARAM_STR);
                    $updateStmt->execute();
    
                    echo json_encode($response);
                } else {
                    http_response_code(401);
                    echo json_encode(['error' => 'Invalid username or password']);
                }
            } catch (PDOException $e) {
                http_response_code(500);
                echo json_encode(['error' => 'An error occurred during login: ' . $e->getMessage()]);
            }
        }
    } 
} else {
    http_response_code(500);
    exit();
}