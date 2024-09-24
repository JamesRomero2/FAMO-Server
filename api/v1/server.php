<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
header("Access-Control-Expose-Headers: Event-Key");

require_once("../../common/connection.php");
require_once("./controller.php");

$http = file_get_contents("php://input");
$data = json_decode($http);
$method = $_SERVER['REQUEST_METHOD'];
date_default_timezone_set('Asia/Manila');
$get = new Get($db);
$post = new Post($db);
$put = new Put($db);
$del = new Delete($db);
$heads = getallheaders();

// if (!isset($data -> session_id)) {
//     exit();
// } else {
//     $sessionID = $data -> session_id;
//     session_start($sessionID);
// }

if (!isset($heads['Event-Key']) || empty($heads['Event-Key'])) {
    exit();
} else {
    $event = $heads['Event-Key'];
}


if ($method === 'GET') {
    if (!isset($_GET['parameter']['session_id'])) {
        echo "No Session ID";
        exit();
    } else {
        $sessionID = $_GET['parameter']['session_id'];
        session_id($sessionID);
        session_start();
    }

    if ($event === 'logout') {
        $get -> logout();
    } elseif ($event === 'mynotifs') {
        echo $get -> getAllMyNotification($_SESSION['user_id']);
    } elseif ($event === 'allUsers') {
        echo $get -> getAllUsers();
    } elseif ($event === 'fetchRoles') {
        echo $get -> fetchRoles();
    } 

} elseif ($method === 'POST') {
    if (!isset($data -> session_id)) {
        echo "No Session ID";
        exit();
    } else {
        $sessionID = $data -> session_id;
        session_id($sessionID);
        session_start();
    }

    if ($event === 'addUser') {
        if (empty($data->username) || empty($data->firstName) || empty($data->lastName) || empty($data->password) || empty($data->confirmPassword)) {
            echo false; // Required fields are missing
        }
        if ($data->password !== $data->confirmPassword) {
            echo false; // Passwords do not match
        }
        echo $post -> addUser($data);
    } 
} elseif ($method === 'PUT') {

} elseif ($method === 'DELETE') {

}
