<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: *");
session_start();
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);


require_once("../../common/connection.php");
require_once("./controller.php");
$http = json_decode(file_get_contents("php://input"));
$method = $_SERVER['REQUEST_METHOD'];
date_default_timezone_set('Asia/Manila');
$get = new Get($db);
$post = new Post($db);
$put = new Put($db);
$del = new Delete($db);
$heads = getallheaders();
// if (!isset($heads['Content-Type']) || empty($heads['Content-Type'])) {
//     http_response_code(401);
//     exit();
// }

echo json_encode($heads);