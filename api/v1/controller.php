<?php

class Master {
    protected $db;
    public function __construct($db) {
        $this->db = $db;
    }
    public function sanitizeString($string) {
        $string = trim($string);
        $string = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', "", $string);
        $string = strip_tags($string);
        $string = stripslashes($string);
        return $string;
    }
    public function sanitizeInt($int) {
        $int = trim($int);
        $int = preg_replace('/<script\b[^>]*>(.*?)<\/script>/is', "", $int);
        $int = str_replace(",", "", $int);
        $int = (int) $int;
        return $int;
    }
    public function sanitizeDate($date) {
        $date = trim($date);
        $date = preg_replace("([^0-9/])", "", $date);

        if (!date("Y-m-d", strtotime(date($date)))) {
            return false;
        } else {
            $date = date("Y-m-d", strtotime(date($date)));
            return $date;
        }
    }
    public function sanitizeBoolean($input) {
        return strtolower($input) === 'false' ? false : (bool) $input;
    }
    public function generateToken() {
        return bin2hex(random_bytes(32));
    }
    public function getCSRFToken() {
        return $_SESSION['CSRF'];
    }
    public function validateCSRF($token) {
        return $token === $_SESSION['CSRF'];
    }
    public function startSession($id) {

    }
    public function getSession($id) {

    }
    public function endSession($id) {
        
    }
    public function getRoleId($roleDesc) {
        try {
            $sql = "SELECT id FROM roles WHERE description = :description AND deleted = FALSE";
            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':description', $roleDesc);
            $stmt->execute();

            return $stmt->fetchColumn();
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
        
    }
}

class Get extends Master {
    public function getAllMyNotification($userId) {
        try {
            $stmt = $this->db->prepare("
                SELECT important, message, created_at
                FROM notifications
                WHERE user_id = :user_id
                ORDER BY created_at DESC
            ");
            $stmt->execute(['user_id' => $userId]);
            $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return json_encode($notifications);
        } catch (\Throwable $th) {
            http_response_code(500);
            echo json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
        
    }
    public function getAllUsers() {
        try {
            $stmt = $this->db->prepare("SELECT u.first_name, u.last_name, r.description AS role, u.last_logged_in, u.status
                FROM users u
                JOIN roles r ON u.role = r.id
                WHERE u.deleted = FALSE AND r.deleted = FALSE");
            $stmt->execute();

            // Fetch the results
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
            // Format the results to the desired structure
            $formattedUsers = [];
            foreach ($users as $user) {
                $formattedUsers[] = [
                    'name' => trim($user['first_name'] . ' ' . $user['last_name']),
                    'role' => $user['role'],
                    'last logged in' => $user['last_logged_in'],
                    'status' => $user['status'],
                ];
            }
    
            return json_encode($formattedUsers);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function fetchRoles() {
        try {
            $stmt = $this->db->prepare("SELECT id, description FROM roles WHERE deleted = FALSE");
            $stmt->execute();
            
            $roles = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            return json_encode($roles);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
}
class Post extends Master {
    public function login(string $username, string $password) {
        try {
            $stmt = $this->db->prepare("SELECT id, username, first_name, last_name, role, password FROM users WHERE username = :username AND password = :password AND status = 'active' AND deleted = 0 LIMIT 1");
            $stmt->bindParam(':username', $username, PDO::PARAM_STR);
            $stmt->bindParam(':password', $password, PDO::PARAM_STR);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

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

                $updateStmt = $this->db->prepare("UPDATE users SET last_logged_in = NOW() WHERE username = :username");
                $updateStmt->bindParam(':username', $username, PDO::PARAM_STR);
                $updateStmt->execute();

                return json_encode($response);
            } else {
                http_response_code(401);
                echo json_encode(['error' => 'Invalid username or password']);
            }
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'An error occurred during login: ' . $e->getMessage()]);
        }
    }
    public function addUser($data) {
        try {
            $roleId = $this -> getRoleId($data->role);
            if (!$roleId) {
                return 0; // Invalid role
            }
            $hashedPassword = password_hash($data->password, PASSWORD_DEFAULT);
            $sql = "INSERT INTO users (username, email, password, first_name, last_name, last_logged_in, role, status)
            VALUES (:username, :email, :password, :first_name, :last_name, NOW(), :role, 'active')";

            $stmt = $this->db->prepare($sql);
            $stmt->bindParam(':username', $data->username);
            $stmt->bindParam(':email', $data->email); // Assuming you have an email field
            $stmt->bindParam(':password', $hashedPassword);
            $stmt->bindParam(':first_name', $data->firstName);
            $stmt->bindParam(':last_name', $data->lastName);
            $stmt->bindParam(':role', $roleId);

            return $stmt->execute();
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
        
    }
}
class Put extends Master {

}
class Delete extends Master {

}
