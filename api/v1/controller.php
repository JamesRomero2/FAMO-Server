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
    function getRandomColor() {
        return sprintf('#%06X', mt_rand(0, 0xFFFFFF));
    }
}

class Get extends Master {
    public function logout($sessionID) {
        $_SESSION = [];
        session_destroy();
    }
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
    public function fetchSupplySummary() {
        try {
            $currentYear = date('Y');
            $currentMonth = date('m');
            // $stmt = $this->db->prepare("SELECT c.description AS name, SUM(i.no_of_stock) AS value FROM categories c JOIN inventory i ON c.id = i.category_id WHERE YEAR(i.date_delivery) = :currentYear AND MONTH(i.date_delivery) = :currentMonth GROUP BY c.description");
            // $stmt->bindParam(':currentYear', $currentYear, PDO::PARAM_INT);
            // $stmt->bindParam(':currentMonth', $currentMonth, PDO::PARAM_INT);
            $stmt = $this->db->prepare("SELECT c.description AS name, SUM(i.no_of_stock) AS value FROM categories c JOIN inventory i ON c.id = i.category_id GROUP BY c.description");
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $output = [];
            foreach ($results as $row) {
                $output[] = [
                    'name' => $row['name'],
                    'value' => (int) $row['value'],
                    'color' => $this -> getRandomColor(),
                ];
            }

            return json_encode($output);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function fetchAllInventoryDashboard() {
        try {
            $stmt = $this->db->prepare("SELECT  i.item_name AS item_name, i.no_of_stock AS quantity, u.description AS unit_of_measurement, c.description AS category FROM  inventory i JOIN  categories c ON i.category_id = c.id JOIN  units_of_measurement u ON i.unit_id = u.id WHERE i.no_of_stock != 0");
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $output = [];

            foreach ($results as $row) {
                $output[] = [
                    'item name' => $row['item_name'],
                    'quantity' => (int) $row['quantity'],
                    'unit' => $row['unit_of_measurement'],
                    'category' => $row['category']
                ];
            }

            return json_encode($output);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function shelf() {
        try {
            $stmt = $this->db->prepare("SELECT COUNT(*) AS total_items FROM inventory");
            $stmt -> execute();
            $totalItems = $stmt->fetch(PDO::FETCH_ASSOC)['total_items'];
            $stmt1 = $this->db->prepare("SELECT COUNT(*) AS total_categories FROM categories");
            $stmt1 -> execute();
            $totalCategories = $stmt1->fetch(PDO::FETCH_ASSOC)['total_categories'];
            $stmt2 = $this->db->prepare("SELECT COUNT(*) AS total_users FROM users");
            $stmt2 -> execute();
            $totalUsers = $stmt2->fetch(PDO::FETCH_ASSOC)['total_users'];

            return json_encode([
                'supply' => (int) $totalItems,     // Total number of distinct items
                'category' => (int) $totalCategories, // Total categories
                'user' => (int) $totalUsers          // Total users
            ]);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function fetchAllOutOfStockDashboard() {
        try {
            $stmt = $this->db->prepare("SELECT i.item_name AS item_name, i.no_of_stock AS quantity, u.description AS unit_of_measurement, c.description AS category FROM  inventory i JOIN  categories c ON i.category_id = c.id JOIN  units_of_measurement u ON i.unit_id = u.id WHERE i.no_of_stock = 0");
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $output = [];

            foreach ($results as $row) {
                $output[] = [
                    'item name' => $row['item_name'],
                    'quantity' => (int) $row['quantity'],
                    'unit' => $row['unit_of_measurement'],
                    'category' => $row['category']
                ];
            }

            return json_encode($output);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function inventoryCategoryPercentage() {
        try {
            $stmt = $this->db->prepare("SELECT c.description AS name, SUM(i.no_of_stock) AS total_stock FROM categories c JOIN inventory i ON c.id = i.category_id GROUP BY c.description");
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $totalStock = 0;
            foreach ($results as $row) {
                $totalStock += $row['total_stock'];
            }

            $output = [];
            foreach ($results as $row) {
                $percentage = ($row['total_stock'] / $totalStock) * 100;
                $output[] = [
                    'name' => $row['name'],
                    'percentage' => round($percentage, 2)  // Round to 2 decimal places
                ];
            }

            return json_encode($output);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function pieChartDetails() {
        try {
            $stmt = $this->db->prepare("SELECT  COUNT(*) AS totalItems, SUM(CASE WHEN uom.low_limit < inv.no_of_stock THEN 1 ELSE 0 END) AS lowItems, SUM(CASE WHEN uom.full_limit = inv.no_of_stock THEN 1 ELSE 0 END) AS fullItems, SUM(CASE WHEN inv.no_of_stock <= uom.reserved_limit THEN 1 ELSE 0 END) AS reservedItems, SUM(CASE WHEN inv.no_of_stock = 0 THEN 1 ELSE 0 END) AS noStockItems FROM inventory inv JOIN units_of_measurement uom ON inv.unit_id = uom.id");
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            $output = [
                'totalItems' => (int) $result['totalItems'],
                'Low Items' => (int) $result['lowItems'],
                'Full Items' => (int) $result['fullItems'],
                'Reserved Items' => (int) $result['reservedItems'],
                'No Stocks Items' => (int) $result['noStockItems'],
            ];

            return json_encode($output);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function getItemCategory() {
        try {
            $stmt = $this->db->prepare("SELECT description FROM categories");
            $stmt->execute();
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $descriptions = array_column($result, 'description');

            return json_encode($descriptions);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function getItemUnitOfMeasurement() {
        try {
            $stmt = $this->db->prepare("SELECT unit FROM units_of_measurement");
            $stmt->execute();
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $unit = array_column($result, 'unit');

            return json_encode($unit);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function getRequestData() {
        try {
            $stmt = $this->db->prepare("SELECT requests.request_number AS 'Request ID', CONCAT(users.first_name, ' ', users.last_name) AS 'Requested By', requests.request_date AS 'Request Date', status.description AS 'Status' FROM requests JOIN users ON requests.requested_by = users.id JOIN status ON requests.status_id = status.id WHERE requests.archive = 0");
            $stmt->execute();
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return json_encode($result);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function getBelowThresholdItems() {
        try {
            $stmt = $this->db->prepare("SELECT inventory.item_name AS itemname, inventory.no_of_stock AS quantity, units_of_measurement.description AS unit, categories.description AS categories FROM  inventory JOIN  units_of_measurement ON inventory.unit_id = units_of_measurement.id LEFT JOIN categories ON inventory.category_id = categories.id WHERE inventory.no_of_stock < units_of_measurement.low_limit AND inventory.no_of_stock > 0");
            $stmt->execute();
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return json_encode($result);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function getSpecificRequest($requestID) {
        try {
            $stmt = $this->db->prepare("SELECT 
                ri.item_name AS itemName, 
                c.description AS category, 
                pg.abbrev AS groupAbbrev, 
                ri.quantity, 
                uom.description AS UOM, 
                ri.justification 
            FROM 
                request_items ri 
            JOIN 
                requests r ON ri.request_id = r.id 
            LEFT JOIN 
                categories c ON ri.category_id = c.id 
            LEFT JOIN 
                units_of_measurement uom ON ri.units_of_measurement_id = uom.id 
            LEFT JOIN 
                pup_groups pg ON ri.pup_group_id = pg.id 
            WHERE 
                r.request_number = :request_number");
            $stmt->bindParam(':request_number', $requestID, PDO::PARAM_STR);
            $stmt->execute();
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return json_encode($result);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function getDestination() {
        try {
            $stmt = $this->db->prepare("SELECT abbrev FROM pup_groups");
            $stmt->execute();
            $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $descriptions = array_column($result, 'abbrev');

            return json_encode($descriptions);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function getTopFrequentItems() {
        try {
            $stmt = $this->db->prepare("SELECT 
            pg.abbrev AS group_abbrev,
            inv.item_name,
            f.amount,
            pg.id AS group_id,
            group_totals.total_amount
        FROM frequency f
        JOIN inventory inv ON f.inventory_id = inv.id
        JOIN pup_groups pg ON f.pup_groups_id = pg.id
        JOIN (
            SELECT pup_groups_id, SUM(amount) AS total_amount
            FROM frequency
            GROUP BY pup_groups_id
        ) group_totals ON group_totals.pup_groups_id = pg.id
        JOIN (
            SELECT 
                f2.pup_groups_id,
                f2.inventory_id,
                f2.amount,
                ROW_NUMBER() OVER (PARTITION BY f2.pup_groups_id ORDER BY f2.amount DESC) AS rank
            FROM frequency f2
        ) ranked_items ON ranked_items.pup_groups_id = f.pup_groups_id 
                        AND ranked_items.inventory_id = f.inventory_id 
                        AND ranked_items.rank <= 5
        ORDER BY pg.abbrev, ranked_items.rank;
    ");
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $data = [];
            foreach ($results as $row) {
                $groupAbbrev = $row['group_abbrev'];
                
                if (!isset($data[$groupAbbrev])) {
                    $data[$groupAbbrev] = [
                        'items' => [],
                        'total_amount' => $row['total_amount']
                    ];
                }
        
                $data[$groupAbbrev]['items'][] = [
                    'item_name' => $row['item_name'],
                    'amount' => $row['amount']
                ];
            }
            return json_encode($data);
        } catch (\Throwable $e) {
            http_response_code(500);
            return json_encode(['error' => 'An error occurred  ' . $e->getMessage()]);
        }
    }
    public function getFullInventoryDetails() {
        try {
            $stmt = $this->db->prepare("SELECT inv.item_name AS `Item name`, cat.description AS `Category`, pg.abbrev AS `Destination`, uom.description AS `Unit`, inv.no_of_stock AS `Quantity` FROM inventory inv LEFT JOIN categories cat ON inv.category_id = cat.id LEFT JOIN units_of_measurement uom ON inv.unit_id = uom.id LEFT JOIN pup_groups pg ON inv.pup_group_id = pg.id ORDER BY pg.abbrev, inv.item_name;");
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            return json_encode($results);
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
    public function addRequest($data, $userID) {
        try {
            $stmt = $this->db->prepare("SELECT COUNT(*) AS total FROM requests");
            $stmt->execute();
            $rowCount = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
            $currentYear = date('Y');
            $currentMonth = date('m'); 
            $number = $rowCount + 1; 

            $requestNumber = sprintf("REQ-%s-%s-%04d", $currentYear, $currentMonth, $number);

            $stmt1 = $this->db->prepare("INSERT INTO requests (request_number, requested_by, request_date, archive) VALUES (:request_number, :requested_by, NOW(), 0)");
            $stmt1->bindParam(':request_number', $requestNumber);
            $stmt1->bindParam(':requested_by', $userID);

            $stmt1->execute();

            $requestId = $this->db->lastInsertId();
            if (is_object($data)) {
                $data = json_decode(json_encode($data), true);
            } elseif (is_string($data)) {
                // If it's a JSON string, decode it to an associative array
                $data = json_decode($data, true);
            }

            foreach ($data as $item) {
                $sqlCategory = "SELECT id FROM categories WHERE description = :category";
                $stmtCategory = $this->db->prepare($sqlCategory);
                $stmtCategory->bindParam(':category', $item['category']);
                $stmtCategory->execute();
                $categoryId = $stmtCategory->fetch(PDO::FETCH_ASSOC)['id'];

                $sqlUOM = "SELECT id FROM units_of_measurement WHERE unit = :uom";
                $stmtUOM = $this->db->prepare($sqlUOM);
                $stmtUOM->bindParam(':uom', $item['UOM']);
                $stmtUOM->execute();
                $uomId = $stmtUOM->fetch(PDO::FETCH_ASSOC)['id'];

                $sqlGroup = "SELECT id FROM pup_groups WHERE abbrev = :abbr";
                $sqlGroup = $this->db->prepare($sqlGroup);
                $sqlGroup->bindParam(':abbr', $item['destination']);
                $sqlGroup->execute();
                $destinationId = $sqlGroup->fetch(PDO::FETCH_ASSOC)['id'];

                $sqlInsert = "
                    INSERT INTO request_items (
                        request_id, 
                        item_name, 
                        category_id, 
                        units_of_measurement_id, 
                        pup_group_id,
                        quantity, 
                        justification
                    ) VALUES (
                        :request_id, 
                        :item_name, 
                        :category_id, 
                        :units_of_measurement_id,
                        :pupgID,
                        :quantity, 
                        :justification
                    )
                ";
                $stmtInsert = $this->db->prepare($sqlInsert);

                // Bind values
                $stmtInsert->bindParam(':request_id', $requestId);
                $stmtInsert->bindParam(':item_name', $item['itemName']);
                $stmtInsert->bindParam(':category_id', $categoryId);
                $stmtInsert->bindParam(':units_of_measurement_id', $uomId);
                $stmtInsert->bindParam(':pupgID', $destinationId);
                $stmtInsert->bindParam(':quantity', $item['quantity']);
                $stmtInsert->bindParam(':justification', $item['justification']);
                
                // Execute the insert statement
                $stmtInsert->execute();
            }
            return "Request items inserted successfully.";
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
