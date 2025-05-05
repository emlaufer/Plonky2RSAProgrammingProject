<?php
// users.php
header('Content-Type: application/json');
require_once 'db_connection.php';

$db = getDbConnection();
$method = $_SERVER['REQUEST_METHOD'];

// Get all users
if ($method === 'GET') {
    try {
        $results = $db->query('SELECT _id, name, public_key FROM users');
        $users = [];
        
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $users[] = $row;
        }
        
        echo json_encode($users);
    } catch (Exception $e) {
        header('HTTP/1.1 500 Internal Server Error');
        echo json_encode(['error' => 'Failed to fetch users: ' . $e->getMessage()]);
    }
}
// Create a new user
elseif ($method === 'POST') {
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        
        // Validate required fields
        if (!isset($data['name']) || empty($data['name'])) {
            header('HTTP/1.1 400 Bad Request');
            echo json_encode(['error' => 'Name is required']);
            exit;
        }

        if (!isset($data['public_key']) || empty($data['public_key'])) {
            header('HTTP/1.1 400 Bad Request');
            echo json_encode(['error' => 'Public key is required']);
            exit;
        }
        
        // Insert the new user
        $stmt = $db->prepare('INSERT INTO users (name, public_key) VALUES (:name, :public_key)');
        $stmt->bindValue(':name', $data['name'], SQLITE3_TEXT);
        $stmt->bindValue(':public_key', $data['public_key'], SQLITE3_TEXT);
        
        $result = $stmt->execute();
        
        if ($result) {
            $userId = $db->lastInsertRowID();
            
            // Fetch the newly created user
            $stmt = $db->prepare('SELECT _id, name, public_key FROM users WHERE _id = :id');
            $stmt->bindValue(':id', $userId, SQLITE3_INTEGER);
            $newUser = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
            
            header('HTTP/1.1 201 Created');
            echo json_encode($newUser);
        } else {
            throw new Exception('Failed to insert user');
        }
    } catch (Exception $e) {
        header('HTTP/1.1 500 Internal Server Error');
        echo json_encode(['error' => 'Failed to create user: ' . $e->getMessage()]);
    }
}
else {
    header('HTTP/1.1 404 Not Found');
    echo json_encode(['error' => 'Endpoint not found']);
}
?>
