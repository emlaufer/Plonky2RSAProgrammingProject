<?php
// circuits.php
header('Content-Type: application/json');
require_once 'db_connection.php';

$db = getDbConnection();
$method = $_SERVER['REQUEST_METHOD'];

// Get all circuits
if ($method === 'GET') {
    try {
        $results = $db->query('SELECT _id, name FROM circuits');
        $circuits = [];
        
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $circuits[] = $row;
        }

        header('HTTP/1.1 200 OK');
        echo json_encode($circuits);
    } catch (Exception $e) {
        header('HTTP/1.1 500 Internal Server Error');
        echo json_encode(['error' => 'Failed to fetch circuits: ' . $e->getMessage()]);
    }
}
// Create a new circuit
elseif ($method === 'POST') {
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        
        // Validate required fields
        if (!isset($data['name']) || empty($data['name'])) {
            header('HTTP/1.1 400 Bad Request');
            echo json_encode(['error' => 'Name is required']);
            exit;
        }

        if (!isset($data['circuit']) || empty($data['circuit'])) {
            header('HTTP/1.1 400 Bad Request');
            echo json_encode(['error' => 'Circuit is required']);
            exit;
        }

        if (!isset($data['verifier_circuit_data']) || empty($data['verifier_circuit_data'])) {
            header('HTTP/1.1 400 Bad Request');
            echo json_encode(['error' => 'Verifier circuit data is required']);
            exit;
        }
        
        // Insert the new circuit
        $stmt = $db->prepare('INSERT INTO circuits (name, circuit, verifier_circuit_data) VALUES (:name, :circuit, :verifier_circuit_data)');
        $stmt->bindValue(':name', $data['name'], SQLITE3_TEXT);
        $stmt->bindValue(':circuit', $data['circuit'], SQLITE3_TEXT);
        $stmt->bindValue(':verifier_circuit_data', $data['verifier_circuit_data'], SQLITE3_TEXT);
        
        $result = $stmt->execute();
        
        if ($result) {
            $circuitId = $db->lastInsertRowID();
            
            // Fetch the newly created circuit
            $stmt = $db->prepare('SELECT _id, name, circuit, verifier_circuit_data FROM circuits WHERE _id = :id');
            $stmt->bindValue(':id', $circuitId, SQLITE3_INTEGER);
            $newCircuit = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
            
            header('HTTP/1.1 201 Created');
            echo json_encode($newCircuit);
        } else {
            // Check the error message for a unique constraint violation
            $errorMsg = $db->lastErrorMsg();
            if (strpos($errorMsg, 'UNIQUE constraint failed: circuits.name') !== false) {
                header('HTTP/1.1 400 Bad Request');
                echo json_encode(['error' => 'A circuit with this name already exists']);
            } else {
                header('HTTP/1.1 500 Internal Server Error');
                echo json_encode(['error' => 'Failed to create circuit: ' . $errorMsg]);
            }
        }
    } catch (Exception $e) {
        header('HTTP/1.1 500 Internal Server Error');
        echo json_encode(['error' => 'Failed to create circuit: ' . $e->getMessage()]);
    }
} else {
    header('HTTP/1.1 404 Not Found');
    echo json_encode(['error' => 'Endpoint not found']);
}
?>
