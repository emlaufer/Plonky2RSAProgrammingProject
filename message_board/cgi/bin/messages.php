<?php
// messages.php
header('Content-Type: application/json');
require_once 'db_connection.php';

$db = getDbConnection();
$method = $_SERVER['REQUEST_METHOD'];

// Function to verify proof
function verifyProof($proof, $verifierData, $common, $message, $publicKeys) {
    $binaryPath = './verify';
    $tmp_dir = __DIR__ . '/data/tmp/';
    if (!file_exists($tmp_dir)) {
        mkdir($tmp_dir, 0755, true);
    }

    // Create temporary files
    $circuitFile = tempnam($tmp_dir, 'circuit_');
    $proofFile = tempnam($tmp_dir, 'proof_');
    $publicInputFile = tempnam($tmp_dir, 'public_input_');
    sort($publicKeys); // Ensure consistent order for verification

    // Write data to the files
    file_put_contents($circuitFile, json_encode(['verifier_circuit_data' => $verifierData, 'circuit' => $common], JSON_UNESCAPED_SLASHES)
);
    file_put_contents($proofFile, json_encode(["proof" => $proof], JSON_UNESCAPED_SLASHES));
    file_put_contents($publicInputFile, json_encode(['message' => $message, 'public_keys' => $publicKeys], JSON_UNESCAPED_SLASHES));

    // Execute the binary
    $output = shell_exec("$binaryPath $circuitFile $proofFile $publicInputFile 2>&1");

    // Delete temporary files
    unlink($circuitFile);
    unlink($proofFile);
    unlink($publicInputFile);

    // Check if the verification was successful
    if ($output === "success\n") {
        return true;
    }

    return false;
}

// Get all messages
if ($method === 'GET') {
    try {
        $messages = array();
        $query = $db->query('
            SELECT m._id, m.message, m.timestamp, m.proof, m.circuit_id, c.circuit AS common, c.verifier_circuit_data AS verifierData
            FROM messages m
            JOIN circuits c ON m.circuit_id = c._id
            ORDER BY m.timestamp DESC
        ');
        
        while ($message = $query->fetchArray(SQLITE3_ASSOC)) {
            // Get user IDs for this message
            $userQuery = $db->prepare('
                SELECT user_id FROM message_users WHERE message_id = :message_id
            ');
            $userQuery->bindValue(':message_id', $message['_id'], SQLITE3_INTEGER);
            $userResult = $userQuery->execute();
            
            $userIds = array();
            while ($user = $userResult->fetchArray(SQLITE3_ASSOC)) {
                $userIds[] = $user['user_id'];
            }
            
            $message['userIds'] = $userIds;
            $messages[] = $message;
        }
        
        echo json_encode($messages);
    } catch (Exception $e) {
        header('HTTP/1.1 500 Internal Server Error');
        echo json_encode(array('error' => 'Failed to fetch messages: ' . $e->getMessage()));
    }
}
// Create a new message
elseif ($method === 'POST') {
    try {
        $data = json_decode(file_get_contents('php://input'), true);
        
        // Replace null coalescing operators with isset/ternary
        $userIds = isset($data['userIds']) ? $data['userIds'] : array();
        $message = isset($data['message']) ? $data['message'] : '';
        $proof = isset($data['proof']) ? $data['proof'] : null;
        $circuit_id = isset($data['circuit_id']) ? $data['circuit_id'] : null;
        
        if (empty($userIds) || !is_array($userIds) || empty($message) || empty($circuit_id)) {
            header('HTTP/1.1 400 Bad Request');
            echo json_encode(array('error' => 'UserIds array and message are required'));
            exit;
        }
        
        // Fetch common and verifierData from the circuits table
        $stmt = $db->prepare('SELECT circuit AS common, verifier_circuit_data AS verifierData FROM circuits WHERE _id = :circuit_id');
        $stmt->bindValue(':circuit_id', $circuit_id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $circuitData = $result->fetchArray(SQLITE3_ASSOC);
        
        if (!$circuitData) {
            header('HTTP/1.1 400 Bad Request');
            echo json_encode(array('error' => 'Invalid circuit_id'));
            exit;
        }

        $common = $circuitData['common'];
        $verifierData = $circuitData['verifierData'];
        
        // Verify users exist
        $placeholders = implode(',', array_fill(0, count($userIds), '?'));
        $stmt = $db->prepare("SELECT _id, public_key FROM users WHERE _id IN ($placeholders)");
        
        foreach ($userIds as $index => $userId) {
            $stmt->bindValue($index + 1, $userId, SQLITE3_INTEGER);
        }
        
        $result = $stmt->execute();
        $users = array();
        $publicKeys = array();
        
        while ($user = $result->fetchArray(SQLITE3_ASSOC)) {
            $users[] = $user;
            if (!empty($user['public_key'])) {
                $publicKeys[] = $user['public_key'];
            }
        }
        
        if (count($users) !== count($userIds)) {
            header('HTTP/1.1 400 Bad Request');
            echo json_encode(array('error' => 'One or more users do not exist'));
            exit;
        }
        
        // Verify proof if provided
        if ($proof) {
            try {
                $isValid = verifyProof($proof, $verifierData, $common, $message, $publicKeys);
                
                // If you implement the actual verification and it fails:
                if (!$isValid) {
                    header('HTTP/1.1 400 Bad Request');
                    echo json_encode(array('error' => 'Proof verification failed'));
                    exit;
                }
            } catch (Exception $e) {
                header('HTTP/1.1 400 Bad Request');
                echo json_encode(array('error' => 'Proof verification failed: ' . $e->getMessage()));
                exit;
            }
        } else {
            header('HTTP/1.1 400 Bad Request');
            echo json_encode(array('error' => 'Proof verification failed: No proof provided'));
            exit;
        }
        
        // Begin transaction
        $db->exec('BEGIN TRANSACTION');
        
        // Insert message
        $stmt = $db->prepare('
            INSERT INTO messages (message, timestamp, proof, circuit_id)
            VALUES (:message, :timestamp, :proof, :circuit_id)
        ');
        $stmt->bindValue(':message', $message, SQLITE3_TEXT);
        $stmt->bindValue(':timestamp', date('Y-m-d H:i:s'), SQLITE3_TEXT);
        $stmt->bindValue(':proof', $proof ? json_encode($proof) : null, $proof ? SQLITE3_TEXT : SQLITE3_NULL);
        $stmt->bindValue(':circuit_id', $circuit_id, SQLITE3_INTEGER);
        $stmt->execute();
        
        $messageId = $db->lastInsertRowID();
        
        // Associate users with message
        foreach ($userIds as $userId) {
            $stmt = $db->prepare('
                INSERT INTO message_users (message_id, user_id)
                VALUES (:message_id, :user_id)
            ');
            $stmt->bindValue(':message_id', $messageId, SQLITE3_INTEGER);
            $stmt->bindValue(':user_id', $userId, SQLITE3_INTEGER);
            $stmt->execute();
        }
        
        $db->exec('COMMIT');
        
        // Get the created message
        $stmt = $db->prepare('
            SELECT _id, message, timestamp, proof, circuit_id
            FROM messages WHERE _id = :_id
        ');
        $stmt->bindValue(':_id', $messageId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $newMessage = $result->fetchArray(SQLITE3_ASSOC);
        $newMessage['userIds'] = $userIds;
        
        header('HTTP/1.1 201 Created');
        echo json_encode($newMessage);
    } catch (Exception $e) {
        $db->exec('ROLLBACK');
        header('HTTP/1.1 500 Internal Server Error');
        echo json_encode(array('error' => 'Failed to add message: ' . $e->getMessage()));
    }
}
else {
    header('HTTP/1.1 404 Not Found');
    echo json_encode(array('error' => 'Endpoint not found'));
}
?>
