<?php
// db_connection.php
function getDbConnection() {
    $db_path = __DIR__ . '/data/database.sqlite';
    
    // Create directory if it doesn't exist
    $dir = dirname($db_path);
    if (!file_exists($dir)) {
        mkdir($dir, 0755, true);
    }
    
    $isNewDatabase = !file_exists($db_path);

    try {
        $db = new SQLite3($db_path);
        $db->exec('PRAGMA foreign_keys = ON;');
        
        // Initialize tables if they don't exist
        $db->exec('
            CREATE TABLE IF NOT EXISTS users (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                public_key TEXT
            )
        ');

        $db->exec('
            CREATE TABLE IF NOT EXISTS circuits (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                circuit TEXT NOT NULL,
                verifier_circuit_data TEXT NOT NULL
            )
        ');
        
        $db->exec('
            CREATE TABLE IF NOT EXISTS messages (
                _id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                proof TEXT,
                circuit_id INTEGER,
                FOREIGN KEY (circuit_id) REFERENCES circuits(_id)
            )
        ');
        
        $db->exec('
            CREATE TABLE IF NOT EXISTS message_users (
                message_id INTEGER,
                user_id INTEGER,
                PRIMARY KEY (message_id, user_id),
                FOREIGN KEY (message_id) REFERENCES messages(_id),
                FOREIGN KEY (user_id) REFERENCES users(_id)
            )
        ');

        // Populate database with initial data if it's a new database
        if ($isNewDatabase) {
            populateDatabase($db);
        }

        return $db;
    } catch (Exception $e) {
        header('HTTP/1.1 500 Internal Server Error');
        echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
        exit;
    }
}

function populateDatabase($db) {
    //$initialUsers = [
    //    [
    //        'name' => 'Sarah Johnson',
    //        'publicKey' => 'sSwOy93sanQfEIsRZOaje3WSeg1o7WbxFhtJQzID+Wsr25b03b4XE7A2/li7+TNfW7hpZhXfn9JYq/6r4GUzxJBPlG8in4XaP81zw/cAKfLb8pYF+/uFsz7GaUf1LXlu2HpWl5f5eLGrjYaH8gXt0hyfFg3ibaxY5uQpL3f4Uk+jdE1nclfTH3Pn9Topv+HrtzqieJjL2pSyXyZuvWpt++Kf5azlAlpa1HuHlQl03HLcWU5VGTpHpAcGOYKt13sXh6T1soAOStjNXbZ8/IBXBCvkwpRqA9ZB8p0YUhtwghg0Lvzbt5+lVatIMX4MKX1zONJo6x0jJuNtlNjeO0MXuA=='
    //    ],
    //    [
    //        'name' => 'Michael Chen',
    //        'publicKey' => 'SzGTbzQsv4NYTn/stEMaaZbLbtJfbWYtn64AdvtR+4Chhw71smibhGfR/RWqMWRL2Cl7vXjOvP2MkjfD0H6MKFHfAa6g0VCUnGBe1D6XMd0X77ZUAMDfmEI/+aGydBbMhLqVZV9oRUanCrBwG+Or9Zo9M07PU3l8xZfQIeQ94jOEqndoRGL0nhieuITTA0zCpLcCoTwzdEgriKMTHInMTJ+eVwRzRkTdCfuxPWGxchGrndHB/KITHxgqiRUUqG6bxj9h2UOl9YACn7IZqWyvUSU+OcZ3nAiE7XWwe+8VxpYrO5NXNrAx+xl1OHuU4HHOGVHF71pyzfuQvh1BYVDrsQ=='
    //    ],
    //    [
    //        'name' => 'Alex Rivera',
    //        'publicKey' => '02cewMgVbtAPXezjAxXvukon15WW/E9zN1NnALCNVQPeFGFxj8nDtQ7EEO8vMRNfT4ZgqDLI+u7/ncJcxzGKNzfUX609VdLdXKtftYkwsib/84c4K4v3CRWG8cmUW7/+FumXGiEkLIRujJPuEzcVrqzlNWqZ3C+nIwENuLyHy2UrYwCeq6SuIfzvUit3gKV7PeZdYlct67Tiyf0wAc3dZe/qR7HM+uOVDoevU3L3yHTPsSeuXbiKAGttcaEToAyBY6nJPb25ywY/WRfIRvAM65oSZn3uDnKRGyRYYvN3JKE4taZvstfy0sW+YdODA9n4B2UsNQk7EZLrzk+fmda4pA=='
    //    ],
    //    [
    //        'name' => 'Emily Wilson',
    //        'publicKey' => 'H1LvHI1eglgkEUcuO4pKH434gb/RjTX9jeNF6fqALqbVGk4plhmwXj8OIR9KxzCH+8Y+UkFnHPOB664vWOdeLXIM/QqDVkuj88RoHk/E6DcYu+HAwIHnEvBuMn5WQB7Z6ev3nnG+0MLi3gd6mFs+O9Wd51PgJnA9jVGds5P4UXYuArxyi6+B1vZQXWrdsFLC1mEr0/+SVzooK3GCBkhnQJM8FEKXb39LNDN4579qCqzfNEUnz6VPuXpbFdcHnGsOCCxdi733iKps4wPI1aEuM4lnjGkjK8VSB/Xa2KQ2vZkJZTNGhN0n9Yuonyypb6MlZoGy07Unhg9a+Ml51tJuxA=='
    //    ],
    //    [
    //        'name' => 'David Kim',
    //        'publicKey' => 'xY2hf7pLi6KYvFjMez5kmOf1Bc8nzPdnKXteSC5EoU4Hg9DxpoCigmJomlNr+4la1H5KP9ggXzDMIERUjFp5XJ+dxZ/jg1+z4uTHxFpS0Y5LkjyBYIZk3oafmtBxRFALao2ZHM5igWjwVGRh+JP5qEK3wl/0JQqwXquyvqcd9rb2LyjLBHVtHrj2Um7qzTp01nIYh7g7nANU99JW/Be1kAO1Qtf8fxz8i1wz5xLdYqHrQvPfHPSWdRsvlaFlM1CLR8BEAjs1qqHt7M3GGPJKA+ZWoC+WJ6W1n+QMegAva69uFqfQmvIQyiNnX63H4iOVupyiCs/WkeEylWHhMghg0Q=='
    //    ],
    //    [
    //        'name' => 'Jessica Taylor',
    //        'publicKey' => 'gSBHoubtIVZ2shLDOcVdSIprncwrdrszIucVY9FyCXpUIY2RgNaYgbY1CACQ35cNpWXHA+q3qDBy3EKStzuDGApqybaiOuBEL4umxVhEJWSNVjcOYhGPG9GzIRvV0mCEhDhH/S18cbRzn7YbbVB+aAs1GDuOOcJ0nGSUSH+SDnlhNqPYNcawncgrTuilliHmUpObQaqWvWklxixN3t5GyCsKCdCedjX//Eg16K02ieHt9Njf+s2N0XhnGwqSJVOvNKPsl92yf9rKMCsdM/0s4rIovJRpxfNcx9EqVUX+4N7c4V3if2HUWdMvzvN9hlMxMQCZ4dsRTV7eht25Of+y3g=='
    //    ]
    //];

    //$stmt = $db->prepare('INSERT INTO users (name, public_key) VALUES (:name, :publicKey)');
    //foreach ($initialUsers as $user) {
    //    $stmt->bindValue(':name', $user['name'], SQLITE3_TEXT);
    //    $stmt->bindValue(':publicKey', $user['publicKey'], SQLITE3_TEXT);
    //    $stmt->execute();
    //}
}
?>
