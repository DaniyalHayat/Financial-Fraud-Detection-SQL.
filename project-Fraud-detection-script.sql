-- Step 1: Create the database
CREATE DATABASE IF NOT EXISTS fraud_detection;

-- Step 2: Use the newly created database
USE fraud_detection;

-- Step 3: Create users table
CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255),
    email VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Step 4: Create transactions table
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    amount DECIMAL(10, 2),
    transaction_date DATETIME,
    transaction_type VARCHAR(50),
    location VARCHAR(255),
    status VARCHAR(50) DEFAULT 'completed',
    risk_score INT DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Step 5: Create the user_access_logs table to track user logins for auditing purposes
CREATE TABLE IF NOT EXISTS user_access_logs (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    accessed_transaction_id INT,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (accessed_transaction_id) REFERENCES transactions(transaction_id)
);

-- Step 6: Create the fraud_patterns table to store known fraud patterns
CREATE TABLE IF NOT EXISTS fraud_patterns (
    pattern_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    transaction_type VARCHAR(50),
    high_frequency_transactions BOOLEAN,
    location_mismatch BOOLEAN,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Step 7: Insert some sample data into the users table
INSERT INTO users (name, email) VALUES 
('Alice', 'alice@example.com'),
('Bob', 'bob@example.com'),
('Charlie', 'charlie@example.com'),
('David', 'david@example.com');

-- Step 8: Insert some sample data into the transactions table
INSERT INTO transactions (user_id, amount, transaction_date, transaction_type, location) VALUES 
(1, 100.00, '2024-09-01 10:00:00', 'purchase', 'New York'),
(1, 10500.00, '2024-09-01 10:05:00', 'purchase', 'New York'),
(1, 150.00, '2024-09-02 11:00:00', 'purchase', 'Boston'),
(2, 250.00, '2024-09-01 12:00:00', 'withdrawal', 'Los Angeles'),
(2, 1000.00, '2024-09-03 09:30:00', 'deposit', 'Los Angeles'),
(3, 10000.00, '2024-09-04 14:00:00', 'purchase', 'San Francisco'),
(4, 500.00, '2024-09-05 10:30:00', 'withdrawal', 'Miami');

-- Step 9: Insert some sample data into the fraud_patterns table
INSERT INTO fraud_patterns (user_id, transaction_type, high_frequency_transactions, location_mismatch) VALUES 
(1, 'purchase', TRUE, TRUE),
(2, 'withdrawal', TRUE, FALSE);

-- Step 10: Insert a sample log into user_access_logs
INSERT INTO user_access_logs (user_id, accessed_transaction_id) 
VALUES (1, 1), (2, 2), (3, 3);

-- Step 11: Update the risk_score based on the pre-defined rules
UPDATE transactions
JOIN (
    SELECT 
        transaction_id,
        CASE 
            WHEN amount > (SELECT AVG(amount) + 2 * STDDEV(amount) FROM (SELECT * FROM transactions) AS temp) THEN 3
            WHEN ABS(TIMESTAMPDIFF(MINUTE, transaction_date, NOW())) < 10 THEN 2
            WHEN location != (SELECT location FROM (SELECT * FROM transactions) AS t2 WHERE t2.user_id = transactions.user_id ORDER BY transaction_date DESC LIMIT 1) THEN 4
            ELSE 1
        END AS new_risk_score
    FROM transactions
) AS subquery ON transactions.transaction_id = subquery.transaction_id
SET transactions.risk_score = subquery.new_risk_score;

-- Step 12: Create a trigger to detect high-risk transactions in real time
DELIMITER //
CREATE TRIGGER fraud_alert_trigger
AFTER INSERT ON transactions
FOR EACH ROW
BEGIN
    IF NEW.risk_score > 7 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'High-risk transaction detected!';
    END IF;
END //
DELIMITER ;

-- Step 13: Create an audit table to log transaction activities
CREATE TABLE IF NOT EXISTS transaction_audit (
    audit_id INT PRIMARY KEY AUTO_INCREMENT,
    transaction_id INT,
    user_id INT,
    amount DECIMAL(10, 2),
    transaction_date DATETIME,
    audit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    audit_action VARCHAR(50),
    FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Step 14: Insert a sample log entry for a suspicious transaction
INSERT INTO transaction_audit (transaction_id, user_id, amount, transaction_date, audit_action)
VALUES (1, 1, 10500.00, '2024-09-01 10:05:00', 'flagged as suspicious');