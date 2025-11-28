DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL
);

INSERT INTO users (id, name, email, role) VALUES
(1, 'Alice', 'alice@example.com', 'admin'),
(2, 'Bob', 'bob@example.com', 'user'),
(3, 'Carol', 'carol@example.org', 'user');
