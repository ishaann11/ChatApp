CREATE TABLE users(
    id SERIAL PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(100),
    reset_password_token VARCHAR(255),
    reset_password_expires TIMESTAMP
);

