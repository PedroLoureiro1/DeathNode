DROP DATABASE IF EXISTS deathnode_db;
DROP USER IF EXISTS shadow_admin;
DROP USER IF EXISTS app_worker;

CREATE DATABASE deathnode_db;

CREATE USER shadow_admin WITH ENCRYPTED PASSWORD 'AdminSecret123';

CREATE USER app_worker WITH ENCRYPTED PASSWORD 'AppWorkerSecret123';

\c deathnode_db;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    ciphertext_hash CHAR(64) UNIQUE NOT NULL,
    encrypted_payload JSONB NOT NULL,
    payload_hash TEXT,
    payload_signature TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_documents_created_at ON documents(created_at DESC);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO shadow_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO shadow_admin;

GRANT CONNECT ON DATABASE deathnode_db TO app_worker;
GRANT USAGE ON SCHEMA public TO app_worker;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO app_worker;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_worker;