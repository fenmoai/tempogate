CREATE TABLE refresh_tokens (
    token      TEXT PRIMARY KEY,
    jti        TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    email      TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
